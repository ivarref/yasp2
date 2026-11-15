(ns yasp2.mtls-web-proxy-client
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [nrepl.http :as http]
            [nrepl.tls :as tls]
            [yasp2.web-echo-server :as web-echo-server])
  (:import (java.io BufferedInputStream BufferedOutputStream BufferedReader InputStream InputStreamReader OutputStream)
           (java.lang AutoCloseable)
           (java.net InetAddress InetSocketAddress ServerSocket Socket SocketTimeoutException)
           (java.nio.charset StandardCharsets)
           (java.util Arrays Base64)
           (javax.net.ssl SSLServerSocket SSLSocket)))

(set! *warn-on-reflection* true)

;; The basic idea:
;; A client and server using mTLS over the wire.
;; The "wire" is HTTP posts.

;; Each POST and response contains a header and "raw" TLS bytes.
;; The header contains information such as:
;; * is there more bytes available?
;; * session id
;; * EOF?


;; The implementation of the client:
;; The client opens a TCP server that will take plaintext nREPL commands in.
;; A single thread will be used for each accepted connection.

;; Per connection:
;; On init, the connection thread does:
;; Create an interim TCP echo server.
;; Connect a TLS client to the echo server.
;; Closes the echo server, but let echo connection stay open.

;; The connection thread now holds 3 sockets (6 streams):
;; the plaintext
;; the TLS client
;; the TCP echo connection

;; When creating a TLS client, it will (probably) send a bunch of bytes
;; on connect


(def buf-size 65536)

(defn- do-copy [^InputStream input ^OutputStream output]
  (let [buffer (make-array Byte/TYPE buf-size)]
    (loop []
      (let [size (.read input buffer)]
        (when (pos? size)
          (do (.write output buffer 0 size)
              (.flush output)
              (recur)))))))


(defn echo-loop! [^Socket s]
  (with-open [_s s
              in (BufferedInputStream. (.getInputStream s))
              out (BufferedOutputStream. (.getOutputStream s))]
    (do-copy in out)))


#_(def tls-echo-port (promise))


(defn start-tls-echo-server! [server-keys-file]
  (let [server-ctx (tls/ssl-str-context (slurp server-keys-file))]
    (let [^SSLServerSocket server (tls/server-socket server-ctx "127.0.0.1" 0)]
      (future
        (loop []
          (let [sock (.accept ^ServerSocket server)]
            (println "<<<< TLS server got new connection")
            (future (echo-loop! sock))
            (recur))))
      server)))




(defn- pr-str-safe [x]
  (let [v (binding [*print-dup* false
                    *print-meta* false
                    *print-readably* true
                    *print-length* nil
                    *print-level* nil
                    *print-namespace-maps* false]
            (pr-str x))]
    (if (= x (edn/read-string v))
      v
      (throw (ex-info (str "Could not pr-str object") {:input x})))))


(defn bytes->b64-str [^bytes b]
  (.encodeToString (Base64/getMimeEncoder 64 (.getBytes "\n" StandardCharsets/US_ASCII)) b))


(defn- part-str->bytes [part-str]
  (.decode (Base64/getMimeDecoder) (.getBytes ^String part-str StandardCharsets/US_ASCII)))

(defn- part-str->edn [part-str]
  (let [bytes (.decode (Base64/getMimeDecoder) (.getBytes ^String part-str StandardCharsets/US_ASCII))
        str' (String. bytes StandardCharsets/US_ASCII)]
    (edn/read-string str')))


(defn send-to-remote! [web-server-endpoint header buffer]
  (println ">>>> Client send" header (alength ^byte/1 buffer))
  (http/post web-server-endpoint header buffer))


(defn run-proxy! [tls-context web-server-endpoint ^Socket plaintext']
  ;; plaintext connection established
  (let [interim-echo-server (ServerSocket.)]
    (.bind interim-echo-server (InetSocketAddress. "127.0.0.1" 0))
    (let [echo-port (.getLocalPort interim-echo-server)
          _ (println "interim echo server listening on port" echo-port)
          tls-client (future
                       (try
                         (let [^SSLSocket sock (tls/socket tls-context "127.0.0.1" echo-port 10000)]
                           sock)
                         (catch Exception e
                           (println "Could not create tls-client:" (ex-message e))
                           e)))
          tcp-echo-sock (.accept interim-echo-server)
          _ (.close interim-echo-server)
          _ (println "interim echo server accepted socket")
          _ (.setSoTimeout tcp-echo-sock 1000)
          tcp-echo-read (BufferedInputStream. (.getInputStream tcp-echo-sock))
          tcp-echo-write (BufferedOutputStream. (.getOutputStream tcp-echo-sock))
          start-time (System/currentTimeMillis)
          session-id (str (random-uuid))
          ;; Establish mTLS connection. The TLS client will send some bytes to the echo server.
          ;; We send those bytes to the remote and keep the pump going until the tls-client is returned
          tls-client' (loop [n 0
                             remote-available? false]
                        (println "initial TLS pump" n)
                        (let [spent-ms (- (System/currentTimeMillis)
                                          start-time)]
                          (when (> spent-ms 60000)
                            (println "Spent too long time to establish mTLS connection")
                            (throw (ex-info "Could not establish mTLS connection (timeout)" {}))))
                        (if (realized? tls-client)
                          (let [tls-client' @tls-client]
                            (if (instance? Exception tls-client')
                              (do
                                (println "Could not create tls-client")
                                nil)
                              (do
                                (println "Returning tls client")
                                tls-client')))
                          (let [buffer (make-array Byte/TYPE buf-size)]
                            (let [size (if (and remote-available? (= 0 (.available tcp-echo-read)))
                                         0                  ; don't do a blocking read if the remote has more data coming
                                         (try
                                           #_(println "Reading from TCP echo server")
                                           (.read tcp-echo-read buffer)
                                           (catch SocketTimeoutException _ste
                                             0)))]
                              (if (= -1 size)
                                (do
                                  (println "EOF reached when reading from tcp-echo")
                                  nil)
                                (do
                                  #_(println "Read" size "bytes from tcp-echo")
                                  (let [available (.available tcp-echo-read)
                                        header {:session   session-id
                                                :available (pos? available)}]
                                    #_(println "tcp-echo available:" available)
                                    (let [[hdr chunk] (send-to-remote! web-server-endpoint header
                                                                       (^[byte/1 int] Arrays/copyOf buffer (int size)))]
                                      (println "<<<< Client recv" hdr (alength ^byte/1 chunk))
                                      (io/copy chunk tcp-echo-write)
                                      (.flush tcp-echo-write)
                                      (if (:eof hdr)
                                        nil
                                        (recur (inc n) (:available hdr)))))))))))]
      (when tls-client'
        (assert (instance? Socket tls-client'))
        (let [buf-plaintext (make-array Byte/TYPE buf-size)
              buf-tls (make-array Byte/TYPE (* 4 buf-size))]
          (with-open [sock plaintext'
                      plaintext-in (BufferedInputStream. (.getInputStream sock))
                      plaintext-out (BufferedOutputStream. (.getOutputStream sock))
                      tls-client-in (BufferedInputStream. (.getInputStream ^Socket tls-client'))
                      tls-client-out (BufferedOutputStream. (.getOutputStream ^Socket tls-client'))]
            (.setSoTimeout sock 1000)
            (.setSoTimeout ^Socket tls-client' 10)
            (.setSoTimeout tcp-echo-sock 10)
            (loop []
              ;; Read from the plaintext connection ...
              (let [n (try
                        (.read plaintext-in buf-plaintext)
                        (catch SocketTimeoutException _ste
                          0))]
                ;; Forward those bytes to the TLS client
                (when (pos-int? n)
                  (.write tls-client-out buf-plaintext 0 n)
                  (.flush tls-client-out))

                ;; Read those bytes back as "TLS bytes"
                (let [n2 (try
                           (.read tcp-echo-read buf-tls)
                           (catch SocketTimeoutException _ste
                             0))]

                  ;; Forward the TLS bytes to the remote web server
                  (let [[hdr chunk] (send-to-remote! web-server-endpoint
                                                     {:session session-id}
                                                     (^[byte/1 int] Arrays/copyOf buf-tls (int n2)))]
                    ;; Write the TLS bytes back to the TCP echo server ...
                    (.write tcp-echo-write ^byte/1 chunk)
                    (.flush tcp-echo-write)

                    ;; Read decrypted TLS back
                    (let [n3 (try
                               (.read tls-client-in buf-plaintext)
                               (catch SocketTimeoutException _ste
                                 0))]

                      ;; Write the decrypted bytes to the plaintext connection
                      (.write plaintext-out buf-plaintext 0 (int n3))
                      (.flush plaintext-out)
                      (recur))))))))))
    nil))

#_(defn dev [_]
    (let [v (make-array Byte/TYPE 123)
          cpy (^[byte/1 int] Arrays/copyOf v (int 0))])
    (send-to-remote! {} {}
                     (make-array Byte/TYPE 0)))

(defn start-plaintext-echo-server! [client-keys-file web-server-endpoint]
  (let [tls-context (tls/ssl-str-context (slurp client-keys-file))
        server (ServerSocket.)]
    (.bind server (InetSocketAddress. "127.0.0.1" 0))
    (future
      (loop []
        (let [sock (.accept server)]
          (future
            (try
              (run-proxy! tls-context web-server-endpoint sock)
              (catch Exception e
                (println ">>>> Local plaintext TCP->Web proxy crashed:" (ex-message e))
                (.printStackTrace e)))))
        (recur)))
    server))

#_(defn run [{:keys [remote-url]}]
    (let [[headers payload-bytes] (http/post remote-url {:hello :what})]
      (when-not (= (get headers :hello) :world)
        (throw (ex-info "Bad HTTP response for :hello message. Is web proxy running?" {:remote-url remote-url})))
      (println "OK :hello-message"))

    #_(let [opts' {:client-tls-context (tls/ssl-str-context (slurp "client.keys"))}
            plaintext-port 9999
            ss (ServerSocket. plaintext-port
                              0
                              (InetAddress/getLoopbackAddress))]
        (future
          (let [s (.accept ss)]
            (println "plaintext server got new client")
            (run-proxy! opts' s)))
        (with-open [client (^[InetAddress int] Socket/new (InetAddress/getLoopbackAddress) plaintext-port)
                    in (BufferedReader. (InputStreamReader. (.getInputStream client) StandardCharsets/US_ASCII))
                    out (.getOutputStream client)]
          (.write out (.getBytes "Hello\n" StandardCharsets/US_ASCII))
          (.flush out)
          (println "received:" (.readLine in)))))

(defn dev []
  (try
    (with-open [^ServerSocket tls-server (start-tls-echo-server! "server.keys")
                ^AutoCloseable web-server (web-echo-server/start-web-server! (atom {}) (.getLocalPort tls-server))
                ^ServerSocket plaintext-server (start-plaintext-echo-server!
                                                 "client.keys"
                                                 (str "http://127.0.0.1:"
                                                      (-> web-server meta :port)
                                                      "/nrepl"))]
      (let [web-server-port (-> web-server meta :port)
            plaintext-port (.getLocalPort plaintext-server)]
        (println "plaintext-server ready at port" plaintext-port)
        (println "web-server ready at port" web-server-port)
        (println "tls-server ready at port" (.getLocalPort tls-server))
        (with-open [^Socket client (Socket. "127.0.0.1" ^int plaintext-port)
                    in (BufferedReader. (InputStreamReader. (.getInputStream client) StandardCharsets/US_ASCII))
                    out (.getOutputStream client)]
          (println "Writing 'Hello\\n'")
          (.write out (.getBytes "Hello\n" StandardCharsets/US_ASCII))
          (.flush out)
          (println "Waiting for reply...")
          (let [fut (future
                      (println "received:" (.readLine in)))]
            (when (= :timeout (deref fut 20000 :timeout))
              (println "Timeout waiting for reply!"))))
        #_(run {:remote-url (str "http://127.0.0.1:" web-server-port "/nrepl")})))
    (catch Exception e
      (println "Error:" (ex-message e))))
  #_(let [web-server-port (web-echo-server/start-web-server! {})]
      (println "web-server port is:" web-server-port)))

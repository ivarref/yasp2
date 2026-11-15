(ns yasp2.mtls-web-proxy-client
  (:require [nrepl.http :as http]
            [nrepl.tls :as tls]
            [yasp2.web-server :as web-server])
  (:import (java.io BufferedInputStream BufferedOutputStream BufferedReader InputStream InputStreamReader OutputStream)
           (java.lang AutoCloseable)
           (java.net InetSocketAddress ServerSocket Socket SocketTimeoutException)
           (java.nio.charset StandardCharsets)
           (java.util Arrays)
           (javax.net.ssl SSLServerSocket)))

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


(defn send-to-remote!
  ([web-server-endpoint header]
   (http/post web-server-endpoint header))
  ([web-server-endpoint header buffer siz]
   (println ">>>> Client send" header (alength ^byte/1 buffer))
   (let [buf' (^[byte/1 int] Arrays/copyOf buffer (int siz))]
     (http/post web-server-endpoint header buf'))))


(defn read-some [^BufferedInputStream in ^byte/1 buf]
  (try
    (.read in buf)
    (catch SocketTimeoutException _ste
      0)))


(defn write-some [^BufferedOutputStream out buf size]
  (when (>= size 1)
    (.write out ^byte/1 buf 0 (int size))
    (.flush out)))


(defn write-all [^BufferedOutputStream out buf]
  (.write out ^byte/1 buf 0 (int (alength ^byte/1 buf)))
  (.flush out))


(defn- tls-handshake-pump [^String web-server-endpoint
                           ^String session-id
                           tls-sock-future
                           ^Socket tcp-echo-sock
                           ^BufferedInputStream tcp-echo-read
                           ^BufferedOutputStream tcp-echo-write]
  (.setSoTimeout tcp-echo-sock 1000)
  (let [start-time (System/currentTimeMillis)
        buffer (make-array Byte/TYPE buf-size)]
    (loop [n 0
           remote-available? false]
      (let [spent-ms (- (System/currentTimeMillis)
                        start-time)]
        (cond
          (> spent-ms 60000)
          (do
            (println "Spent too long time to establish mTLS connection")
            {:error :handshake-timeout})

          (realized? tls-sock-future)
          @tls-sock-future

          :else
          (let [size (if (and remote-available? (= 0 (.available tcp-echo-read)))
                       ; don't do a blocking read if the remote has more data coming
                       0
                       (read-some tcp-echo-read buffer))]
            (if (= -1 size)
              {:error :eof-tcp-echo}
              (let [available (.available tcp-echo-read)
                    header {:session   session-id
                            :data      true
                            :available available}]
                (let [[hdr chunk] (send-to-remote! web-server-endpoint header buffer size)]
                  (println "<<<< Client recv" hdr (alength ^byte/1 chunk))
                  (write-all tcp-echo-write chunk)
                  (if (:eof hdr)
                    {:error :eof-remote-handshake}
                    (recur (inc n) (:available hdr))))))))))))


(defn tls-pump [^String web-server-endpoint
                ^String session-id
                ^Socket plaintext
                ^Socket tcp-echo-sock
                ^BufferedInputStream tcp-echo-read
                ^BufferedOutputStream tcp-echo-write
                ^Socket tls-client]
  (let [buf-plaintext (make-array Byte/TYPE buf-size)
        buf-tls (make-array Byte/TYPE (* 4 buf-size))]
    (with-open [plaintext-in (BufferedInputStream. (.getInputStream plaintext))
                plaintext-out (BufferedOutputStream. (.getOutputStream plaintext))
                tls-client-in (BufferedInputStream. (.getInputStream tls-client))
                tls-client-out (BufferedOutputStream. (.getOutputStream tls-client))]
      (.setSoTimeout plaintext 1000)
      (.setSoTimeout tls-client 10)
      (.setSoTimeout tcp-echo-sock 10)
      (loop []
        ;; Read bytes from the plaintext connection
        (let [n (read-some plaintext-in buf-plaintext)]
          ;; Is it an EOF?
          (if (= -1 n)
            (do
              (send-to-remote! web-server-endpoint {:session session-id :eof true})
              {:eof :client})
            (do
              ;; Forward bytes to the TLS client
              (write-some tls-client-out buf-plaintext n)

              ;; Read bytes back as "TLS bytes"
              (let [n2 (read-some tcp-echo-read buf-tls)]
                (if (= -1 n2)
                  (throw (ex-info "Unexpected state: tcp-echo socket is closed" {}))

                  ;; Forward the TLS bytes to the remote web server
                  (let [data-hdr {:session session-id :data true}
                        [hdr chunk] (send-to-remote! web-server-endpoint data-hdr buf-tls n2)]
                    (cond
                      (:eof hdr)
                      {:eof :remote}

                      (:data hdr)
                      (do
                        ;; Write received TLS bytes back to the TCP echo server
                        (write-all tcp-echo-write chunk)

                        ;; Read decrypted TLS back
                        (let [n3 (read-some tls-client-in buf-plaintext)]
                          (if (= -1 n3)
                            (throw (ex-info "Unexpected state: tls-client socket is closed" {}))

                            (do
                              ;; Write the decrypted bytes to the plaintext connection
                              (write-some plaintext-out buf-plaintext n3)

                              ;; And keep going!
                              (recur)))))

                      :else
                      (throw (ex-info "Unexpected state" {:remote-header hdr})))))))))))))


(defn run-proxy! [tls-context web-server-endpoint ^Socket plaintext']
  ;; plaintext connection established
  (try
    (let [interim-echo-server (ServerSocket.)
          _ (.bind interim-echo-server (InetSocketAddress. "127.0.0.1" 0))
          echo-port (.getLocalPort interim-echo-server)]
      (let [tls-client (future
                         (try
                           (let [sock (tls/socket tls-context "127.0.0.1" echo-port 60000)]
                             {:sock sock})
                           (catch Exception e
                             (println "Could not create tls-client:" (ex-message e))
                             {:error e})))]
        (with-open [tcp-echo-sock (.accept interim-echo-server)
                    tcp-echo-read (BufferedInputStream. (.getInputStream tcp-echo-sock))
                    tcp-echo-write (BufferedOutputStream. (.getOutputStream tcp-echo-sock))]
          (tls/close-silently interim-echo-server)
          (let [session-id (str (random-uuid))
                ;; Establish mTLS connection.
                ;; The TLS client will send some bytes to the echo server.
                ;; We send those bytes to the remote and keep the pump going
                ;; until the tls-client is returned
                tls-client1 (tls-handshake-pump
                              web-server-endpoint
                              session-id
                              tls-client
                              tcp-echo-sock
                              tcp-echo-read
                              tcp-echo-write)]
            (cond
              (:error tls-client1)
              tls-client1

              (:sock tls-client1)
              (with-open [^Socket tls-client' (:sock tls-client1)]
                (try
                  (tls-pump web-server-endpoint
                            session-id
                            plaintext'
                            tcp-echo-sock
                            tcp-echo-read
                            tcp-echo-write
                            tls-client')
                  (catch Exception e
                    {:error     :tls-pump
                     :exception e})))

              :else
              (throw (ex-info "Unexpected state" {:tls-client tls-client1})))))))
    (finally
      (tls/close-silently plaintext'))))


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


(defn dev []
  (try
    (let [web-server-state (atom {})]
      (with-open [^ServerSocket tls-server (start-tls-echo-server! "server.keys")
                  ^AutoCloseable web-server (web-server/start-web-server! web-server-state (.getLocalPort tls-server))
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
              (when (= :timeout (deref fut 10000 :timeout))
                (println "Timeout waiting for reply!"))))
          (let [web-server-shutdown (future
                                      (while (not (empty? (keys (get @web-server-state :session))))
                                        (Thread/sleep 10)))]
            (when (= :timeout (deref web-server-shutdown 10000 :timeout))
              (println "Timeout waiting for web server to shutdown")))
          #_(run {:remote-url (str "http://127.0.0.1:" web-server-port "/nrepl")}))))
    (catch Exception e
      (println "Error:" (ex-message e)))))

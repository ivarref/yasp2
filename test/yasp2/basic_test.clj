(ns yasp2.basic-test
  (:require [clojure.string :as str]
            [clojure.test :refer :all]
            [nrepl.tls :as tls]
            [yasp2.mtls-web-proxy-client :as client]
            [yasp2.web-server :as web-server]
            [yasp2.certgen :as certgen])
  (:import (java.io BufferedInputStream BufferedOutputStream BufferedReader
                    BufferedWriter File InputStream InputStreamReader OutputStream OutputStreamWriter)
           (java.lang AutoCloseable)
           (java.lang.management ManagementFactory)
           (java.net ServerSocket Socket SocketException)
           (java.nio.charset StandardCharsets)
           (javax.net.ssl SSLServerSocket)))


(defn temp-file [file-name]
  (let [f (File/createTempFile file-name ".keys")]
    (.deleteOnExit f)
    #_(spit (.getAbsolutePath f) content)
    (.getAbsolutePath f)))


(defonce client-keys-1 (temp-file "client-1"))
(defonce server-keys-1 (temp-file "server-1"))

(defonce client-keys-2 (temp-file "client-2"))
(defonce server-keys-2 (temp-file "server-2"))


(defonce
  bootstrap-keys
  (do
    (let [{:keys [root-ca-cert server-key server-cert client-key client-cert]} (certgen/generate)]
      (spit server-keys-1 (str root-ca-cert "\n" server-cert "\n" server-key))
      (spit client-keys-1 (str root-ca-cert "\n" client-cert "\n" client-key)))
    (let [{:keys [root-ca-cert server-key server-cert client-key client-cert]} (certgen/generate)]
      (spit server-keys-2 (str root-ca-cert "\n" server-cert "\n" server-key))
      (spit client-keys-2 (str root-ca-cert "\n" client-cert "\n" client-key)))
    nil))


(defn sock->line-writer [^Socket sock]
  (let [out (OutputStreamWriter.
              (BufferedOutputStream. (.getOutputStream sock))
              StandardCharsets/UTF_8)]
    (fn [^String lin]
      (.write out lin)
      (.write out "\n")
      (.flush out))))


(defn sock->line-reader [^Socket sock]
  (let [in (-> (.getInputStream sock)
               (InputStreamReader. StandardCharsets/UTF_8)
               (BufferedReader.))]
    (fn []
      (.readLine in))))


(defn- do-copy [^InputStream input ^OutputStream output]
  (let [buffer (make-array Byte/TYPE 65536)]
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


(defn start-tls-echo-server! [futures-count server-keys-file]
  (let [server-ctx (tls/ssl-str-context (slurp server-keys-file))]
    (let [^SSLServerSocket server (tls/server-socket server-ctx "127.0.0.1" 0)
          accept-loop (future
                        (try
                          (swap! futures-count inc)
                          (loop []
                            (let [recur? (try
                                           (let [sock (.accept ^ServerSocket server)]
                                             (future
                                               (try
                                                 (swap! futures-count inc)
                                                 (echo-loop! sock)
                                                 (finally
                                                   (swap! futures-count dec))))
                                             true)
                                           (catch SocketException e
                                             (if (.isClosed server)
                                               nil
                                               (do
                                                 (.printStackTrace e)
                                                 (throw e)))))]
                              (when recur?
                                (recur))))
                          (finally
                            (swap! futures-count dec))))]
      (with-meta
        (reify AutoCloseable
          (close [_]
            (tls/close-silently server)
            (when (= :timeout (deref accept-loop 10000 :timeout))
              (throw (ex-info "Timeout waiting for tls echo server to shut down" {})))))
        {:port (.getLocalPort server)}))))


(defn port-of [x]
  (let [v (some-> x meta :port)]
    (assert (pos-int? v))
    v))


;; Case: Client EOFs
(deftest hello-client-eof
  (try
    (let [result-promise (promise)
          futures (atom 0)]
      (with-open [^AutoCloseable tls-server (start-tls-echo-server! futures "server.keys")
                  ^AutoCloseable web-server (web-server/start-web-server!
                                              (atom {}) (port-of tls-server))
                  ^AutoCloseable plaintext-server (client/start-proxy-server!
                                                    {:client-keys-file    "client.keys"
                                                     :web-server-endpoint (str "http://127.0.0.1:"
                                                                               (port-of web-server)
                                                                               "/nrepl")
                                                     :post-timeout-ms     3000
                                                     :result-promise      result-promise
                                                     :drain-on-close?     true})]
        (with-open [^Socket client (Socket. "127.0.0.1" ^int (port-of plaintext-server))
                    in (-> (.getInputStream client)
                           (InputStreamReader. StandardCharsets/UTF_8)
                           (BufferedReader.))
                    out (BufferedOutputStream. (.getOutputStream client))]
          (.setSoTimeout client 5000)
          (.write out (.getBytes "Hello ÆØÅ\n" StandardCharsets/UTF_8))
          (.flush out)
          (is (= "Hello ÆØÅ" (.readLine in)))

          (.write out (.getBytes "Yolo\n" StandardCharsets/UTF_8))
          (.flush out)
          (is (= "Yolo" (.readLine in)))))
      (is (= {:eof :client}
             @result-promise)))
    (catch Exception e
      (println "Error:" (ex-message e))
      (throw e))))


(defn uppercase-handler! [^Socket s]
  (let [in (BufferedReader. (InputStreamReader. (.getInputStream s) StandardCharsets/UTF_8))
        out (BufferedWriter. (OutputStreamWriter. (.getOutputStream s) StandardCharsets/UTF_8))]
    (loop []
      (when-let [lin (.readLine in)]
        (.write out (str/upper-case lin))
        (.write out "\n")
        (.flush out)))))


(defn start-tls-server!
  "A simple TLS server for development purposes.
  Calls conn-handler on new connections in a background thread."
  [server-keys-file conn-handler]
  (let [server-ctx (tls/ssl-str-context (slurp server-keys-file))
        futures-count (atom 0)]
    (let [^SSLServerSocket server (tls/server-socket server-ctx "127.0.0.1" 0)
          accept-loop (future
                        (try
                          (swap! futures-count inc)
                          (loop []
                            (let [recur? (try
                                           (let [sock (.accept ^ServerSocket server)]
                                             (.setKeepAlive sock true)
                                             (future
                                               (try
                                                 (swap! futures-count inc)
                                                 (conn-handler sock)
                                                 (catch Exception e
                                                   (.printStackTrace e)
                                                   (println "Conn-handler threw exception:"
                                                            (ex-message e)))
                                                 (finally
                                                   (tls/close-silently sock)
                                                   (swap! futures-count dec))))
                                             true)
                                           (catch SocketException e
                                             (if (.isClosed server)
                                               nil
                                               (do
                                                 (.printStackTrace e)
                                                 (throw e)))))]
                              (when recur?
                                (recur))))
                          (finally
                            (swap! futures-count dec))))]
      (with-meta
        (reify AutoCloseable
          (close [_]
            (tls/close-silently server)
            (when (= :timeout (deref accept-loop 10000 :timeout))
              (throw (ex-info "Timeout waiting for tls echo server to shut down" {})))))
        {:port (.getLocalPort server)}))))


(deftest eof-remote
  (try
    (let [result-promise (promise)]
      (with-open [^AutoCloseable tls-server (start-tls-server! "server.keys" uppercase-handler!)
                  ^AutoCloseable web-server (web-server/start-web-server!
                                              (atom {}) (port-of tls-server))
                  ^AutoCloseable plaintext-server (client/start-proxy-server!
                                                    {:client-keys-file    "client.keys"
                                                     :web-server-endpoint (str "http://127.0.0.1:"
                                                                               (port-of web-server)
                                                                               "/nrepl")
                                                     :post-timeout-ms     3000
                                                     :result-promise      result-promise
                                                     :drain-on-close?     true})]
        (with-open [^Socket client (Socket. "127.0.0.1" ^int (port-of plaintext-server))]
          (let [in (-> (.getInputStream client)
                       (InputStreamReader. StandardCharsets/UTF_8)
                       (BufferedReader.))
                out (BufferedOutputStream. (.getOutputStream client))]
            (.setSoTimeout client 5000)
            (.write out (.getBytes "hello\n" StandardCharsets/UTF_8))
            (.flush out)
            (is (= "HELLO" (.readLine in)))
            (.write out (.getBytes "yolo\n" StandardCharsets/UTF_8))
            (.flush out)))
        (is (= {:eof :remote-tls} @result-promise))))
    (catch Exception e
      (println "Error:" (ex-message e))
      (throw e))))


;; Case:
;; Client sends and receives lots of data. Keeps the pump going for some time.
;; TCP server only writes data, never read anything.
;; This causes HTTP server, which writes to the TCP server, to eventually become blocked.
;;
;; Which in turn results in that HTTP POST on client proxy side times out.
;; The client proxy then closes the connection.
;; Causing the client (TCP) connection to throw on read/write
;;
;; The result on the proxy is {:eof :http}
;;
;; Phew!

(deftest buffer-full->http-timeout
  (try
    (let [result-promise (promise)
          web-state (atom {})
          exception-count (atom 0)]
      #_(println "self pid is:" (.getPid (ManagementFactory/getRuntimeMXBean)))
      (with-open [^AutoCloseable tls-server (start-tls-server!
                                              "server.keys"
                                              (fn [sock]
                                                (try
                                                  (let [write (sock->line-writer sock)]
                                                    (loop []
                                                      (write "yolo")
                                                      (recur)))
                                                  (catch Exception _e
                                                    ;; Connection/socket closed when shutting down
                                                    ;; web server
                                                    (swap! exception-count inc)
                                                    nil))))
                  ^AutoCloseable web-server (web-server/start-web-server!
                                              web-state (port-of tls-server))
                  ^AutoCloseable plaintext-server (client/start-proxy-server!
                                                    {:client-keys-file    "client.keys"
                                                     :web-server-endpoint (str "http://127.0.0.1:"
                                                                               (port-of web-server)
                                                                               "/nrepl")
                                                     :post-timeout-ms     3000
                                                     :result-promise      result-promise
                                                     :drain-on-close?     true})
                  ^Socket client (Socket. "127.0.0.1" ^int (port-of plaintext-server))]
        (try
          (let [read-line (sock->line-reader client)
                write (sock->line-writer client)]
            (while true
              (write "hello")
              (read-line)))
          (catch Exception _e
            ;; The proxy has closed the connection while we were using it.
            ;; The cause: timeout for POST-ing
            (swap! exception-count inc)
            nil)))
      (is (= 2 @exception-count))
      (is (= {:eof :http-timeout} @result-promise)))
    (catch Exception e
      (println "buffer-full->http-timeout error:" (ex-message e))
      (throw e))))


(deftest bad-client-keys
  (try
    (let [result-promise (promise)
          web-state (atom {})]
      (with-open [^AutoCloseable tls-server (start-tls-server!
                                              server-keys-1
                                              (fn [sock]
                                                (try
                                                  (let [write (sock->line-writer sock)]
                                                    (write "yolo"))
                                                  (catch Exception _e
                                                    nil))))
                  ^AutoCloseable web-server (web-server/start-web-server!
                                              web-state (port-of tls-server))
                  ^AutoCloseable plaintext-server (client/start-proxy-server!
                                                    {:client-keys-file    client-keys-2
                                                     :web-server-endpoint (str "http://127.0.0.1:"
                                                                               (port-of web-server)
                                                                               "/nrepl")
                                                     :post-timeout-ms     3000
                                                     :result-promise      result-promise
                                                     :drain-on-close?     true})]
        (try
          (with-open [^Socket _client (Socket. "127.0.0.1" ^int (port-of plaintext-server))])
          (catch Exception _e
            ;; The proxy may have closed the connection while we were using it.
            ;; The cause: TLS handshake error
            nil)))
      (is (= :handshake-error (:eof @result-promise))))
    (catch Exception e
      (println "bad-client-keys error:" (ex-message e))
      (throw e))))


;; TODO the error message for this is not good enough ... We can do better!
(deftest bad-key-type
  (try
    (let [result-promise (promise)
          web-state (atom {})]
      (with-open [^AutoCloseable tls-server (start-tls-server! client-keys-1 (fn [sock] nil))
                  ^AutoCloseable web-server (web-server/start-web-server!
                                              web-state (port-of tls-server))
                  ^AutoCloseable plaintext-server (client/start-proxy-server!
                                                    {:client-keys-file    server-keys-1
                                                     :web-server-endpoint (str "http://127.0.0.1:"
                                                                               (port-of web-server)
                                                                               "/nrepl")
                                                     :post-timeout-ms     3000
                                                     :result-promise      result-promise
                                                     :drain-on-close?     true})]
        (try
          (with-open [^Socket _client (Socket. "127.0.0.1" ^int (port-of plaintext-server))])
          (catch Exception _e
            ;; The proxy may have closed the connection while we were using it.
            ;; The cause: TLS handshake error
            nil)))
      (is (= :handshake-error (:eof @result-promise))))
    (catch Exception e
      (println "bad-client-keys error:" (ex-message e))
      (throw e))))


;; Trigger client-disconnected state by
;; 1. Filling the buffer to client-in in the proxy
;; 2. Wait for the proxy to block on write
;; 3. Disconnect client
#_(deftest ^:focus client-disconnected
    (try
      (let [result-promise (promise)]
        (with-open [^AutoCloseable tls-server (start-tls-server!
                                                "server.keys"
                                                (fn [sock]
                                                  (let [out (BufferedOutputStream. (.getOutputStream sock))]
                                                    (loop [line 1]
                                                      (.write out (.getBytes "hello\n" StandardCharsets/UTF_8))
                                                      (.flush out)
                                                      (println "wrote line" line)
                                                      (recur (inc line))))))
                    ^AutoCloseable web-server (web-server/start-web-server!
                                                (atom {}) (port-of tls-server))
                    ^AutoCloseable plaintext-server (client/start-proxy-server!
                                                      "client.keys"
                                                      (str "http://127.0.0.1:"
                                                           (port-of web-server)
                                                           "/nrepl")
                                                      result-promise
                                                      true)]
          (with-open [^Socket client (Socket. "127.0.0.1" ^int (port-of plaintext-server))]
            (let [in (-> (.getInputStream client)
                         (InputStreamReader. StandardCharsets/UTF_8)
                         (BufferedReader.))
                  out (BufferedOutputStream. (.getOutputStream client))]
              (.setSoTimeout client 5000)
              (Thread/sleep 5000)
              #_(Thread/sleep 1000)))
          (is (= {:eof :client-disconnected} @result-promise))))
      (catch Exception e
        (println "Error:" (ex-message e))
        (throw e))))

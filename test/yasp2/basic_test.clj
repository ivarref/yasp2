(ns yasp2.basic-test
  (:require [clojure.test :refer :all]
            [nrepl.tls :as tls]
            [yasp2.mtls-web-proxy-client :as client]
            [yasp2.web-server :as web-server])
  (:import (java.io BufferedInputStream BufferedOutputStream BufferedReader
                    InputStream InputStreamReader OutputStream)
           (java.lang AutoCloseable)
           (java.net ServerSocket Socket SocketException)
           (java.nio.charset StandardCharsets)
           (javax.net.ssl SSLServerSocket)))


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


;; Case: Client EOFs
#_(deftest hello-client-eof
    (try
      (let [web-server-state (atom {})
            result-promise (promise)
            futures (atom 0)]
        (with-open [^AutoCloseable tls-server (start-tls-echo-server! futures "server.keys")
                    ^AutoCloseable web-server (web-server/start-web-server!
                                                web-server-state (-> tls-server meta :port))
                    ^ServerSocket plaintext-server (client/start-proxy-server!
                                                     "client.keys"
                                                     (str "http://127.0.0.1:"
                                                          (-> web-server meta :port)
                                                          "/nrepl")
                                                     result-promise)]
          (let [_web-server-port (-> web-server meta :port)
                plaintext-port (.getLocalPort plaintext-server)]
            (with-open [^Socket client (Socket. "127.0.0.1" ^int plaintext-port)
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
              (is (= "Yolo" (.readLine in)))
              (is (= 1 (count (keys (get @web-server-state :session))))))
            (let [web-server-shutdown (future
                                        (while (not (empty? (keys (get @web-server-state :session))))
                                          (Thread/sleep 10)))]
              (when (= :timeout (deref web-server-shutdown 10000 :timeout))
                (println "Timeout waiting for web server to shutdown")))))
        (while (not= 0 @futures)
          (Thread/sleep 10))
        (when (= :timeout (deref result-promise 10000 :timeout))
          (throw (ex-info "Timeout waiting for result-promise" {})))
        (is (= {:eof :client}
               @result-promise)))
      (catch Exception e
        (println "Error:" (ex-message e))
        (throw e))))


(defn uppercase-loop! [^Socket s]
  (with-open [_s s
              in (BufferedInputStream. (.getInputStream s))
              out (BufferedOutputStream. (.getOutputStream s))]
    (do-copy in out)))


(defn start-uppercase-echo-server! [futures-count server-keys-file]
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
                                                 (uppercase-loop! sock)
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


(deftest client-disconnect
  (try
    (let [web-server-state (atom {})
          result-promise (promise)
          futures (atom 0)]
      (with-open [^AutoCloseable tls-server (start-tls-echo-server! futures "server.keys")
                  ^AutoCloseable web-server (web-server/start-web-server!
                                              web-server-state
                                              (-> tls-server meta :port))
                  ^AutoCloseable plaintext-server (client/start-proxy-server!
                                                    "client.keys"
                                                    (str "http://127.0.0.1:"
                                                         (-> web-server meta :port)
                                                         "/nrepl")
                                                    result-promise)]
        (with-open [^Socket client (Socket. "127.0.0.1" ^int (-> plaintext-server meta :port))]
          (let [in (-> (.getInputStream client)
                       (InputStreamReader. StandardCharsets/UTF_8)
                       (BufferedReader.))
                out (BufferedOutputStream. (.getOutputStream client))]
            (.setSoTimeout client 5000)
            (.write out (.getBytes "Hello ÆØÅ\n" StandardCharsets/UTF_8))
            (.flush out)
            #_(is (= "Hello ÆØÅ" (.readLine in)))))
        (let [web-server-shutdown (future
                                    (while (not (empty? (keys (get @web-server-state :session))))
                                      (Thread/sleep 10)))]
          (when (= :timeout (deref web-server-shutdown 10000 :timeout))
            (println "Timeout waiting for web server to shutdown"))))
      (while (not= 0 @futures)
        (Thread/sleep 10))
      (when (= :timeout (deref result-promise 10000 :timeout))
        (throw (ex-info "Timeout waiting for result-promise" {})))
      (println @result-promise)
      #_(is (= {:eof :client}
               @result-promise)))
    (catch Exception e
      (println "Error:" (ex-message e))
      (throw e))))

(ns yasp2.web-server
  (:require [clojure.java.io :as io]
            [nrepl.http :as http]
            [nrepl.tls :as tls]
            [yasp2.post-body-handler :as post-body-handler])
  (:import (com.sun.net.httpserver HttpExchange HttpHandler HttpHandlers HttpServer Request)
           (java.io BufferedInputStream BufferedOutputStream ByteArrayOutputStream IOException)
           (java.lang AutoCloseable)
           (java.net InetSocketAddress Socket SocketTimeoutException)
           (java.nio.charset Charset StandardCharsets)
           (java.util Arrays)
           (java.util.function Predicate)))


;; Run a web server that
;; writes to a plain bytes TCP connection ...


(defn- respond!
  [^HttpExchange ex ^long code ^String body]
  (let [bs (.getBytes body StandardCharsets/UTF_8)]
    (.sendResponseHeaders ex code (alength bs))
    (with-open [os (.getResponseBody ex)]
      (.write os bs))))


(def post-request?
  (reify Predicate
    (test [_ req]
      (= "POST" (.getRequestMethod ^Request req)))))


(defn post-handler
  [state-atom proxy-to-port ^HttpExchange ex]
  (locking state-atom
    (swap! state-atom
           (fn [old-state]
             (update old-state :request-count (fn [x] (inc (or x 0)))))))
  (let [encoded-response (try
                           (with-open [input-stream (.getRequestBody ex)
                                       baos (ByteArrayOutputStream.)]
                             (io/copy input-stream baos)
                             (let [body-str (^[byte/1 Charset] String/new
                                              (.toByteArray baos)
                                              StandardCharsets/US_ASCII)
                                   resp (post-body-handler/handle-body
                                          state-atom proxy-to-port body-str)]
                               resp))
                           (catch Exception e
                             (.printStackTrace e)
                             (http/encode {:eof   :internal-error
                                           :error (str "Exception: " (ex-message e))})))]
    (respond! ex 200 encoded-response)))


(def fallback-handler
  (reify HttpHandler
    (^void handle [_ ^HttpExchange ex]
      (.add (.getResponseHeaders ex) "Allow" "POST")
      (respond! ex 405 "method not allowed\n"))))


(defn create-handler [state-atom proxy-to-port]
  (HttpHandlers/handleOrElse
    post-request?
    (reify HttpHandler
      (^void handle [_ ^HttpExchange ex]
        (locking state-atom
          (swap! state-atom (fn [old-state]
                              (update old-state :running-threads
                                      (fnil conj #{})
                                      (Thread/currentThread)))))
        (try
          (post-handler state-atom proxy-to-port ex)
          (finally
            (locking state-atom
              (swap! state-atom (fn [old-state]
                                  (update old-state :running-threads
                                          (fnil disj #{})
                                          (Thread/currentThread)))))))))
    fallback-handler))


(defn start-web-server! [state-atom proxy-to-port]
  (let [server (HttpServer/create (InetSocketAddress. "127.0.0.1" 0) 0)]
    (.createContext server "/nrepl" ^HttpHandler (create-handler state-atom proxy-to-port))
    (future (.start server))
    (with-meta
      (reify AutoCloseable
        (close [_]
          #_(println "web-server: Begin shutdown")
          (doseq [{:keys [socket in out]} (vals (get @state-atom :session))]
            #_(println "Force closing connection ...")
            (tls/close-silently in)
            (tls/close-silently out)
            (tls/close-silently socket))
          (let [stop-server-job (future (.stop server 3))]
            (when (= :timeout (deref stop-server-job 5000 :timeout))
              (binding [*out* *err*]
                (println "Warning: Timeout waiting for web server to stop"))))))
      {:port (.getPort (.getAddress server))})))

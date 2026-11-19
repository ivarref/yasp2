(ns yasp2.web-server
  (:require [clojure.java.io :as io]
            [nrepl.http :as http]
            [nrepl.tls :as tls])
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


(defn make-connection! [proxy-to-port]
  (let [s (^[String int] Socket/new "127.0.0.1" proxy-to-port)]
    (.setSoTimeout s 10)
    {:socket s
     :in     (BufferedInputStream. (.getInputStream s))
     :out    (BufferedOutputStream. (.getOutputStream s))}))


(defn handle-body [state-atom proxy-to-port [headers payload-bytes]]
  (let [session-id (get headers :session)]
    (cond
      (= :what (get headers :hello nil))
      (http/encode {:hello :world})

      (and session-id (get headers :eof))
      (locking state-atom
        (try
          #_(println "Web server: Received EOF")
          (let [{:keys [^Socket socket ^BufferedInputStream in out]} (get-in @state-atom [:session session-id])]
            (tls/close-silently out)
            (tls/close-silently in)
            (tls/close-silently socket)
            (swap! state-atom
                   (fn [old-state]
                     (update old-state :session (fn [sess] (dissoc sess session-id)))))
            (http/encode {:session-id session-id
                          :closed     true}))
          (catch Exception e
            (println "Web server: Exception while closing sockets:" (ex-message e))
            (.printStackTrace e)
            (http/encode {:session-id session-id
                          :error      (ex-message e)}))))


      (and session-id (get headers :data))
      (let [new-state (locking state-atom
                        (swap! state-atom
                               (fn [old-state]
                                 (if (some? (get-in old-state [:session session-id]))
                                   old-state
                                   (assoc-in old-state [:session session-id]
                                             (make-connection! proxy-to-port))))))
            buf-size (get headers :buf-size)]
        (let [{:keys [^Socket _socket
                      ^BufferedInputStream in
                      ^BufferedOutputStream out]} (get-in new-state [:session session-id])
              buffer (make-array Byte/TYPE buf-size)
              write-exception (atom nil)]
          (try
            (.write out ^byte/1 payload-bytes)
            (.flush out)
            (catch IOException e
              (reset! write-exception e)))
          (if-let [write-ex @write-exception]
            (http/encode {:session session-id
                          :error   :write
                          :detail  (ex-message write-ex)})
            (let [size (try
                         (.read in buffer)
                         (catch SocketTimeoutException _ste
                           0))]
              (if (= -1 size)
                (http/encode {:session session-id
                              :eof     true})
                (do
                  #_(println "<<<< Web server recv" headers (alength payload-bytes))
                  (http/encode {:session   session-id
                                :data      true
                                :available false #_(.available in)}
                               (^[byte/1 int] Arrays/copyOf buffer (int size)))))))))

      :else
      (do
        (println "Web echo server: not implemented headers:" headers)
        (http/encode {:error :not-implemented})))))


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
                             (let [body-str (^[byte/1 Charset] String/new (.toByteArray baos) StandardCharsets/US_ASCII)
                                   decoded (http/decode-body-string body-str)
                                   resp (handle-body state-atom proxy-to-port decoded)]
                               resp))
                           (catch Exception e
                             (http/encode {:error (str "Exception: " (ex-message e))})))]
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
        (post-handler state-atom proxy-to-port ex)))
    fallback-handler))


(defn start-web-server! [state-atom proxy-to-port]
  (let [server (HttpServer/create (InetSocketAddress. "127.0.0.1" 0) 0)]
    (.createContext server "/nrepl" ^HttpHandler (create-handler state-atom proxy-to-port))
    (.start server)
    (with-meta
      (reify AutoCloseable
        (close [_]
          (let [stop-server-job (future (.stop server 10))]
            (when (= :timeout (deref stop-server-job 5000 :timeout))
              (binding [*out* *err*]
                (println "Warning: Timeout waiting for web server to stop"))))
          (let [web-server-shutdown (future
                                      (while (not (empty? (keys (get @state-atom :session))))
                                        (Thread/sleep 10)))]
            (when (= :timeout (deref web-server-shutdown 5000 :timeout))
              (binding [*out* *err*]
                (println "Warning: Timeout waiting for web sessions to exit"))))))
      {:port (.getPort (.getAddress server))})))

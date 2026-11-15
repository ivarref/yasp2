(ns yasp2.echo-tcp-server
  (:require [clojure.string :as str]
            [nrepl.tls-utils :as tls-utils])
  (:import (com.sun.net.httpserver HttpExchange HttpHandler HttpHandlers HttpServer Request)
           (java.io BufferedInputStream BufferedOutputStream ByteArrayOutputStream IOException InputStream OutputStream StringReader)
           (java.net InetAddress InetSocketAddress ServerSocket Socket)
           (java.nio.charset StandardCharsets)
           (java.util.function Predicate)))


(set! *warn-on-reflection* true)





(defn echo! [^Socket s]
  (with-open [in (BufferedInputStream. (.getInputStream s))
              out (BufferedOutputStream. (.getOutputStream s))]
    (tls-utils/do-copy in out)))


(defn run [opts]
  (let [ss (ServerSocket. (get opts :port 9999)
                          0
                          (InetAddress/getLoopbackAddress))]
    (loop []
      (let [s (.accept ss)]
        (future (echo! s))
        (recur)))))


(defn- respond!
  [^HttpExchange ex ^long code ^String body]
  (let [bs (.getBytes body StandardCharsets/UTF_8)]
    (.sendResponseHeaders ex code (alength bs))
    (with-open [os (.getResponseBody ex)]
      (.write os bs))))

;; Predicate<Request>: boolean test(Object)
(def post-request?
  (reify Predicate
    (test [_ req]
      (= "POST" (.getRequestMethod ^Request req)))))


(defn encode-response [])

;; HttpHandler: void handle(HttpExchange) throws IOException
(def post-handler
  (reify HttpHandler
    (^void handle [_ ^HttpExchange ex]
      (when (= "/boom" (.getPath (.getRequestURI ex)))
        ;; no 'throws' clause needed – Clojure lets you throw checked exceptions
        (throw (IOException. "simulated I/O failure")))
      (with-open [input-stream (.getRequestBody ex)
                  baos (ByteArrayOutputStream.)]
        (clojure.java.io/copy input-stream baos)
        (let [body-str (String. (.toByteArray baos) StandardCharsets/US_ASCII)
              parts (str/split body-str #"\.")]
          (if (= 2 (count parts))
            (respond! ex 200 "OK body POST\n")
            (respond! ex 200 "broken body POST\n")))))))

(def fallback-handler
  (reify HttpHandler
    (^void handle [_ ^HttpExchange ex]
      (.add (.getResponseHeaders ex) "Allow" "POST")
      (respond! ex 405 "method not allowed\n"))))

(def handler
  (HttpHandlers/handleOrElse post-request? post-handler fallback-handler))

(defn start-web-server! [_]
  (doto (HttpServer/create (InetSocketAddress. (InetAddress/getLoopbackAddress) 8080) 0)
    (.createContext "/" ^HttpHandler handler)
    (.start)))

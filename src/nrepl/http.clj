(ns nrepl.http
  (:require [clojure.edn :as edn]
            [clojure.string :as str])
  (:import (java.net URI)
           (java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers
                          HttpResponse$BodyHandlers)
           (java.nio.charset Charset StandardCharsets)
           (java.time Duration)
           (java.util Base64)))


(set! *warn-on-reflection* true)


(def client
  (-> (HttpClient/newBuilder)
      (.connectTimeout (Duration/ofSeconds 5))
      (.build)))




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


(defn- str->b64-str [^String b]
  (.encodeToString (Base64/getMimeEncoder 64 (.getBytes "\n" StandardCharsets/US_ASCII))
                   (.getBytes b StandardCharsets/US_ASCII)))


(defn- bytes->b64-str [^bytes b]
  (.encodeToString (Base64/getMimeEncoder 64 (.getBytes "\n" StandardCharsets/US_ASCII)) b))


(defn- b64-str->bytes [^String s]
  (.decode (Base64/getMimeDecoder) (.getBytes ^String s StandardCharsets/US_ASCII)))


(defn- part-str->edn [part-str]
  (let [bytes (.decode (Base64/getMimeDecoder) (.getBytes ^String part-str StandardCharsets/US_ASCII))
        str' (String. bytes StandardCharsets/US_ASCII)]
    (edn/read-string str')))


(defn encode
  ([header]
   (encode header (make-array Byte/TYPE 0)))
  ([header payload]
   (str (str->b64-str (pr-str-safe header))
        "."
        (bytes->b64-str payload))))


(defn decode-body-string [^String body-str]
  (let [parts (str/split body-str #"\.")]
    (if (or (= 1 (count parts))
            (= 2 (count parts)))
      (let [header-bytes (b64-str->bytes (first parts))
            header-str (^[byte/1 Charset] String/new header-bytes StandardCharsets/US_ASCII)
            header-map (edn/read-string header-str)
            payload-bytes (if (= 1 (count parts))
                            (make-array Byte/TYPE 0)
                            (b64-str->bytes (second parts)))]
        [header-map payload-bytes])
      (throw (ex-info "Unexpected body format" {:body body-str})))))


(defn- post-text [^String url ^String body]
  (let [req (-> (HttpRequest/newBuilder (URI/create url))
                (.timeout (Duration/ofSeconds 60))
                (.header "Content-Type" "text/plain; charset=utf-8")
                (.POST (HttpRequest$BodyPublishers/ofString body StandardCharsets/UTF_8))
                (.build))
        resp (.send ^HttpClient client req (HttpResponse$BodyHandlers/ofString))]
    (if (= 200 (.statusCode resp))
      (decode-body-string (.body resp))
      (throw (ex-info "Unexpected HTTP status code" {:code (.statusCode resp)})))))


(defn post
  ([^String url header]
   (post url header (make-array Byte/TYPE 0)))
  ([^String url header payload]
   (assert (map? header))
   (post-text url (encode header payload))))
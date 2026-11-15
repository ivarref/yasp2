(ns nrepl.web-utils
  (:require [clojure.edn :as edn])
  (:import (java.nio.charset StandardCharsets)
           (java.util Base64)))

(set! *warn-on-reflection* true)


(defn- bytes->b64-str [^bytes b]
  (.encodeToString (Base64/getMimeEncoder 64 (.getBytes "\n" StandardCharsets/US_ASCII)) b))


(defn- b64-str->bytes [^String s]
  (let [bytes (.decode (Base64/getMimeDecoder) (.getBytes ^String s StandardCharsets/US_ASCII))
        str' (String. bytes StandardCharsets/US_ASCII)]
    (edn/read-string str')))


(defn- b64-str->edn [^String s]
  (let [bytes (.decode (Base64/getMimeDecoder) (.getBytes ^String s StandardCharsets/US_ASCII))
        str' (String. bytes StandardCharsets/US_ASCII)]
    (edn/read-string str')))

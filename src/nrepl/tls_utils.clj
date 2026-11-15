(ns nrepl.tls-utils
  (:require [clojure.edn :as edn]
            [clojure.string :as str])
  (:import (java.io InputStream OutputStream)
           (java.util Base64)))

(defn- do-copy [^InputStream input ^OutputStream output]
  (let [buffer (make-array Byte/TYPE 65536)]
    (loop []
      (let [size (.read input buffer)]
        (when (pos? size)
          (do (.write output buffer 0 size)
              (.flush output)
              (recur)))))))

(defn- base64->binary ^bytes [^String string]
  (.decode (Base64/getMimeDecoder) string))

(defn decode-body-str [body-str]
  (let [parts (str/split body-str #"\.")]
    (cond
      (= 2 (count parts))
      (let [[header bytes] parts]
        {:header (edn/read-string (base64->binary header))
         :bytes  (base64->binary bytes)})

      (= 1 (count parts))
      {:header (edn/read-string (base64->binary (first parts)))
       :bytes  (make-array Byte/TYPE 0)}

      :else
      (throw (ex-info "Unexpected body format" {:body body-str})))))
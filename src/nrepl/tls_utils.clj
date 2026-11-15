(ns nrepl.tls-utils
  (:import (java.io InputStream OutputStream)))


(defn- do-copy [^InputStream input ^OutputStream output]
  (let [buffer (make-array Byte/TYPE 65536)]
    (loop []
      (let [size (.read input buffer)]
        (when (pos? size)
          (do (.write output buffer 0 size)
              (.flush output)
              (recur)))))))
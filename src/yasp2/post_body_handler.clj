(ns yasp2.post-body-handler
  (:require [clojure.java.io :as io]
            [nrepl.http :as http]
            [nrepl.tls :as tls])
  (:import (java.io BufferedInputStream BufferedOutputStream ByteArrayOutputStream IOException
                    InputStream)
           (java.net Socket SocketTimeoutException)
           (java.nio.charset Charset)
           (java.util Arrays)
           (sun.nio.cs US_ASCII)))

(defn make-connection! [proxy-to-port]
  (let [s (^[String int] Socket/new "127.0.0.1" proxy-to-port)]
    (.setSoTimeout s 10)
    (.setKeepAlive s true)
    {:socket s
     :in     (BufferedInputStream. (.getInputStream s))
     :out    (BufferedOutputStream. (.getOutputStream s))}))

(defn handle-data! [session-id session-state buf-size payload-bytes]
  (let [{:keys [^Socket _socket ^BufferedInputStream in ^BufferedOutputStream out]} session-state
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

(defn- handle-body-decoded [state-atom proxy-to-port [headers payload-bytes]]
  (let [session-id (get headers :session)]
    (cond
      (= :what (get headers :hello nil))
      (http/encode {:hello :world})

      (and session-id (get headers :eof))
      (locking state-atom
        (try
          #_(println "Web server: Received EOF")
          (let [{:keys [^Socket socket ^BufferedInputStream in out]}
                (get-in @state-atom [:session session-id])]
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
        (handle-data! session-id
                      (get-in new-state [:session session-id])
                      buf-size
                      payload-bytes))

      :else
      (do
        (println "Web echo server: not implemented headers:" headers)
        (http/encode {:eof :not-implemented-headers})))))


(defn handle-body [state-atom proxy-port body]
  (cond
    (string? body)
    (let [resp-str (handle-body-decoded state-atom proxy-port (http/decode-body-string body))]
      (assert (string? resp-str))
      resp-str)

    (instance? InputStream body)
    (with-open [baos (ByteArrayOutputStream.)]
      (io/copy ^InputStream body baos)
      (let [body-str (^[byte/1 Charset] String/new
                       (.toByteArray baos)
                       US_ASCII)]
        (handle-body state-atom proxy-port body-str)))

    :else
    (http/encode {:eof :unhandled-body-type})))


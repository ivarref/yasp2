(ns yasp2.mtls-web-proxy-client
  (:require [nrepl.http :as http]
            [nrepl.tls :as tls]
            [yasp2.web-server :as web-server])
  (:import (java.io BufferedInputStream BufferedOutputStream BufferedReader InputStream InputStreamReader IOException OutputStream)
           (java.lang AutoCloseable)
           (java.net InetSocketAddress ServerSocket Socket SocketTimeoutException)
           (java.nio ByteBuffer)
           (java.nio.charset StandardCharsets)
           (java.util Arrays)
           (javax.net.ssl SSLContext SSLEngine SSLEngineResult SSLEngineResult$HandshakeStatus SSLEngineResult$Status SSLServerSocket)))

(set! *warn-on-reflection* true)

;; The basic idea:
;; A client and server using mTLS over the wire.
;; The "wire" is HTTP posts.

;; Each POST and response contains a header and "raw" TLS bytes.
;; The header contains information such as:
;; * is there more bytes available?
;; * session id
;; * EOF?


(defn read-some [^BufferedInputStream in ^byte/1 buf]
  (try
    (.read in buf)
    (catch SocketTimeoutException _ste
      0)
    (catch IOException _ioe
      -1)))


(defn run-delegated-tasks [^SSLEngine engine]
  (while (= SSLEngineResult$HandshakeStatus/NEED_TASK (.getHandshakeStatus engine))
    (when-let [^Runnable task (.getDelegatedTask engine)]
      (.run task))))


(defn bytebuffer-drain-to-byte-array
  "Copies the bytes written so far (0 .. position) to a byte array. Clears input byte buffer afterwards."
  [^ByteBuffer buf]
  (let [_ (.flip buf)
        arr (byte-array (.remaining buf))]
    (.get ^ByteBuffer buf arr)
    (.clear buf)
    arr))


(defn check-engine-result! [^SSLEngineResult res]
  (let [status (.getStatus res)]
    (cond
      (= SSLEngineResult$Status/OK status)
      :ok

      (= SSLEngineResult$Status/BUFFER_OVERFLOW status)
      (throw (ex-info "Got SSLEngineResult$Status/BUFFER_OVERFLOW" {}))

      (= SSLEngineResult$Status/BUFFER_UNDERFLOW status)
      :underflow

      (= SSLEngineResult$Status/CLOSED status)
      :closed)))


(defn handshake-drain-wraps! [^SSLEngine engine ^ByteBuffer net-out]
  ;; This will generate handshake bytes to send to the remote
  (while (= SSLEngineResult$HandshakeStatus/NEED_WRAP (.getHandshakeStatus engine))
    (let [^SSLEngineResult res (.wrap engine (ByteBuffer/allocate 0) net-out)]
      (check-engine-result! res)
      (run-delegated-tasks engine)))
  (bytebuffer-drain-to-byte-array net-out))


(defn handshake-feed-unwraps! [^SSLEngine engine
                               ^ByteBuffer net-in
                               ^ByteBuffer app-in
                               ^byte/1 byte-chunk]
  ;; Push data received from the remote to the SSLEngine
  (.put net-in byte-chunk)
  (.flip net-in)
  (try
    (loop []
      ;; leftover bytes after the handshake is stored in net-in
      (when (and (.hasRemaining net-in)
                 (= SSLEngineResult$HandshakeStatus/NEED_UNWRAP (.getHandshakeStatus engine)))
        (let [^SSLEngineResult res (.unwrap engine net-in app-in)]
          (run-delegated-tasks engine)
          (when (and (= :ok (check-engine-result! res))
                     (pos-int? (.bytesConsumed res)))
            (recur)))))
    (finally
      (.compact net-in))))


(defn unwraps! [^SSLEngine engine
                ^ByteBuffer net-in
                ^ByteBuffer app-in
                ^byte/1 byte-chunk]
  ;; Push data received from net-in to app-in (via SSLEngine)
  (.put net-in byte-chunk)
  (.flip net-in)
  (try
    (loop []
      (when (.hasRemaining net-in)
        (let [^SSLEngineResult res (.unwrap engine net-in app-in)]
          (run-delegated-tasks engine)
          (check-engine-result! res)
          (when (pos-int? (.bytesConsumed res))
            (recur)))))
    (if (.isInboundDone engine)
      ;; TLS shutdown/close received
      :closed
      :open)
    (finally
      (.compact net-in))))


(defn wraps! [^SSLEngine engine
              ^ByteBuffer app-out
              ^ByteBuffer net-out
              ^byte/1 byte-chunk]
  ;; Push data received from the plaintext to the SSLEngine
  (.put app-out byte-chunk)
  (.flip app-out)
  (try
    (loop []
      (when (or (.hasRemaining app-out)
                (= SSLEngineResult$HandshakeStatus/NEED_WRAP (.getHandshakeStatus engine)))
        (let [^SSLEngineResult res (.wrap engine app-out net-out)]
          (run-delegated-tasks engine)
          (when (and (= :ok (check-engine-result! res))
                     (or (pos-int? (.bytesConsumed res))
                         (pos-int? (.bytesProduced res))))
            (recur)))))
    (finally
      (.compact app-out))))


(defn handshake! [^String session-id
                  buf-size
                  ^SSLEngine engine ^String web-server-endpoint
                  ^ByteBuffer net-in ^ByteBuffer net-out
                  ^ByteBuffer app-in]
  (.beginHandshake engine)
  (loop [start-ms (System/currentTimeMillis)]
    (let [spent-ms (- (System/currentTimeMillis)
                      start-ms)]
      (if (> spent-ms 30000)
        (throw (ex-info "Spent too long handshaking" {}))
        (let [handshake-status (.getHandshakeStatus engine)]
          (if (or (= SSLEngineResult$HandshakeStatus/FINISHED handshake-status)
                  (= SSLEngineResult$HandshakeStatus/NOT_HANDSHAKING handshake-status))
            :done
            (do
              (let [out-bytes (handshake-drain-wraps! engine net-out)
                    hdr {:session  session-id
                         :data     true
                         :buf-size buf-size}
                    [hdr-remote byte-chunk] (http/post web-server-endpoint
                                                       hdr
                                                       out-bytes)]
                (when (:eof hdr-remote)
                  (throw (ex-info "Remote sent EOF during handshake" {})))
                (handshake-feed-unwraps! engine net-in app-in byte-chunk)
                (when (.isInboundDone engine)
                  (throw (ex-info "Remote closed TLS during handshake" {})))
                (when (= 0 (alength ^byte/1 byte-chunk))
                  (Thread/sleep 10))
                (recur start-ms)))))))))


(defn close-outbound!
  [^SSLEngine engine ^ByteBuffer net-out]
  (.closeOutbound engine)
  (let [bytebuf-empty (ByteBuffer/allocate 0)]
    (loop []
      (when-not (.isOutboundDone engine)
        (let [res (.wrap engine bytebuf-empty net-out)]
          (check-engine-result! res)
          (when (pos-int? (.bytesProduced res))
            (recur))))))
  (bytebuffer-drain-to-byte-array net-out))


(defn close-tls-session! [^String session-id
                          ^String web-server-endpoint
                          ^SSLEngine engine
                          ^BufferedOutputStream plain-out
                          ^ByteBuffer app-in
                          ^ByteBuffer net-in
                          ^ByteBuffer net-out
                          buf-size]
  (loop [start-ms (System/currentTimeMillis)
         out (close-outbound! engine net-out)]
    (let [[hdr byte-chunk] (http/post
                             web-server-endpoint
                             {:session  session-id
                              :data     true
                              :buf-size buf-size}
                             out)
          engine-state (unwraps! engine net-in app-in byte-chunk)
          spent-ms (- (System/currentTimeMillis) start-ms)
          client-gone? (try
                         (.write plain-out
                                 ^byte/1 (bytebuffer-drain-to-byte-array app-in))
                         (.flush plain-out)
                         false
                         (catch IOException _
                           true))]
      (if (or (:eof hdr)
              (= :closed engine-state)
              (> spent-ms 5000)
              client-gone?)
        {:eof :client}
        (do
          (when (zero? (alength ^byte/1 byte-chunk))
            (Thread/sleep 10))
          (recur start-ms (byte-array 0)))))))


(defn data-loop! [^String session-id
                  ^String web-server-endpoint
                  ^SSLEngine engine
                  ^BufferedInputStream plain-in
                  ^BufferedOutputStream plain-out
                  ^ByteBuffer app-in
                  ^ByteBuffer app-out
                  ^ByteBuffer net-in
                  ^ByteBuffer net-out
                  ^byte/1 buf
                  buf-size]
  (loop [remote-chunk (make-array Byte/TYPE 0)]
    ;; On initial loop: copy whatever might be in net-in to app-in
    ;; Regular loop: copy net-in + remote-chunk to app-in
    (let [engine-state (unwraps! engine net-in app-in remote-chunk)
          ;; Copy app-in (decrypted bytebuffer) to the plaintext outputstream
          client-gone? (try
                         (.write plain-out ^byte/1 (bytebuffer-drain-to-byte-array app-in))
                         (.flush plain-out)
                         false
                         (catch IOException _
                           ;; Ignore exceptions if client is gone
                           true))]
      (cond
        (= :closed engine-state) {:eof :remote-tls}
        client-gone? {:eof :client-disconnected}
        :else
        (let [n (read-some plain-in buf)]
          (if (= n -1)
            ;; We are done reading from plaintext in
            ;; Close the TLS session:
            (close-tls-session! session-id
                                web-server-endpoint
                                engine
                                plain-out
                                app-in
                                net-in
                                net-out
                                buf-size)
            (do
              (wraps! engine app-out net-out (^[byte/1 int] Arrays/copyOf buf (int n)))
              (let [net-out' (bytebuffer-drain-to-byte-array net-out)
                    [hdr byte-chunk] (http/post
                                       web-server-endpoint
                                       {:session  session-id
                                        :data     true
                                        :buf-size buf-size}
                                       net-out')]
                (if (:eof hdr)
                  {:eof :remote}
                  (recur byte-chunk))))))))))


;; Based on https://docs.oracle.com/javase/8/docs/technotes/guides/security//jsse/samples/sslengine/SSLEngineSimpleDemo.java
;; The JDK docs:
;; https://docs.oracle.com/javase/8/docs/api/javax/net/ssl/SSLEngine.html
;; https://docs.oracle.com/javase/8/docs/api/javax/net/ssl/SSLEngineResult.HandshakeStatus.html
;; https://docs.oracle.com/javase/8/docs/api/java/nio/ByteBuffer.html
;; And plenty of help from Claude Code as well
(defn run-conn-proxy! [^SSLContext tls-context web-server-endpoint ^Socket plaintext]
  (let [session-id (str (random-uuid))]
    (try
      (let [^SSLEngine engine (.createSSLEngine tls-context)
            _ (.setUseClientMode engine true)
            _ (.setEnabledProtocols engine (into-array String ["TLSv1.3"]))
            session (.getSession engine)
            buf-size (max (.getApplicationBufferSize session) (.getPacketBufferSize session))
            buffer-max (* 4 buf-size)
            app-in (ByteBuffer/allocate buffer-max)
            app-out (ByteBuffer/allocate buffer-max)
            net-in (ByteBuffer/allocate buffer-max)
            net-out (ByteBuffer/allocate buffer-max)]
        ;; Do the TLS handshake first
        (handshake! session-id buf-size engine web-server-endpoint net-in net-out app-in)
        (.setSoTimeout plaintext 1000)
        (let [plain-in (BufferedInputStream. (.getInputStream plaintext))
              plain-out (BufferedOutputStream. (.getOutputStream plaintext))
              buf (byte-array (int buf-size))]
          (data-loop! session-id
                      web-server-endpoint
                      engine
                      plain-in
                      plain-out
                      app-in
                      app-out
                      net-in
                      net-out
                      buf
                      buf-size)))
      (finally
        (try
          (http/post web-server-endpoint
                     {:session session-id
                      :eof     true})
          (catch Exception _
            nil))
        (tls/close-silently plaintext)))))


(defn start-proxy-server! [client-keys-file web-server-endpoint result-promise drain-on-close?]
  (let [tls-context (tls/ssl-str-context (slurp client-keys-file))
        server (ServerSocket.)
        active-conns (atom 0)]
    (.bind server (InetSocketAddress. "127.0.0.1" 0))
    (future
      (loop []
        (let [sock (.accept server)]
          (future
            (try
              (swap! active-conns inc)
              (let [res (run-conn-proxy! tls-context web-server-endpoint sock)]
                (when result-promise
                  (deliver result-promise res)))
              (catch Exception e
                (println ">>>> Local plaintext TCP->Web proxy crashed:" (ex-message e))
                (.printStackTrace e)
                (when result-promise
                  (deliver result-promise {:error true
                                           :ex    e})))
              (finally
                (swap! active-conns dec)))))
        (recur)))
    (with-meta
      (reify AutoCloseable
        (close [_]
          (tls/close-silently server)
          (when drain-on-close?
            (let [start-ms (System/currentTimeMillis)]
              (loop []
                (let [spent-ms (- (System/currentTimeMillis) start-ms)]
                  (when (> spent-ms 10000)
                    (throw (ex-info "Timeout waiting for proxy connection threads to finish" {})))
                  (when (not= @active-conns 0)
                    (Thread/sleep 10)
                    (recur)))))
            (when (= :timeout (deref result-promise 10000 :timeout))
              (throw (ex-info "Timeout waiting for result-promise" {}))))))
      {:port (.getLocalPort server)})))


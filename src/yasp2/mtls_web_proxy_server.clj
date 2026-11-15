;; The basic idea:
;; A client and server using mTLS over the wire.
;; The "wire" is HTTP posts.
;; Each POST and response contains a header and "raw" TLS bytes.
;; The header contains information such as:
;; * is there more bytes available?
;; * session id
;; * EOF reached?


;; The implementation of the client:
;; The client opens a TCP server that will take plaintext nREPL commands in.
;; A single thread will be used for each accepted connection.

;; Per connection:
;; On init, the connection thread does:
;; Create an interim TCP echo server.
;; Connect a TLS client to the echo server.
;; Closes the echo server, but let echo connection stay open.

;; The connection thread now holds 3 sockets (6 streams):
;; the plaintext
;; the TLS client
;; the TCP echo connection

;; When creating a TLS client, it will (probably) send a bunch of bytes
;; on connect



;; Drain the tcp-echo connection to establish mTLS

;; The connection thread will then enter a read-write loop:
;; drain tcp-echo.in to HTTP POST
;; feed the response to tcp-echo.out


;; Create a TLS client that connets to a TCP echo server.
;;



(ns yasp2.mtls-web-proxy-server)

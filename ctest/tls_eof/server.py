# A TLS server that ends connections the ways real servers do and the
# OpenSSL backend once mishandled (D-86; #99, #100). Loopback only, two
# connections, then it exits.
#
#   noclose   HTTP/1.0, a close-delimited body, then a TCP close with no TLS
#             close_notify. Was "peer closed during TLS" (R: zu_closed).
#   together  a keep-alive body and its close_notify in ONE TCP send, then the
#             connection held open, so the client's single read takes both
#             into its rbio and the socket never becomes readable. The pool's
#             liveness probe could not see it and reused the dead connection.
#   keepalive answers every request on a connection until the client closes,
#             one thread per connection: the third mode's pooled connection
#             stays open while another connection's handshake fails.
#
# SSLObject over memory BIOs, so the bytes on the wire are exactly these.
import socket, ssl, sys, time

mode, port, cert, key = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
ls = socket.socket()
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", port))
ls.listen(4)
print("ready", flush=True)


def pump(raw, inc):
    d = raw.recv(16384)
    if not d:
        raise EOFError
    inc.write(d)


def keepalive(raw):
    s = ctx.wrap_socket(raw, server_side=True)
    try:
        while True:
            req = b""
            while b"\r\n\r\n" not in req:
                d = s.recv(4096)
                if not d:
                    return
                req += d
            s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    except (ssl.SSLError, OSError):
        return          # the failing handshake is this mode's whole point
    finally:
        raw.close()


if mode == "keepalive":
    import threading
    for _ in range(3):
        raw, _ = ls.accept()
        threading.Thread(target=keepalive, args=(raw,), daemon=True).start()
    time.sleep(5)
    sys.exit(0)

for _ in range(2):
    raw, _ = ls.accept()
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_side=True)
    try:
        while True:
            try:
                obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                if out.pending:
                    raw.sendall(out.read())
                pump(raw, inc)
        if out.pending:
            raw.sendall(out.read())
        req = b""
        while b"\r\n\r\n" not in req:
            try:
                req += obj.read(4096)
            except ssl.SSLWantReadError:
                pump(raw, inc)
    except EOFError:
        raw.close()
        continue
    if mode == "noclose":
        obj.write(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n" + b"x" * 5000)
        raw.sendall(out.read())
        raw.close()                     # FIN, and never a close_notify
    else:
        obj.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        try:
            obj.unwrap()
        except ssl.SSLWantReadError:
            pass
        raw.sendall(out.read())         # body record + close_notify, one send
        time.sleep(3)
        raw.close()

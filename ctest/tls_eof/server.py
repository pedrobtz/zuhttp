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
#   resume    keepalive, at most TLS 1.2 (where sessions resume), with a
#             line per connection saying whether it was resumed (#307).
#   bulk      keepalive, answering with a 16 MiB body, for nwrx (#311).
#   optcert   keepalive, asking for a client certificate it does not require
#             (#313): a client with none must still be answered.
#   badmac    a complete response and, in the same TCP send, a record whose
#             MAC is broken, then the connection held open (#314): the
#             response must reach the client before the error does.
#   fork      keepalive with a 200 KB body at /big and a line per accept,
#             request and close, for fork.sh to read (#249).
#
# SSLObject over memory BIOs, so the bytes on the wire are exactly these.
import socket, ssl, sys, time

mode, port, cert, key = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
if mode == "resume":
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
if mode == "optcert":
    ctx.verify_mode = ssl.CERT_OPTIONAL
    ctx.load_verify_locations(cert)   # any CA will do: none is presented
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
    if mode == "resume":
        print("reused=%s" % s.session_reused, flush=True)
    try:
        while True:
            req = b""
            while b"\r\n\r\n" not in req:
                d = s.recv(4096)
                if not d:
                    return
                req += d
            if mode == "bulk":
                n = 16 * 1024 * 1024
                s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % n)
                s.sendall(b"x" * n)
            else:
                s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    except (ssl.SSLError, OSError):
        return          # the failing handshake is this mode's whole point
    finally:
        raw.close()


BIG = bytes(i % 251 for i in range(200000))


def forked(raw, n):
    # A line per event, so fork.sh can read off what each connection
    # received: a child that closed an inherited connection gracefully shows
    # up as "closed by the client" before the parent's last requests on it.
    s = ctx.wrap_socket(raw, server_side=True)
    reqs = 0
    try:
        while True:
            req = b""
            while b"\r\n\r\n" not in req:
                d = s.recv(4096)
                if not d:
                    print("conn %d closed by the client after %d requests" % (n, reqs),
                          flush=True)
                    return
                req += d
            reqs += 1
            path = req.split(b" ", 2)[1]
            print("conn %d request %d %s" % (n, reqs, path.decode()), flush=True)
            if path == b"/big":
                s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(BIG) + BIG)
            else:
                s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    except (ssl.SSLError, OSError) as e:
        print("conn %d ended: %s" % (n, e), flush=True)
    finally:
        raw.close()


if mode == "fork":
    import threading
    for n in range(1, 4):
        raw, _ = ls.accept()
        print("accept %d" % n, flush=True)
        threading.Thread(target=forked, args=(raw, n), daemon=True).start()
    time.sleep(5)
    sys.exit(0)

if mode in ("keepalive", "resume", "bulk", "optcert"):
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
    elif mode == "badmac":
        obj.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        good = out.read()
        obj.write(b"x")
        bad = bytearray(out.read())
        bad[-1] ^= 1                    # the MAC (or AEAD tag) no longer checks
        raw.sendall(good + bytes(bad))
        time.sleep(3)
        raw.close()
    else:
        obj.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        try:
            obj.unwrap()
        except ssl.SSLWantReadError:
            pass
        raw.sendall(out.read())         # body record + close_notify, one send
        time.sleep(3)
        raw.close()

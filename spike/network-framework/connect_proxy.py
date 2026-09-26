"""Minimal HTTP CONNECT proxy for nw_probe: logs each CONNECT and splices bytes.

Test-only. Listens on 127.0.0.1:PORT (argv[1]); one thread per direction.
The log is what makes the probe's proxy row non-vacuous: a PASS with no
CONNECT line here would mean Network.framework went direct.
"""
import socket, sys, threading

def pipe(a, b):
    try:
        while (d := a.recv(65536)):
            b.sendall(d)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try: s.shutdown(socket.SHUT_RDWR)
            except OSError: pass

def handle(c):
    head = b""
    while b"\r\n\r\n" not in head:
        d = c.recv(4096)
        if not d: return c.close()
        head += d
    line = head.split(b"\r\n", 1)[0].decode()
    print("proxy saw:", line, flush=True)
    method, target, _ = line.split(" ", 2)
    if method != "CONNECT":
        c.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n"); return c.close()
    host, port = target.rsplit(":", 1)
    u = socket.create_connection((host, int(port)), timeout=10)
    c.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    threading.Thread(target=pipe, args=(c, u), daemon=True).start()
    pipe(u, c)

srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1]))); srv.listen(16)
print("listening", flush=True)
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()

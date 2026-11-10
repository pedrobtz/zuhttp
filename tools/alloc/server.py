"""Loopback HTTP/1.1 server for tools/alloc/exercise.R (#237).

Started by the R driver with the allocation-failure interposer removed from
its environment, so a failed allocation lands in the client, never here.
Serves on an ephemeral port and writes "<port> <pid>" to the file named by
argv[1] once it is listening. The driver kills it when done; it also exits
on its own after 120 seconds, so a driver that dies cannot leave it behind.

  GET  /len      Content-Length body, 50,000 bytes
  GET  /chunked  the same bytes, chunked, gzip-encoded
  POST /echo     returns the request body
"""
import gzip
import http.server
import os
import socketserver
import sys
import threading

BODY = bytes((i * 7 + 3) % 251 for i in range(50000))
GZ = gzip.compress(BODY)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/len":
            self.send_response(200)
            self.send_header("Content-Length", str(len(BODY)))
            self.end_headers()
            self.wfile.write(BODY)
        elif self.path == "/chunked":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Content-Encoding", "gzip")
            self.end_headers()
            for i in range(0, len(GZ), 4096):
                piece = GZ[i:i + 4096]
                self.wfile.write(b"%x\r\n%s\r\n" % (len(piece), piece))
            self.wfile.write(b"0\r\n\r\n")
        else:
            self.send_error(404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        data = self.rfile.read(n)
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


srv = Server(("127.0.0.1", 0), Handler)
tmp = sys.argv[1] + ".tmp"
with open(tmp, "w") as f:
    f.write("%d %d\n" % (srv.server_address[1], os.getpid()))
os.replace(tmp, sys.argv[1])
threading.Timer(120, lambda: os._exit(0)).start()
srv.serve_forever()

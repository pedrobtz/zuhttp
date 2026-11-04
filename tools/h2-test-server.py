"""A local HTTP/2 echo server for zuhttp's live HTTP/2 tests (design §65.8).

    pip install hypercorn
    python3 tools/h2-test-server.py PORT_H2C PORT_TLS CERT KEY

Serves the same app twice: cleartext on PORT_H2C, where a client speaking
prior-knowledge h2c is answered over HTTP/2 (hypercorn switches on the
connection preface), and TLS on PORT_TLS, where ALPN offers h2 then
http/1.1. Its HTTP/2 is the `h2` package's, not nghttp2's, so the client's
frames are checked by an implementation independent of the one zuhttp
vendors.

    GET  /get    JSON: method, path, the HTTP version the server saw, and
                 the request headers
    POST /post   the request body, byte for byte

tests/testthat/test-http2.R reads ZU_H2_TEST_SERVER (the h2c base URL),
ZU_H2_TEST_TLS (the TLS base URL) and ZU_H2_TEST_CA (the certificate to
trust); .github/workflows/network.yaml starts this server and sets them.
"""
import asyncio
import json
import sys

from hypercorn.asyncio import serve
from hypercorn.config import Config


async def app(scope, receive, send):
    if scope["type"] != "http":
        return
    body = b""
    while True:
        msg = await receive()
        body += msg.get("body", b"")
        if not msg.get("more_body"):
            break
    if scope["path"] == "/post":
        out, ctype = body, b"application/octet-stream"
    else:
        out = json.dumps({
            "method": scope["method"],
            "path": scope["path"],
            "query": scope["query_string"].decode(),
            "http_version": scope["http_version"],
            "headers": {k.decode(): v.decode() for k, v in scope["headers"]},
        }).encode()
        ctype = b"application/json"
    await send({"type": "http.response.start", "status": 200,
                "headers": [(b"content-type", ctype),
                            (b"content-length", str(len(out)).encode())]})
    await send({"type": "http.response.body", "body": out})


async def main(port_h2c, port_tls, cert, key):
    plain = Config()
    plain.bind = ["127.0.0.1:%d" % port_h2c]
    tls = Config()
    tls.bind = ["127.0.0.1:%d" % port_tls]
    tls.certfile, tls.keyfile = cert, key
    tls.alpn_protocols = ["h2", "http/1.1"]
    await asyncio.gather(serve(app, plain), serve(app, tls))


if __name__ == "__main__":
    asyncio.run(main(int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]))

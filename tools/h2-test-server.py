"""A local HTTP/2 echo server for zuhttp's live HTTP/2 tests (design §65.8).

    pip install hypercorn
    python3 tools/h2-test-server.py PORT_H2C PORT_TLS CERT KEY

Serves the same app twice: cleartext on PORT_H2C, where a client speaking
prior-knowledge h2c is answered over HTTP/2 (hypercorn switches on the
connection preface), and TLS on PORT_TLS, where ALPN offers h2 then
http/1.1. Its HTTP/2 is the `h2` package's, not nghttp2's, so the client's
frames are checked by an implementation independent of the one zuhttp
vendors.

    GET  /get       JSON: method, path, the HTTP version the server saw, and
                    the request headers
    POST /post      the request body, byte for byte
    GET  /bytes?n=  n bytes of a repeating pattern, sent in 64 KiB pieces;
                    the server counts what it has handed to the protocol
    GET  /sent      that count, as JSON; /sent?reset=1 zeroes it
    GET  /slow      a few bytes, then nothing for 30 seconds
    GET  /trailers  "x", then the trailer field grpc-status: 0 (HTTP/2)

tests/testthat/test-http2.R reads ZU_H2_TEST_SERVER (the h2c base URL),
ZU_H2_TEST_TLS (the TLS base URL) and ZU_H2_TEST_CA (the certificate to
trust); .github/workflows/network.yaml starts this server and sets them.
"""
import asyncio
import json
import sys

from hypercorn.asyncio import serve
from hypercorn.config import Config


SENT = 0
PATTERN = bytes(range(256)) * 256          # 64 KiB


async def stream_bytes(send, n):
    global SENT
    await send({"type": "http.response.start", "status": 200,
                "headers": [(b"content-type", b"application/octet-stream")]})
    while n > 0:
        piece = PATTERN[:min(n, len(PATTERN))]
        # Over HTTP/2 this await returns only once flow control lets the
        # piece go, so SENT is how far the client has let the server run.
        await send({"type": "http.response.body", "body": piece, "more_body": True})
        SENT += len(piece)
        n -= len(piece)
    await send({"type": "http.response.body", "body": b""})


async def app(scope, receive, send):
    global SENT
    if scope["type"] != "http":
        return
    query = dict(p.split("=", 1) for p in scope["query_string"].decode().split("&") if "=" in p)
    if scope["path"] == "/bytes":
        await stream_bytes(send, int(query.get("n", "0")))
        return
    if scope["path"] == "/sent":
        out = json.dumps({"sent": SENT}).encode()
        if query.get("reset") == "1":
            SENT = 0
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": out})
        return
    if scope["path"] == "/slow":
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"slow", "more_body": True})
        await asyncio.sleep(30)
        await send({"type": "http.response.body", "body": b""})
        return
    if scope["path"] == "/trailers":
        await send({"type": "http.response.start", "status": 200, "trailers": True,
                    "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": b"x"})
        await send({"type": "http.response.trailers", "more_trailers": False,
                    "headers": [(b"grpc-status", b"0"), (b"grpc-message", b"ok")]})
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

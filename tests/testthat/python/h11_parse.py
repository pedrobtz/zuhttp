# Reference HTTP/1.1 response parser for test-h11.R (#240): h11, a
# sans-I/O implementation of RFC 9112 (https://github.com/python-hyper/h11).
#
# stdin: a JSON array of {"method": ..., "hex": ...}, each the bytes one
# server connection sent in answer to that method, after which it closed.
# stdout: a JSON array with, for each, what an h11 client made of them:
#   {"refused": true, "why": ...}  when h11 raised a protocol error, or
#   {"refused": false, "status": n, "headers": [[name, value], ...],
#    "trailers": [[name, value], ...], "body": hex}
# Header names come back lowercased (h11 normalises them); interim 1xx
# responses are skipped, as a client does.
import json
import sys

import h11


def parse(method, data):
    conn = h11.Connection(our_role=h11.CLIENT)
    conn.send(h11.Request(method=method, target="/", headers=[("Host", "x")]))
    conn.send(h11.EndOfMessage())
    out = {"refused": False, "status": None, "headers": [], "trailers": [],
           "body": ""}
    body = bytearray()
    try:
        conn.receive_data(data)
        conn.receive_data(b"")  # the server closed the connection
        while True:
            ev = conn.next_event()
            if isinstance(ev, h11.InformationalResponse):
                continue
            if isinstance(ev, h11.Response):
                out["status"] = ev.status_code
                out["headers"] = [[n.decode("latin-1"), v.decode("latin-1")]
                                  for n, v in ev.headers]
            elif isinstance(ev, h11.Data):
                body += ev.data
            elif isinstance(ev, h11.EndOfMessage):
                out["trailers"] = [[n.decode("latin-1"), v.decode("latin-1")]
                                   for n, v in ev.headers]
                break
            elif ev is h11.NEED_DATA:
                # Only after EOF: the message cannot be completed.
                return {"refused": True, "why": "incomplete message"}
            elif isinstance(ev, h11.ConnectionClosed):
                return {"refused": True, "why": "closed before a response"}
    except h11.RemoteProtocolError as e:
        return {"refused": True, "why": str(e)}
    out["body"] = body.hex()
    return out


cases = json.loads(sys.stdin.buffer.read().decode("utf-8"))
sys.stdout.write(json.dumps([parse(c["method"], bytes.fromhex(c["hex"]))
                             for c in cases]))

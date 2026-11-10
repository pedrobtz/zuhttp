"""Curated fuzz seeds for zuhttp (design §43, §50.3).

Run via fuzz/seed-corpus.sh. Deterministic and byte-identical on every
platform, which the shell version was not — see that script's comment.
"""
import os
import shutil
import zlib

TARGETS = ("response", "chunked", "headers", "uri", "redirect", "inflate",
           "proxy", "redact", "body", "h2", "pull", "pool")

README = """\
Curated fuzz seeds (design §43, §50.3).

Regenerate with fuzz/seed-corpus.sh (or `make -C fuzz reseed`). Do not add
files here by hand -- add them to seed-corpus.py, so the corpus stays
reproducible and every seed keeps its explanation.

Every file is a real protocol sample, a specific attack the design names
(CL/TE conflict, duplicate Content-Length, obs-fold, CRLF injection, an
over-large port, a decompression bomb, an httpoxy-shaped environment), or a
`regress-*` input for a bug that was actually found.

Soak-grown corpora are deliberately NOT committed. Running libFuzzer locally
writes new coverage units into these directories, which is how it should work
-- but a 45 s run per target grows this to ~29,000 files and tens of MB, and
even `-merge=1` minimisation leaves ~12,000 unexplainable blobs. Run
`make -C fuzz reseed` before committing. CI keeps its grown corpora as
artifacts from the `soak` job in .github/workflows/fuzz.yaml.
"""


def w(path, data):
    if isinstance(data, str):
        data = data.encode()
    with open(os.path.join("corpus", path), "wb") as f:
        f.write(data)


def main():
    # Only the directories this script writes. corpus/engine is curated by
    # hand and committed as-is; removing the whole corpus/ here deleted it on
    # every reseed.
    for t in TARGETS:
        shutil.rmtree(os.path.join("corpus", t), ignore_errors=True)
        os.makedirs(os.path.join("corpus", t))

    # --- response: the §18.1 framing / smuggling alphabet -------------------
    w("response/ok", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
    w("response/no_headers", "HTTP/1.1 204 No Content\r\n\r\n")
    w("response/chunked",
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
    w("response/cl_te_conflict",
      "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n")
    w("response/dup_cl",
      "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n")
    w("response/obs_fold", "HTTP/1.1 200 OK\r\nX-A: one\r\n  two\r\n\r\n")
    w("response/cl_negative", "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n")
    w("response/cl_overflow",
      "HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999\r\n\r\n")
    w("response/te_not_chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n")
    w("response/informational",
      "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    w("response/space_before_colon", "HTTP/1.1 200 OK\r\nX-A : v\r\n\r\n")
    w("response/nul_in_value", b"HTTP/1.1 200 OK\r\nX-A: a\x00b\r\n\r\n")
    w("response/bare_lf", "HTTP/1.1 200 OK\nContent-Length: 0\n\n")
    w("response/huge_status", "HTTP/1.1 999999 X\r\n\r\n")
    w("response/partial", "HTTP/1.1 200 OK\r\nContent-Len")

    # --- chunked: the first byte picks the fragmentation point --------------
    w("chunked/simple", b"\x03" + b"5\r\nhello\r\n0\r\n\r\n")
    w("chunked/trailer", b"\x00" + b"5\r\nhello\r\n0\r\nX-T: v\r\n\r\n")
    w("chunked/ext", b"\x00" + b"5;name=value\r\nhello\r\n0\r\n\r\n")
    w("chunked/bad_size", b"\x00" + b"zz\r\nhello\r\n0\r\n\r\n")
    w("chunked/size_overflow", b"\x00" + b"FFFFFFFFFFFFFFFFFF\r\nx\r\n")
    w("chunked/negative", b"\x00" + b"-5\r\nhello\r\n")
    w("chunked/empty_final", b"\x00" + b"0\r\n\r\n")
    w("chunked/no_terminator", b"\x00" + b"5\r\nhello")

    # --- headers: NAME \0 VALUE ---------------------------------------------
    w("headers/simple", b"Content-Type\x00application/json")
    w("headers/crlf_injection", b"X-Evil\x00v\r\nInjected: yes")
    w("headers/lf_injection", b"X-Evil\x00v\nInjected: yes")
    w("headers/nul_value", b"X-A\x00a\x00b")
    w("headers/empty_name", b"\x00value")
    w("headers/empty_value", b"X-Empty\x00")
    w("headers/bad_token", b"X Space\x00v")
    w("headers/separator_in_name", b"X(paren)\x00v")
    w("headers/high_bytes", b"X-A\x00\xff\xfe\x80")
    w("headers/tab_value", b"X-A\x00\tvalue\t")
    w("headers/long_name", b"A" * 2000 + b"\x00v")

    # --- uri -----------------------------------------------------------------
    uris = [
        "https://example.com/a/b?q=1#f", "http://[::1]:8080/x",
        "http://192.168.0.1/", "https://user:pw@evil.com/",
        "https://good.com@evil.com/", "http://h:65536/",
        "https://example.com../", "https://example.com./", "http://[",
        "http://[]", "http://[:::::::::::]/", "https://////////a",
        "http://h/%2e%2e/%2e%2e/", "ftp://example.com/", "mailto:a@b.com",
        "//host/path", "/just/path", "http://h:0443/",
        "https://[fe80::1%25eth0]/", "http://h/?", "://", "h:", "",
    ]
    for i, u in enumerate(uris, 1):
        w("uri/seed%02d" % i, u)
    # regressions: inputs that once crashed something
    w("uri/regress-userinfo-in-scheme", "http://h@oocd.com:/")
    w("uri/regress-ipvfuture", "http://[v7.xyz]/")

    # --- redirect: Location values against a credentialed base --------------
    locs = ["g", "./g", "../g", "../../../g", "/g", "?y", "#s",
            "//other.example/z", "https://other.example:8443/z",
            "http://h:65536/", "ftp://x/y", "https://user:pw@other.example/",
            "", "g?y#s", "../../.."]
    for i, l in enumerate(locs, 1):
        w("redirect/seed%02d" % i, l)
    # #230: the same input is also a header set for the §19.2 strip.
    w("redirect/headers-credentials",
      "Authorization: Bearer t\nCookie: a=b\nX-Keep: 1\nproxy-authorization: Basic x\n"
      "Accept: */*\nAUTHORIZATION: again")
    w("redirect/headers-none", "Accept: */*\nX-Trace: 1")

    # --- proxy: first byte selects no_proxy / URL / resolution / CONNECT ----
    w("proxy/np_simple", b"\x00example.com\x00api.example.com")
    w("proxy/np_star", b"\x00*\x00anything.com")
    w("proxy/np_port", b"\x00example.com:8080\x00example.com")
    w("proxy/np_ipv6", b"\x00[::1]:8080\x00::1")
    w("proxy/np_ip", b"\x001.2.3.4\x0010.1.2.3.4")
    w("proxy/np_list", b"\x00a.com, b.com ,c.com\x00b.com")
    w("proxy/np_dot", b"\x00.example.com\x00example.com")
    w("proxy/url_plain", b"\x01http://px.example:3128")
    w("proxy/url_creds", b"\x01http://user:pass@px.example:3128")
    w("proxy/url_pct", b"\x01http://us%40er:p%40ss@px:3128")
    w("proxy/url_bad_pct", b"\x01http://u:p%zz@px:3128")
    w("proxy/url_bare", b"\x01px.example:3128")
    w("proxy/url_socks", b"\x01socks5://px:1080")
    w("proxy/res_env", b"\x02http://px.example:3128\x00internal.example")
    w("proxy/res_empty", b"\x02\x00")
    w("proxy/regress-ipvfuture",
      b"\x01http://[veee.0;;;;***UU;;;;;;;;;;;;;:]//;m=")
    # #230: case 3 builds a CONNECT for the target URL before the NUL through
    # a proxy with credentials, then parses the reply after it.
    w("proxy/connect-200", b"\x03https://target.example:8443/x\x00"
      b"HTTP/1.1 200 Connection established\r\n\r\n")
    w("proxy/connect-407", b"\x03https://target.example/\x00HTTP/1.1 407 Proxy Auth\r\n"
      b"Proxy-Authenticate: Basic realm=x\r\nContent-Length: 0\r\n\r\n")
    w("proxy/connect-403", b"\x03https://[::1]:443/\x00HTTP/1.1 403 Forbidden\r\n\r\n")
    w("proxy/connect-garbage", b"\x03https://t.example/\x00HTTP/1.1 2000 OK\r\n\r\n")
    w("proxy/connect-cut", b"\x03https://t.example/\x00HTTP/1.1 200 OK\r\nX: y")
    # A CONNECT request that exactly fills its buffer: the harness searched it
    # with strstr(), which ran off the end (found by the libFuzzer smoke).
    w("proxy/regress-230-full-buffer", b'\x03https://tPro\x00HTTP/1.1 414 tps:// .1 407 Proxy Auth\r\nProx!y-TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT\xa6TTTTTTTTTTTTTTTTTTTTTTTTTT\x00\x00TTTTTTTTTTTAuhttSSSSSSSSSSSSSSSSS_______________________SSSSSSSSSSSWSSSSSSSSSSSS.icate`: Ba]sic r0\r\n\r\n')

    # --- redact: URLs and form bodies, mostly credential-bearing ------------
    w("redact/userinfo", "https://user:pw@api.example.com/v1/x")
    w("redact/at_in_user", "https://us@er:p@ss@api.example.com/x")
    w("redact/param", "https://h/v1?page=2&api_key=SECRET&sort=asc")
    w("redact/both", "https://u:p@h:8443/x?sig=S&ok=1")
    w("redact/fragment", "https://h/x?access_token=S#frag")
    w("redact/unparseable", "https://user:pw@h:99999999/][?api_key=S")
    w("redact/form", "user=alice&api_key=SECRET&scope=read")
    w("redact/semicolons", "https://h/?a=1;sig=X;b=2")
    w("redact/bare_at", "@@@")
    w("redact/no_scheme", "/just/a/path?api_key=S")
    # regression: a scheme scanned for anywhere let ordinary text be mangled
    w("redact/regress-not-a-url", "not a url at all :// with u:p@h")

    # --- inflate: first byte selects gzip / deflate / encoding-name ---------
    payload = b"hello world " * 40
    co = zlib.compressobj(9, zlib.DEFLATED, 16 + 15)
    w("inflate/gzip_real", b"\x00" + co.compress(payload) + co.flush())
    w("inflate/deflate_zlib", b"\x01" + zlib.compress(payload))
    co2 = zlib.compressobj(9, zlib.DEFLATED, -15)
    w("inflate/deflate_raw", b"\x01" + co2.compress(payload) + co2.flush())
    # the bomb: 64 MB of zeros, which must stop exactly at the cap (§21.4)
    co3 = zlib.compressobj(9, zlib.DEFLATED, 16 + 15)
    w("inflate/bomb", b"\x00" + co3.compress(b"\x00" * (64 << 20)) + co3.flush())
    w("inflate/truncated", b"\x00" + zlib.compress(payload)[:20])
    w("inflate/garbage", b"\x00" + b"\xde\xad\xbe\xef" * 8)
    for name in ("gzip", "deflate", "br", "identity", "GZIP", "gzip, deflate", ""):
        fn = "inflate/enc_" + (name or "empty").replace(", ", "_")
        w(fn, b"\x02" + name.encode())

    # --- body (§27, §21, §40) ------------------------------------------
    #
    # The first byte selects the shape: bits 0-1 the framing, bits 2-3 the
    # Content-Encoding, bit 4 whether decoding is off. One corpus therefore
    # covers every combination the engine can build.
    #
    #   framing:  0 LENGTH=size  1 LENGTH=oversized  2 CHUNKED  3 UNTIL_CLOSE
    #   encoding: 0 gzip  1 deflate  2 br (unsupported)  3 identity
    IDENT_CLOSE = 0x0F      # identity, read to close
    IDENT_CHUNK = 0x0E      # identity, chunked
    DEFLATE_LEN = 0x04      # deflate, LENGTH = size
    DEFLATE_CLOSE = 0x07    # deflate, read to close

    body_payload = b"hello " * 200
    w("body/identity-small", bytes([IDENT_CLOSE]) + b"hello world")
    w("body/empty", bytes([IDENT_CLOSE]))
    # The §40 cap is 64 KB in the target: one seed under it, one exactly on
    # it, one past it. The last is the regression for the bug this target
    # found on its first run — the sink was handed a whole read chunk past
    # the cap before the check fired.
    w("body/identity-under-cap", bytes([IDENT_CLOSE]) + b"B" * 60000)
    w("body/regress-identity-over-cap", bytes([IDENT_CLOSE]) + b"C" * 131072)
    w("body/deflate-small", bytes([DEFLATE_LEN]) + zlib.compress(body_payload))
    w("body/deflate-truncated", bytes([DEFLATE_LEN]) + zlib.compress(body_payload)[:20])
    # A bomb through the streaming path: the cap must hold during inflation,
    # not after it (§21.4), and now also before the sink sees a byte (§40).
    w("body/deflate-bomb", bytes([DEFLATE_CLOSE]) + zlib.compress(b"\x00" * (4 << 20)))
    w("body/brotli-unsupported", bytes([0x08]) + b"anything")
    w("body/chunked-ok", bytes([IDENT_CHUNK]) + b"3\r\nabc\r\n0\r\n\r\n")
    w("body/chunked-bad-size", bytes([IDENT_CHUNK]) + b"zzzz\r\n")
    w("body/chunked-huge-size", bytes([IDENT_CHUNK]) + b"ffffffffffffffff\r\nx")
    w("body/chunked-trailer", bytes([IDENT_CHUNK]) + b"3\r\nabc\r\n0\r\nX-T: 1\r\n\r\n")
    w("body/chunked-truncated", bytes([IDENT_CHUNK]) + b"5\r\nab")
    # #227: the read-size and framing differentials. Bit 5 is a cap of 8
    # bytes. #210 handed the sink a malformed chunk's raw bytes before the
    # parse error; #212 refused under chunked framing a gzip body that fits
    # max_body decoded (5 bytes) but not compressed (25 bytes).
    w("body/regress-210-bad-chunk", bytes([IDENT_CHUNK]) + b"X\r\nATTACK\r\n0\r\n\r\n")
    w("body/regress-210-good-then-bad",
      bytes([IDENT_CHUNK]) + b"3\r\nabc\r\nX\r\nATTACK\r\n0\r\n\r\n")
    gz = zlib.compressobj(9, zlib.DEFLATED, 31)
    w("body/regress-212-gzip-small-cap", bytes([0x20]) + gz.compress(b"hello") + gz.flush())
    # Two faults, a bad gzip stream in bad chunk framing: read whole, the
    # framing fails first; byte by byte, the inflater does. Both are right,
    # and an oracle that compared the error codes aborted on it.
    w("body/regress-227-two-faults",
      bytes([0x42]) + b"B\r\nabc\r\n0\xfd\nX-" + b"\x90" * 6 + b"\xff" + b"\x90" * 5 +
      b"1\r\n\r\n")


    # --- h2: server frames for target 12 (§65.8) -----------------------------
    # Hand-built frames (RFC 9113 §4.1) and HPACK (RFC 7541): 0x88 is the
    # static-table ":status: 200"; a literal is 0x00, name, value, no Huffman.
    def fr(ftype, flags, sid, payload=b""):
        return (len(payload).to_bytes(3, "big") + bytes([ftype, flags]) +
                sid.to_bytes(4, "big") + payload)

    def lit(name, value):
        return bytes([0, len(name)]) + name + bytes([len(value)]) + value

    DATA, HEADERS, RST, SETTINGS, PING, GOAWAY, WINUP, CONT = 0, 1, 3, 4, 6, 7, 8, 9
    END_STREAM, END_HEADERS, ACK = 0x1, 0x4, 0x1
    pre = fr(SETTINGS, 0, 0) + fr(SETTINGS, ACK, 0)
    ok1 = fr(HEADERS, END_HEADERS, 1, b"\x88") + fr(DATA, END_STREAM, 1, b"hello")
    ok3 = fr(HEADERS, END_HEADERS, 3, b"\x88") + fr(DATA, END_STREAM, 3, b"again")
    opt = bytes([0x02])               # whole reads, pooled
    w("h2/ok", opt + pre + ok1 + ok3)
    w("h2/ok-1byte-reads", bytes([0x00]) + pre + ok1 + ok3)
    w("h2/ok-probe-reads", bytes([0x42]) + pre + ok1 + ok3)
    w("h2/headers-only", opt + pre + fr(HEADERS, END_HEADERS | END_STREAM, 1,
                                         b"\x88" + lit(b"x-a", b"1")))
    w("h2/informational-103", opt + pre +
      fr(HEADERS, END_HEADERS, 1, b"\x08\x03103") + ok1)
    w("h2/trailers", opt + pre + fr(HEADERS, END_HEADERS, 1, b"\x88") +
      fr(DATA, 0, 1, b"\x00\x00\x00\x00\x02hi") +
      fr(HEADERS, END_HEADERS | END_STREAM, 1, lit(b"grpc-status", b"0")))
    w("h2/continuation", opt + pre + fr(HEADERS, 0, 1, b"\x88") +
      fr(CONT, END_HEADERS, 1, lit(b"x-b", b"2")) + fr(DATA, END_STREAM, 1, b"c"))
    w("h2/rst-stream", opt + pre + fr(RST, 0, 1, (2).to_bytes(4, "big")))
    w("h2/goaway", opt + pre + fr(GOAWAY, 0, 0, (0).to_bytes(4, "big") +
                                    (1).to_bytes(4, "big")))
    w("h2/goaway-after-response", opt + pre + ok1 +
      fr(GOAWAY, 0, 0, (1).to_bytes(4, "big") + (0).to_bytes(4, "big")))
    w("h2/ping-and-window", opt + pre + fr(PING, 0, 0, b"\x00" * 8) +
      fr(WINUP, 0, 0, (1000).to_bytes(4, "big")) + ok1 + ok3)
    w("h2/content-length-mismatch", opt + pre +
      fr(HEADERS, END_HEADERS, 1, b"\x88" + lit(b"content-length", b"10")) +
      fr(DATA, END_STREAM, 1, b"short"))
    w("h2/data-after-end-stream", opt + pre + ok1 + fr(DATA, 0, 1, b"late"))
    w("h2/not-http2", opt + b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
    w("h2/no-settings-first", opt + ok1)
    w("h2/huge-frame-length", opt + pre + b"\xff\xff\xff\x00\x00\x00\x00\x00\x01")
    w("h2/big-header", opt + pre + fr(HEADERS, END_HEADERS | END_STREAM, 1,
                                       b"\x88" + b"\x00\x03x-z\x7f\x81\x7f" + b"z" * 255))
    w("h2/redirect", opt + pre + fr(HEADERS, END_HEADERS | END_STREAM, 1,
      b"\x08\x03302" + lit(b"location", b"http://origin.test/next")) + ok3 +
      b"\x00ZU\x00" + pre + ok1)
    w("h2/pulled-and-aborted", bytes([0x82]) + pre + ok1 +
      fr(HEADERS, END_HEADERS, 3, b"\x88") + fr(DATA, 0, 3, b"y" * 2000) +
      fr(DATA, END_STREAM, 3, b"z" * 2000))
    w("h2/pulled-trailers", bytes([0x82]) + pre + fr(HEADERS, END_HEADERS, 1, b"\x88") +
      fr(DATA, 0, 1, b"a" * 1000) +
      fr(HEADERS, END_HEADERS | END_STREAM, 1, lit(b"grpc-status", b"0")))
    w("h2/two-connections", bytes([0x12]) + pre + ok1 + b"\x00ZU\x00" + pre + ok1)
    # §65.7 (review #159): option bits 0x4|0x8 send a streamed request body;
    # with 0x1 the body function fails on its second piece. 0x80 pulls the
    # response, so a source the pulled body inherits is released by it.
    w("h2/streamed-body", bytes([0x0E]) + pre + ok1 + ok3)
    w("h2/streamed-body-fails", bytes([0x0D]) + pre + ok1 + b"\x00ZU\x00" + pre + ok1)
    w("h2/streamed-body-pulled", bytes([0x8E]) + pre + ok1 + ok3)

    # --- pull (#229): the pulled body's API against a model ----------------
    # byte 0 framing (0 length, 1 chunked, 2 close, 3 length read a byte at
    # a time; bit 2 7-byte reads), byte 1 the payload length, the payload,
    # then one byte per operation: low bits 0 read, 1 peek+consume, 2 abort,
    # 3 done?; the rest is the size less one.
    def op(kind, k=1):
        return bytes([((k - 1) << 2) | kind])
    hello = b"hello"
    # #213: the whole body arrives in the first read, so the wire has ended;
    # read 1 byte, abort, read: the rest must be cancelled, not served.
    w("pull/regress-213-abort-after-end", bytes([0, 5]) + hello + op(0, 1) + op(2) + op(0, 4))
    w("pull/read-all-length", bytes([0, 5]) + hello + op(0, 64) + op(0, 64) + op(3))
    w("pull/read-all-chunked", bytes([1, 12]) + b"hello, world" + op(0, 3) * 6 + op(3))
    w("pull/read-all-close", bytes([2, 5]) + hello + op(0, 2) * 4 + op(3))
    w("pull/peek-consume", bytes([4, 12]) + b"hello, world" + op(1, 4) * 6 + op(0, 64) + op(3))
    w("pull/abort-mid-bytewise", bytes([3, 12]) + b"hello, world" + op(0, 2) + op(2) +
      op(1, 3) + op(0, 3) + op(3))
    w("pull/empty", bytes([0, 0]) + op(0, 8) + op(3) + op(2) + op(0, 8))
    # #248: byte 0 bit 3 pools the connection, bit 4 is HTTP/2 (bits 0-1 then
    # the DATA frame size: 1, 7, 64, 1000; bit 2 16-byte transport reads, so
    # the stream is still on the wire when it is cut), bits 5-6 a failure (1
    # the connection ends, 2 a reset, 3 a silent peer: a timeout); with a
    # failure, the byte after the length is where it cuts. After the body a
    # second request on the pool must get the whole payload.
    POOL, H2, EOF_, RESET, SILENT = 0x08, 0x10, 0x20, 0x40, 0x60

    def pl(n):
        return bytes((i * 7 + 3) % 256 for i in range(n))

    def pull(opts, n, ops, cut=None):
        return bytes([opts, n]) + (bytes([cut]) if cut is not None else b"") + pl(n) + ops
    w("pull/h2-read-all", pull(H2 | 1, 12, op(0, 3) * 6 + op(3)))
    w("pull/h2-pooled-read-all", pull(H2 | POOL | 1, 40, op(0, 9) * 6 + op(3)))
    w("pull/h2-pooled-peek", pull(H2 | POOL | 0, 30, op(1, 4) * 8 + op(0, 64) + op(3)))
    # A clean cancel keeps the connection, and the next request reuses it.
    w("pull/regress-h2-abort-pools", pull(H2 | POOL | 4 | 1, 200, op(0, 10) + op(2) +
      op(0, 4) + op(3)))
    w("pull/h2-abort-after-end", pull(H2 | POOL | 2, 200, op(0, 10) + op(2) + op(0, 4) + op(3)))
    w("pull/regress-h2-eof-mid-body", pull(H2 | POOL | EOF_ | 4 | 1, 100, op(0, 64) * 8 + op(3),
      40))
    w("pull/regress-h2-reset-mid-body", pull(H2 | POOL | RESET | 0, 60, op(0, 16) * 6 + op(3), 10))
    w("pull/regress-h2-timeout", pull(H2 | POOL | SILENT | 4 | 1, 80, op(0, 20) * 8 + op(3), 30))
    w("pull/regress-h2-abort-before-reset", pull(H2 | POOL | RESET | 4 | 1, 90,
      op(0, 5) + op(2) + op(0, 5) + op(3), 50))
    w("pull/regress-h1-pooled-end", pull(POOL | 0, 12, op(0, 5) * 4 + op(3)))
    w("pull/regress-h1-pooled-chunked", pull(POOL | 1, 23, op(0, 4) * 8 + op(3)))
    w("pull/regress-h1-pooled-abort-bytewise", pull(POOL | 3, 50, op(0, 1) + op(2) + op(0, 3) +
      op(3)))
    w("pull/regress-h1-eof-mid-body", pull(POOL | EOF_ | 0, 50, op(0, 8) * 8 + op(3), 20))
    w("pull/regress-h1-reset-chunked", pull(POOL | RESET | 1, 41, op(0, 6) * 9 + op(3), 13))
    w("pull/regress-h1-timeout", pull(POOL | SILENT | 4, 60, op(1, 9) * 4 + op(0, 30) * 6 +
      op(3), 25))
    w("pull/regress-h1-close-eof-is-end", pull(POOL | EOF_ | 2, 30, op(0, 7) * 6 + op(3), 12))
    w("pull/regress-h1-timeout-unpooled", pull(SILENT | 0, 20, op(0, 3) * 4 + op(2) + op(0, 1),
      5))

    # --- pool (#247): the connection pool against its model ----------------
    # byte 0: max_idle (bits 0-2) and max_per_host (bits 3-4, 0 = no limit);
    # byte 1: idle_timeout in 100 ms units (0 = never); then one byte per
    # operation, (arg << 3) | op: 0 acquire key arg % 6 (host arg % 3), 1
    # release clean, 2 release after a partial read (arg bit 0: unread bytes
    # waiting, else body_incomplete), 3 release with error reason arg % 6, 4
    # the server closes idle connection arg, 5 advance arg * 25 ms, 6 fork,
    # 7 arg % 4: clear, check_fork, nothing, free and make a new pool.
    def po(kind, a=0):
        return bytes([(a << 3) | kind])
    ACQ, REL, PART, ERR, SRVCLOSE, CLOCK, FORK, MISC = range(8)

    def cfg(max_idle, per_host, timeout_units):
        return bytes([max_idle | (per_host << 3), timeout_units])
    w("pool/reuse-clean", cfg(4, 2, 3) + po(ACQ, 0) + po(REL) + po(ACQ, 0) + po(REL) +
      po(ACQ, 1) + po(REL) + po(ACQ, 0) + po(ACQ, 1))
    # One mechanism each. max_per_host 1: two connections for a.test under
    # two keys (TLS 1.2 and 1.3 minimums), so the cap is by host, not key.
    w("pool/regress-per-host-cap", cfg(7, 1, 0) + po(ACQ, 0) + po(ACQ, 0) + po(ACQ, 3) +
      po(REL) + po(REL) + po(REL) + po(ACQ, 0) + po(ACQ, 3))
    w("pool/regress-max-idle", cfg(2, 0, 0) + po(ACQ, 0) + po(ACQ, 1) + po(ACQ, 2) +
      po(REL) + po(REL) + po(REL) + po(ACQ, 0) + po(ACQ, 1) + po(ACQ, 2))
    w("pool/regress-max-idle-zero", cfg(0, 0, 0) + po(ACQ, 0) + po(REL) + po(ACQ, 0))
    # idle_timeout 100 ms, straddled: 75 ms is reused, 100 ms is expired.
    w("pool/regress-expiry-under", cfg(4, 0, 1) + po(ACQ, 0) + po(REL) + po(CLOCK, 3) +
      po(ACQ, 0))
    w("pool/regress-expiry-at", cfg(4, 0, 1) + po(ACQ, 0) + po(REL) + po(CLOCK, 3) +
      po(CLOCK, 1) + po(ACQ, 0))
    w("pool/regress-no-expiry", cfg(4, 0, 0) + po(ACQ, 0) + po(REL) + po(CLOCK, 31) * 8 +
      po(ACQ, 0))
    w("pool/regress-stale-idle", cfg(4, 0, 0) + po(ACQ, 0) + po(REL) + po(SRVCLOSE, 0) +
      po(ACQ, 0))
    # Two idle for one key, the newer one stale: it goes, the older is used.
    w("pool/regress-stale-then-good", cfg(4, 0, 0) + po(ACQ, 0) + po(ACQ, 0) + po(REL) +
      po(REL) + po(SRVCLOSE, 0) + po(ACQ, 0) + po(ACQ, 0))
    w("pool/regress-acquire-newest", cfg(4, 0, 0) + po(ACQ, 0) + po(ACQ, 0) + po(REL, 0) +
      po(REL, 0) + po(ACQ, 0) + po(ACQ, 0) + po(ACQ, 0))
    w("pool/regress-partial-read", cfg(4, 0, 0) + po(ACQ, 0) + po(PART, 0) + po(ACQ, 0))
    w("pool/regress-unread-bytes", cfg(4, 0, 0) + po(ACQ, 0) + po(PART, 1) + po(ACQ, 0))
    w("pool/regress-error-reasons", cfg(7, 0, 0) + po(ACQ, 0) * 6 +
      b"".join(po(ERR, a) for a in range(6)) + po(ACQ, 0))
    w("pool/regress-key-not-host", cfg(4, 0, 0) + po(ACQ, 0) + po(REL) + po(ACQ, 3) +
      po(ACQ, 0))
    # §26.4: idle connections dropped without a close, in-flight ones the
    # child's to drop, and nothing from before the fork reused after it.
    w("pool/regress-fork", cfg(4, 0, 0) + po(ACQ, 0) + po(ACQ, 1) + po(REL) + po(REL) +
      po(FORK) + po(ACQ, 0) + po(REL) + po(ACQ, 0))
    w("pool/regress-fork-in-flight", cfg(4, 0, 0) + po(ACQ, 0) + po(ACQ, 0) + po(REL) +
      po(FORK) + po(ACQ, 0) + po(REL))
    w("pool/regress-fork-check", cfg(4, 0, 0) + po(ACQ, 0) + po(REL) + po(FORK) +
      po(MISC, 1) + po(MISC, 1) + po(ACQ, 0))
    w("pool/regress-fork-free", cfg(4, 0, 0) + po(ACQ, 0) + po(REL) + po(FORK) +
      po(MISC, 3) + po(ACQ, 0) + po(REL))
    # #265: zuh_pool_clear() in a child closed the parent's connections.
    w("pool/regress-265-fork-clear", cfg(4, 0, 0) + po(ACQ, 0) + po(REL) + po(FORK) +
      po(MISC, 0) + po(ACQ, 0))
    w("pool/regress-fork-end", cfg(4, 0, 0) + po(ACQ, 0) + po(ACQ, 2) + po(REL) + po(REL) +
      po(FORK))
    w("pool/clear-and-free", cfg(6, 3, 2) + po(ACQ, 0) + po(ACQ, 1) + po(REL) + po(REL) +
      po(MISC, 0) + po(ACQ, 0) + po(REL) + po(MISC, 3) + po(ACQ, 0))

    with open(os.path.join("corpus", "README"), "w") as f:
        f.write(README)

    n = sum(len(files) for _, _, files in os.walk("corpus"))
    size = sum(os.path.getsize(os.path.join(d, f))
               for d, _, files in os.walk("corpus") for f in files)
    print("seeded %d files, %.0f KB" % (n, size / 1024))


if __name__ == "__main__":
    main()

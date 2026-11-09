"""Curated fuzz seeds for zuhttp (design §43, §50.3).

Run via fuzz/seed-corpus.sh. Deterministic and byte-identical on every
platform, which the shell version was not — see that script's comment.
"""
import os
import shutil
import zlib

TARGETS = ("response", "chunked", "headers", "uri", "redirect", "inflate",
           "proxy", "redact", "body", "h2")

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

    # --- proxy: first byte selects no_proxy / URL / full resolution ---------
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

    with open(os.path.join("corpus", "README"), "w") as f:
        f.write(README)

    n = sum(len(files) for _, _, files in os.walk("corpus"))
    size = sum(os.path.getsize(os.path.join(d, f))
               for d, _, files in os.walk("corpus") for f in files)
    print("seeded %d files, %.0f KB" % (n, size / 1024))


if __name__ == "__main__":
    main()

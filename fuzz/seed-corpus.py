"""Curated fuzz seeds for zuhttp (design §43, §50.3).

Run via fuzz/seed-corpus.sh. Deterministic and byte-identical on every
platform, which the shell version was not — see that script's comment.
"""
import os
import shutil
import zlib

TARGETS = ("response", "chunked", "headers", "uri", "redirect", "inflate",
           "proxy", "redact")

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
    shutil.rmtree("corpus", ignore_errors=True)
    for t in TARGETS:
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

    with open(os.path.join("corpus", "README"), "w") as f:
        f.write(README)

    n = sum(len(files) for _, _, files in os.walk("corpus"))
    size = sum(os.path.getsize(os.path.join(d, f))
               for d, _, files in os.walk("corpus") for f in files)
    print("seeded %d files, %.0f KB" % (n, size / 1024))


if __name__ == "__main__":
    main()

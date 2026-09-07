#!/bin/sh
# Regenerate the curated seed corpus (design §43, §50.3).
#
# Every seed here is hand-written and explainable: a real protocol sample, a
# specific attack the design names, or a regression input for a bug that was
# actually found. Running libFuzzer writes newly-discovered coverage units
# into corpus/ as well, which is how it should work locally — but those must
# NOT be committed, so this script restores the curated set:
#
#   fuzz/seed-corpus.sh        # wipe and re-seed
#
# A 45 s run per target grows the corpus to ~29,000 files and tens of MB.
set -eu
cd "$(dirname "$0")"
rm -rf corpus
mkdir -p corpus/response corpus/chunked corpus/headers corpus/uri \
         corpus/redirect corpus/inflate corpus/proxy corpus/redact

w() { printf '%b' "$2" > "corpus/$1"; }

# --- response: the §18.1 framing / smuggling alphabet ---
w response/ok               "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
w response/no_headers       "HTTP/1.1 204 No Content\r\n\r\n"
w response/chunked          "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
w response/cl_te_conflict   "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"
w response/dup_cl           "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n"
w response/obs_fold         "HTTP/1.1 200 OK\r\nX-A: one\r\n  two\r\n\r\n"
w response/cl_negative      "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n"
w response/cl_overflow      "HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999\r\n\r\n"
w response/te_not_chunked   "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n"
w response/informational    "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
w response/space_before_colon "HTTP/1.1 200 OK\r\nX-A : v\r\n\r\n"
w response/nul_in_value     "HTTP/1.1 200 OK\r\nX-A: a\x00b\r\n\r\n"
w response/bare_lf          "HTTP/1.1 200 OK\nContent-Length: 0\n\n"
w response/huge_status      "HTTP/1.1 999999 X\r\n\r\n"
w response/partial          "HTTP/1.1 200 OK\r\nContent-Len"

# --- chunked: first byte is the fragmentation point ---
w chunked/simple            "\x03""5\r\nhello\r\n0\r\n\r\n"
w chunked/trailer           "\x00""5\r\nhello\r\n0\r\nX-T: v\r\n\r\n"
w chunked/ext               "\x00""5;name=value\r\nhello\r\n0\r\n\r\n"
w chunked/bad_size          "\x00""zz\r\nhello\r\n0\r\n\r\n"
w chunked/size_overflow     "\x00""FFFFFFFFFFFFFFFFFF\r\nx\r\n"
w chunked/negative          "\x00""-5\r\nhello\r\n"
w chunked/empty_final       "\x00""0\r\n\r\n"
w chunked/no_terminator     "\x00""5\r\nhello"

# --- headers: NAME\0VALUE ---
w headers/simple            "Content-Type\x00application/json"
w headers/crlf_injection    "X-Evil\x00v\r\nInjected: yes"
w headers/lf_injection      "X-Evil\x00v\nInjected: yes"
w headers/nul_value         "X-A\x00a\x00b"
w headers/empty_name        "\x00value"
w headers/empty_value       "X-Empty\x00"
w headers/bad_token         "X Space\x00v"
w headers/separator_in_name "X(paren)\x00v"
w headers/high_bytes        "X-A\x00\xff\xfe\x80"
w headers/tab_value         "X-A\x00\tvalue\t"
printf 'A%.0s' $(seq 1 2000) > corpus/headers/long_name
printf '\0v' >> corpus/headers/long_name

# --- uri ---
i=0
for u in "https://example.com/a/b?q=1#f" "http://[::1]:8080/x" "http://192.168.0.1/" \
         "https://user:pw@evil.com/" "https://good.com@evil.com/" "http://h:65536/" \
         "https://example.com../" "https://example.com./" "http://[" "http://[]" \
         "http://[:::::::::::]/" "https://////////a" "http://h/%2e%2e/%2e%2e/" \
         "ftp://example.com/" "mailto:a@b.com" "//host/path" "/just/path" \
         "http://h:0443/" "https://[fe80::1%25eth0]/" "http://h/?" "://" "h:" ""; do
    i=$((i + 1))
    printf '%s' "$u" > "corpus/uri/seed$(printf %02d "$i")"
done
# regressions: inputs that once crashed something
printf 'http://h@oocd.com:/' > corpus/uri/regress-userinfo-in-scheme
printf 'http://[v7.xyz]/'    > corpus/uri/regress-ipvfuture

# --- redirect: Location values against a credentialed base ---
i=0
for l in "g" "./g" "../g" "../../../g" "/g" "?y" "#s" "//other.example/z" \
         "https://other.example:8443/z" "http://h:65536/" "ftp://x/y" \
         "https://user:pw@other.example/" "" "g?y#s" "../../.."; do
    i=$((i + 1))
    printf '%s' "$l" > "corpus/redirect/seed$(printf %02d "$i")"
done

# --- proxy: first byte selects no_proxy / URL / full resolution ---
w proxy/np_simple  "\x00example.com\x00api.example.com"
w proxy/np_star    "\x00*\x00anything.com"
w proxy/np_port    "\x00example.com:8080\x00example.com"
w proxy/np_ipv6    "\x00[::1]:8080\x00::1"
w proxy/np_ip      "\x001.2.3.4\x0010.1.2.3.4"
w proxy/np_list    "\x00a.com, b.com ,c.com\x00b.com"
w proxy/np_dot     "\x00.example.com\x00example.com"
w proxy/url_plain  "\x01http://px.example:3128"
w proxy/url_creds  "\x01http://user:pass@px.example:3128"
w proxy/url_pct    "\x01http://us%40er:p%40ss@px:3128"
w proxy/url_bad_pct "\x01http://u:p%zz@px:3128"
w proxy/url_bare   "\x01px.example:3128"
w proxy/url_socks  "\x01socks5://px:1080"
w proxy/res_env    "\x02http://px.example:3128\x00internal.example"
w proxy/res_empty  "\x02\x00"
printf '\x01http://[veee.0;;;;***UU;;;;;;;;;;;;;:]//;m=' > corpus/proxy/regress-ipvfuture

# --- redact: URLs and form bodies, mostly credential-bearing ---
w redact/userinfo    "https://user:pw@api.example.com/v1/x"
w redact/at_in_user  "https://us@er:p@ss@api.example.com/x"
w redact/param       "https://h/v1?page=2&api_key=SECRET&sort=asc"
w redact/both        "https://u:p@h:8443/x?sig=S&ok=1"
w redact/fragment    "https://h/x?access_token=S#frag"
w redact/unparseable "https://user:pw@h:99999999/][?api_key=S"
w redact/form        "user=alice&api_key=SECRET&scope=read"
w redact/semicolons  "https://h/?a=1;sig=X;b=2"
w redact/bare_at     "@@@"
w redact/no_scheme   "/just/a/path?api_key=S"

# --- inflate: first byte selects gzip / deflate / encoding-name ---
python3 - <<'PY'
import zlib
def w(n, b): open('corpus/inflate/' + n, 'wb').write(b)
p = b'hello world ' * 40
co = zlib.compressobj(9, zlib.DEFLATED, 16 + 15)
w('gzip_real', b'\x00' + co.compress(p) + co.flush())
w('deflate_zlib', b'\x01' + zlib.compress(p))
co2 = zlib.compressobj(9, zlib.DEFLATED, -15)
w('deflate_raw', b'\x01' + co2.compress(p) + co2.flush())
# the bomb: 64 MB of zeros, which must stop exactly at the cap
co3 = zlib.compressobj(9, zlib.DEFLATED, 16 + 15)
w('bomb', b'\x00' + co3.compress(b'\x00' * (64 << 20)) + co3.flush())
w('truncated', b'\x00' + zlib.compress(p)[:20])
w('garbage', b'\x00' + b'\xde\xad\xbe\xef' * 8)
for n in ('gzip', 'deflate', 'br', 'identity', 'GZIP', 'gzip, deflate', ''):
    w('enc_' + (n or 'empty').replace(', ', '_'), b'\x02' + n.encode())
PY

cat > corpus/README <<'ROEOF'
Curated fuzz seeds (design §43, §50.3).

Regenerate with fuzz/seed-corpus.sh (or `make -C fuzz reseed`). Do not add
files here by hand — add them to that script, so the corpus stays
reproducible and every seed keeps its explanation.

Every file is a real protocol sample, a specific attack the design names
(CL/TE conflict, duplicate Content-Length, obs-fold, CRLF injection, an
over-large port, a decompression bomb, an httpoxy-shaped environment), or a
`regress-*` input for a bug that was actually found.

Soak-grown corpora are deliberately NOT committed. Running libFuzzer locally
writes new coverage units into these directories, which is how it should work
— but a 45 s run per target grows this to ~29,000 files and tens of MB, and
even `-merge=1` minimisation leaves ~12,000 unexplainable blobs. Run
`make -C fuzz reseed` before committing. CI keeps its grown corpora as
artifacts from the `soak` job in .github/workflows/fuzz.yaml.
ROEOF
echo "seeded $(find corpus -type f | wc -l | tr -d ' ') files, $(du -sh corpus | cut -f1)"

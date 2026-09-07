#!/bin/sh
# zuhttp Stage S0 — macOS TLS spike test matrix
#
# Answers, in order:
#   1. Does the OpenSSL engine + SecTrust (Keychain) split work end to end?
#   2. Are certificate failures distinguishable and actionable?
#   3. Do custom anchors behave additively vs. as a replacement (§14.2)?
#   4. Does the deprecated Secure Transport fallback still work, and at what
#      protocol ceiling?
#
# Network access is required for the public-host tests.

set -u
cd "$(dirname "$0")"

OPENSSL=${OPENSSL:-/opt/homebrew/opt/openssl@3/bin/openssl}
[ -x "$OPENSSL" ] || OPENSSL=openssl
TMP=tmp
PORT=${PORT:-14443}

pass=0; fail=0
check() { # check <expected rc> <label> <cmd...>
    want=$1; label=$2; shift 2
    out=$("$@" 2>&1); rc=$?
    if [ "$rc" = "$want" ]; then
        pass=$((pass+1)); printf '  \033[32mok\033[0m   %-42s %s\n' "$label" "$(echo "$out" | head -1 | sed 's/.*rc=[01]  //')"
    else
        fail=$((fail+1)); printf '  \033[31mFAIL\033[0m %-42s want rc=%s got rc=%s\n       %s\n' "$label" "$want" "$rc" "$(echo "$out" | head -1)"
    fi
}

make -s tls_spike || exit 1

# ------------------------------------------------------------------
echo
echo "== 1. public hosts, system Keychain trust (engine: openssl) =="
check 0 "example.com trusted"            ./tls_spike --host example.com --quiet
check 0 "www.cloudflare.com trusted"     ./tls_spike --host www.cloudflare.com --quiet
check 0 "api.github.com trusted"         ./tls_spike --host api.github.com --quiet

echo
echo "== 2. certificate failures are distinguishable =="
check 1 "expired rejected"               ./tls_spike --host expired.badssl.com --quiet
check 1 "wrong hostname rejected"        ./tls_spike --host wrong.host.badssl.com --quiet
check 1 "untrusted root rejected"        ./tls_spike --host untrusted-root.badssl.com --quiet
check 1 "self-signed rejected"           ./tls_spike --host self-signed.badssl.com --quiet

echo
echo "== 3. revocation is NOT checked by default (finding F-4) =="
check 0 "revoked ACCEPTED without policy" ./tls_spike --host revoked.badssl.com --quiet
check 1 "revoked rejected with policy"    ./tls_spike --host revoked.badssl.com --revocation --quiet

# ------------------------------------------------------------------
echo
echo "== 4. custom anchors: additive vs replacement (design §14.2) =="
mkdir -p $TMP
if [ ! -f $TMP/ca.pem ]; then
    "$OPENSSL" req -x509 -newkey rsa:2048 -nodes -days 30 \
        -keyout $TMP/ca.key -out $TMP/ca.pem \
        -subj "/CN=zuhttp spike test CA" >/dev/null 2>&1
    "$OPENSSL" req -newkey rsa:2048 -nodes \
        -keyout $TMP/leaf.key -out $TMP/leaf.csr \
        -subj "/CN=localhost" >/dev/null 2>&1
    printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > $TMP/leaf.ext
    "$OPENSSL" x509 -req -in $TMP/leaf.csr -CA $TMP/ca.pem -CAkey $TMP/ca.key \
        -CAcreateserial -out $TMP/leaf.pem -days 30 -extfile $TMP/leaf.ext >/dev/null 2>&1
fi

"$OPENSSL" s_server -quiet -accept $PORT -cert $TMP/leaf.pem -key $TMP/leaf.key \
    -cert_chain $TMP/ca.pem -www >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT INT TERM
sleep 1

check 1 "local CA, no anchor -> rejected"     ./tls_spike --host localhost --port $PORT --quiet
check 0 "local CA, --anchor -> accepted"      ./tls_spike --host localhost --port $PORT --anchor $TMP/ca.pem --quiet
check 0 "local CA, --anchor-only -> accepted" ./tls_spike --host localhost --port $PORT --anchor $TMP/ca.pem --anchor-only --quiet
check 0 "public host + --anchor still ok"     ./tls_spike --host example.com --anchor $TMP/ca.pem --quiet
check 1 "public host + --anchor-only FAILS"   ./tls_spike --host example.com --anchor $TMP/ca.pem --anchor-only --quiet

kill $SRV 2>/dev/null; trap - EXIT INT TERM

# ------------------------------------------------------------------
echo
echo "== 5. Secure Transport fallback (deprecated since macOS 10.15) =="
check 0 "example.com via Secure Transport"   ./tls_spike --host example.com --engine st --quiet
check 1 "expired rejected via ST"            ./tls_spike --host expired.badssl.com --engine st --quiet
echo "  protocol ceiling:"
./tls_spike --host example.com --engine st --quiet | sed 's/^/    /'
./tls_spike --host example.com --engine openssl --quiet | sed 's/^/    /'

# ------------------------------------------------------------------
echo
echo "== 6. loop ownership and thread count =="
./tls_spike --host example.com | sed 's/^/  /'

echo
echo "-------------------------------------------"
printf 'passed %d, failed %d\n' "$pass" "$fail"
[ "$fail" = 0 ]

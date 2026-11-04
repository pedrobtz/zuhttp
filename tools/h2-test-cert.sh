#!/bin/sh
# A CA and a localhost certificate for tools/h2-test-server.py (design §65.8).
#
#   tools/h2-test-cert.sh DIR      writes DIR/ca.pem, DIR/cert.pem, DIR/key.pem
#
# Two certificates rather than one self-signed one, with the extensions the
# test fixture (tests/testthat/helper-tlsfixture.R) uses: SecTrust's SSL
# policy refuses a leaf without serverAuth as "not permitted for this usage".
set -eu
D=$1
mkdir -p "$D"
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=zuhttp-h2-test-CA" \
    -keyout "$D/ca.key" -out "$D/ca.pem" >/dev/null 2>&1
printf '%s\n' "subjectAltName=DNS:localhost,IP:127.0.0.1" "basicConstraints=CA:FALSE" \
    "keyUsage=digitalSignature,keyEncipherment" "extendedKeyUsage=serverAuth" > "$D/leaf.ext"
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" \
    -keyout "$D/key.pem" -out "$D/leaf.csr" >/dev/null 2>&1
openssl x509 -req -in "$D/leaf.csr" -CA "$D/ca.pem" -CAkey "$D/ca.key" -CAcreateserial \
    -days 30 -extfile "$D/leaf.ext" -out "$D/cert.pem" >/dev/null 2>&1
echo "wrote $D/ca.pem $D/cert.pem $D/key.pem"

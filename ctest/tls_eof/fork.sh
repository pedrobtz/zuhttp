#!/bin/sh
# #249: pooled TLS connections inherited by a forked child, against a
# scripted loopback server. `drive fork` holds a pulled body open on one
# connection and a second connection idle in the pool, forks, and the child
# frees both; then the parent reads its body whole and reuses both. This
# script reads the server's log: two connections, each served both of its
# requests, and neither closed by the client before the parent was done
# with it. A child that wrote a close_notify, or a FIN, into a connection
# it inherited fails here even when the parent's next read would recover.
#
# DRIVE names the driver: zuh_tlseof (OpenSSL), zuh_tlseof_asan, or
# zuh_tlseof_nw / zuh_tlseof_nw_asan (Network.framework).
set -e
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'kill $srv 2>/dev/null || true; rm -rf "$tmp"' EXIT
openssl=${OPENSSL:-openssl}
# serverAuth and a short life, which SecTrust requires of a TLS leaf.
"$openssl" req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost \
  -addext "subjectAltName=DNS:localhost" -addext "extendedKeyUsage=serverAuth" \
  -keyout "$tmp/key.pem" -out "$tmp/cert.pem" >/dev/null 2>&1
drive=${DRIVE:-$here/../zuh_tlseof}
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
python3 "$here/server.py" fork "$port" "$tmp/cert.pem" "$tmp/key.pem" >"$tmp/srv.log" 2>&1 &
srv=$!
i=0; until grep -q ready "$tmp/srv.log" 2>/dev/null || [ $i -ge 50 ]; do sleep 0.1; i=$((i + 1)); done
status=0
"$drive" fork "https://localhost:$port/" "$tmp/cert.pem" || status=1
sleep 0.3
check() {
  if ! grep -q "$1" "$tmp/srv.log"; then echo "FAIL fork: the server never logged '$1'"; status=1; fi
}
check "^accept 2$"
check "^conn 1 request 2 /$"
check "^conn 2 request 2 /$"
if grep -q "^accept 3$" "$tmp/srv.log"; then
  echo "FAIL fork: a third connection: an inherited one was not reusable"; status=1
fi
if grep -q "closed by the client after 1 requests\|ended:" "$tmp/srv.log"; then
  echo "FAIL fork: a connection ended before the parent was done with it"; status=1
fi
if [ $status -ne 0 ]; then echo "--- server log"; cat "$tmp/srv.log"; fi
kill $srv 2>/dev/null || true; wait $srv 2>/dev/null || true
exit $status

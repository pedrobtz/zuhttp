#!/bin/sh
# make tls-eof: run drive against server.py in both modes (D-86).
set -e
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'kill $srv 2>/dev/null || true; rm -rf "$tmp"' EXIT
openssl=${OPENSSL:-openssl}
"$openssl" req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost \
  -addext "subjectAltName=DNS:localhost" \
  -keyout "$tmp/key.pem" -out "$tmp/cert.pem" >/dev/null 2>&1
status=0
for mode in noclose together; do
  port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
  python3 "$here/server.py" "$mode" "$port" "$tmp/cert.pem" "$tmp/key.pem" >"$tmp/srv.log" 2>&1 &
  srv=$!
  i=0; until grep -q ready "$tmp/srv.log" 2>/dev/null || [ $i -ge 50 ]; do sleep 0.1; i=$((i + 1)); done
  "$here/../zuh_tlseof" "$mode" "https://localhost:$port/" "$tmp/cert.pem" || status=1
  kill $srv 2>/dev/null || true; wait $srv 2>/dev/null || true
done
exit $status

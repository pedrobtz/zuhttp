#!/bin/sh
# make tls-eof: run drive against server.py in every mode (D-86), and against
# reneg.py (#215), a resumable session after an unverified one (#307), an IP-only certificate (#216) and the two it must refuse (#246), then fork.sh (#249).
# DRIVE names the driver binary: make tls-eof-asan runs the same script
# against an ASan build.
set -e
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'kill $srv 2>/dev/null || true; rm -rf "$tmp"' EXIT
openssl=${OPENSSL:-openssl}
"$openssl" req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost \
  -addext "subjectAltName=DNS:localhost" \
  -keyout "$tmp/key.pem" -out "$tmp/cert.pem" >/dev/null 2>&1
# A second self-signed certificate: trusting it instead fails the handshake.
"$openssl" req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=other \
  -keyout "$tmp/other-key.pem" -out "$tmp/other.pem" >/dev/null 2>&1
# A certificate whose only name is an IP address (#216).
"$openssl" req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=ip-only \
  -addext "subjectAltName=IP:127.0.0.1" \
  -keyout "$tmp/ip-key.pem" -out "$tmp/ip.pem" >/dev/null 2>&1
# #246: one names another address, one names this address as a DNS name.
"$openssl" req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=ip-other \
  -addext "subjectAltName=IP:127.0.0.2" \
  -keyout "$tmp/ipother-key.pem" -out "$tmp/ipother.pem" >/dev/null 2>&1
"$openssl" req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=127.0.0.1 \
  -addext "subjectAltName=DNS:127.0.0.1" \
  -keyout "$tmp/ipdns-key.pem" -out "$tmp/ipdns.pem" >/dev/null 2>&1
drive=${DRIVE:-$here/../zuh_tlseof}
free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'
}
wait_ready() {
  i=0; until grep -q ready "$tmp/srv.log" 2>/dev/null || [ $i -ge 50 ]; do sleep 0.1; i=$((i + 1)); done
}
status=0
for mode in noclose together keepalive; do
  port=$(free_port)
  python3 "$here/server.py" "$mode" "$port" "$tmp/cert.pem" "$tmp/key.pem" >"$tmp/srv.log" 2>&1 &
  srv=$!
  wait_ready
  if [ "$mode" = keepalive ]; then
    "$drive" stale "https://localhost:$port/" "$tmp/cert.pem" "$tmp/other.pem" || status=1
  else
    "$drive" "$mode" "https://localhost:$port/" "$tmp/cert.pem" || status=1
  fi
  kill $srv 2>/dev/null || true; wait $srv 2>/dev/null || true
done

# #216: verified by IP address, against a certificate that names only that.
port=$(free_port)
python3 "$here/server.py" keepalive "$port" "$tmp/ip.pem" "$tmp/ip-key.pem" >"$tmp/srv.log" 2>&1 &
srv=$!
wait_ready
"$drive" one "https://127.0.0.1:$port/" "$tmp/ip.pem" || status=1
kill $srv 2>/dev/null || true; wait $srv 2>/dev/null || true

# #246: and refused, as a hostname error, when the certificate names another
# address or names this one only as a DNS name.
for c in ipother ipdns; do
  port=$(free_port)
  python3 "$here/server.py" keepalive "$port" "$tmp/$c.pem" "$tmp/$c-key.pem" >"$tmp/srv.log" 2>&1 &
  srv=$!
  wait_ready
  "$drive" hostname "https://127.0.0.1:$port/" "$tmp/$c.pem" || status=1
  kill $srv 2>/dev/null || true; wait $srv 2>/dev/null || true
done

# #307: verify off, then verification against a CA that does not vouch for
# the server; at TLS 1.2, where the server resumes sessions.
port=$(free_port)
python3 "$here/server.py" resume "$port" "$tmp/other.pem" "$tmp/other-key.pem" >"$tmp/srv.log" 2>&1 &
srv=$!
wait_ready
"$drive" resume "https://localhost:$port/" "$tmp/cert.pem" || status=1
kill $srv 2>/dev/null || true; wait $srv 2>/dev/null || true

# #313 and #314, the differential for Schannel's run-sch.sh: an optional
# client-certificate request, and a response followed by a broken record.
for mode in optcert badmac; do
  port=$(free_port)
  python3 "$here/server.py" "$mode" "$port" "$tmp/cert.pem" "$tmp/key.pem" >"$tmp/srv.log" 2>&1 &
  srv=$!
  wait_ready
  "$drive" one "https://localhost:$port/" "$tmp/cert.pem" || status=1
  kill $srv 2>/dev/null || true; wait $srv 2>/dev/null || true
done

# A response that stops partway must time out, not end (the OpenSSL
# mutation run: a deadline in tls_read() read as end of stream survived),
# and an upload into a reset must fail as a write error, not a timeout.
port=$(free_port)
python3 "$here/server.py" stall "$port" "$tmp/cert.pem" "$tmp/key.pem" >"$tmp/srv.log" 2>&1 &
srv=$!
wait_ready
"$drive" stall "https://localhost:$port/close" "$tmp/cert.pem" || status=1
"$drive" stall "https://localhost:$port/length" "$tmp/cert.pem" || status=1
kill $srv 2>/dev/null || true; wait $srv 2>/dev/null || true
port=$(free_port)
python3 "$here/server.py" reset "$port" "$tmp/cert.pem" "$tmp/key.pem" >"$tmp/srv.log" 2>&1 &
srv=$!
wait_ready
"$drive" upload "https://localhost:$port/" "$tmp/cert.pem" || status=1
kill $srv 2>/dev/null || true; wait $srv 2>/dev/null || true

# #215: a renegotiation runs the verify callback after the dial returned.
port=$(free_port)
OPENSSL="$openssl" python3 "$here/reneg.py" "$port" "$tmp/cert.pem" "$tmp/key.pem" >"$tmp/srv.log" 2>&1 &
srv=$!
wait_ready
"$drive" one "https://localhost:$port/" "$tmp/cert.pem" || status=1
kill $srv 2>/dev/null || true; wait $srv 2>/dev/null || true

# #315: the same renegotiation on an HTTP/2 connection is refused.
port=$(free_port)
RENEG_ALPN=h2 OPENSSL="$openssl" python3 "$here/reneg.py" "$port" "$tmp/cert.pem" "$tmp/key.pem" >"$tmp/srv.log" 2>&1 &
srv=$!
wait_ready
"$drive" h2reneg "https://localhost:$port/" "$tmp/cert.pem" || status=1
kill $srv 2>/dev/null || true; wait $srv 2>/dev/null || true

# #249: connections a forked child inherited, dropped without a byte.
OPENSSL="$openssl" DRIVE="$drive" "$here/fork.sh" || status=1
exit $status

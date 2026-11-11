#!/bin/sh
# make tls-eof-sch: tls_eof's scripted servers against the engine over
# Schannel (#286), on the Windows CI leg. Schannel has no ca_file (its
# zuh_tls_backend_caps() mask), so the client trusts what the machine
# trusts: the committed fixture's CA (tests/testthat/fixtures/tls, made by
# tools/make-tls-fixture) goes into the LocalMachine Root store for the run
# and comes out again at the end. Its key is public test material, which is
# why it is acceptable in an ephemeral CI runner's store and nowhere else.
#
# The cases are run.sh's, less what cannot apply: no fork() on Windows, and
# no `stale`, which switches trust by ca_file. TLS 1.3's KeyUpdate cannot
# arise, because Schannel is TLS 1.2 here (D-64).
#
# DRIVE names the driver; PYTHON the interpreter (python3 is the Microsoft
# Store stub on a fresh Windows image, so `python` is the default).
set -e
here=$(cd "$(dirname "$0")" && pwd)
fx=$here/../../tests/testthat/fixtures/tls
drive=${DRIVE:-$here/../zuh_tlseof_sch}
py=${PYTHON:-python}
openssl=${OPENSSL:-openssl}
tmp=$(mktemp -d)
srv=
cleanup() {
  [ -n "$srv" ] && kill "$srv" 2>/dev/null || true
  certutil -delstore Root zuhttp-test-CA >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT

certutil -addstore -f Root "$(cygpath -w "$fx/ca.pem")" >/dev/null

free_port() {
  "$py" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'
}
wait_ready() {
  i=0; until grep -q ready "$tmp/srv.log" 2>/dev/null || [ $i -ge 100 ]; do sleep 0.1; i=$((i + 1)); done
}
stop() { kill "$srv" 2>/dev/null || true; wait "$srv" 2>/dev/null || true; srv=; }
status=0
# serve MODE LEAF; then drive ARGS... against it.
serve() {
  port=$(free_port)
  "$py" "$here/server.py" "$1" "$port" "$fx/$2.pem" "$fx/$2.key" >"$tmp/srv.log" 2>&1 &
  srv=$!
  wait_ready
}

# A close-delimited body ended by a TCP close with no close_notify (D-86).
serve noclose good
"$drive" noclose "https://localhost:$port/" - || status=1
stop
# A body and its close_notify in one send: the pooled connection the server
# closed must not carry the second request.
serve together good
"$drive" together "https://localhost:$port/" - || status=1
stop
# #216 and #246: an IP literal against iPAddress SANs only.
serve keepalive ip
"$drive" one "https://127.0.0.1:$port/" - || status=1
stop
for c in ipother ipdns; do
  serve keepalive "$c"
  "$drive" hostname "https://127.0.0.1:$port/" - || status=1
  stop
done
# #307: verify off, then system trust (which has the fixture CA but not the
# rogue one): Schannel's session cache is process-wide, and the second
# handshake must still be verified.
serve resume untrusted
"$drive" resume "https://localhost:$port/" - || status=1
stop
# #308: a name only in the subject CN is no name. #309: a leaf for client
# authentication is not a server certificate; Schannel's chain request names
# no EKU, so this is the row that says whether its SSL policy checks one.
serve keepalive cnonly
"$drive" hostname "https://localhost:$port/" - || status=1
stop
serve keepalive clientonly
"$drive" certificate "https://localhost:$port/" - || status=1
stop
# #313: a server that asks for a client certificate it does not require.
# #314: a response, then a record that fails to decrypt, in one send.
serve optcert good
"$drive" one "https://localhost:$port/" - || status=1
stop
serve badmac good
"$drive" one "https://localhost:$port/" - || status=1
stop
# A response that stops partway times out; an upload into a reset fails as
# a write error. The same rows as run.sh's.
serve stall good
"$drive" stall "https://localhost:$port/close" - || status=1
"$drive" stall "https://localhost:$port/length" - || status=1
stop
serve reset good
"$drive" upload "https://localhost:$port/" - || status=1
stop
# #215: a TLS 1.2 renegotiation between the request and the response.
# Schannel reports SEC_I_RENEGOTIATE, which is not handled yet (#298): the
# request fails with a TLS class and no body. `refused` says so when that
# changes, and this becomes `one`, as on OpenSSL.
port=$(free_port)
OPENSSL="$openssl" "$py" "$here/reneg.py" "$port" "$fx/good.pem" "$fx/good.key" >"$tmp/srv.log" 2>&1 &
srv=$!
wait_ready
"$drive" refused "https://localhost:$port/" - || status=1
stop
exit $status

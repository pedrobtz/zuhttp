#!/bin/sh
# make tls-rx-nw: nwrx (#311) against server.py's bulk mode, with the §50.5
# fixture's `good` leaf, which Network.framework accepts (run.sh's
# self-signed certificates lack the serverAuth EKU it requires).
set -e
here=$(cd "$(dirname "$0")" && pwd)
fx=$here/../../tests/testthat/fixtures/tls
tmp=$(mktemp -d)
trap 'kill $srv 2>/dev/null || true; rm -rf "$tmp"' EXIT
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
python3 "$here/server.py" bulk "$port" "$fx/good.pem" "$fx/good.key" >"$tmp/srv.log" 2>&1 &
srv=$!
i=0; until grep -q ready "$tmp/srv.log" 2>/dev/null || [ $i -ge 50 ]; do sleep 0.1; i=$((i + 1)); done
"${NWRX:-$here/../zuh_nwrx}" "$port" "$fx/ca.pem"

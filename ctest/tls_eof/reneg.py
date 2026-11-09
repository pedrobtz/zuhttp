# A TLS 1.2 server that renegotiates between the request and the response
# (#215). Python's ssl module cannot start a renegotiation, so this drives
# `openssl s_server`, whose interactive `R` command sends a HelloRequest. The
# client's verify callback runs again for the new handshake, after the call
# that configured the connection has returned: whatever it reads must still
# be the connection's own. No tickets and no session cache, so the second
# handshake is a full one and verifies the certificate again rather than
# resuming. One connection, then it exits.
#
#   reneg.py PORT CERT KEY    (OPENSSL names the CLI, default `openssl`)
import os, subprocess, sys, time

port, cert, key = sys.argv[1], sys.argv[2], sys.argv[3]
p = subprocess.Popen([os.environ.get("OPENSSL", "openssl"), "s_server", "-accept", port,
                      "-cert", cert, "-key", key, "-tls1_2", "-no_ticket", "-no_cache"],
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
seen = b""
while b"ACCEPT" not in seen:
    d = p.stdout.read1(4096)
    if not d:
        sys.exit("s_server did not start: " + seen.decode(errors="replace"))
    seen += d
print("ready", flush=True)
seen = b""
deadline = time.time() + 10
while b"\r\n\r\n" not in seen and time.time() < deadline:
    d = p.stdout.read1(4096)
    if not d:
        break
    seen += d
p.stdin.write(b"R\n")               # renegotiate, before any response byte
p.stdin.flush()
time.sleep(0.5)
p.stdin.write(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
p.stdin.flush()
time.sleep(2)                       # the client has read its 2 bytes by now
p.kill()
rest = p.stdout.read()
sys.stderr.write(rest.decode(errors="replace"))

# Working through a proxy

Many corporate and university networks only reach the internet through
an HTTP proxy. zuhttp supports the two ways such a proxy is used:

- **Plain HTTP** requests are sent to the proxy with the full URL in the
  request line, and the proxy fetches them.
- **HTTPS** requests open a tunnel with `CONNECT`. The proxy relays
  encrypted bytes and never sees the content; the certificate is
  verified between you and the real server, exactly as without a proxy.

Proxies with no authentication and with Basic authentication are
supported. NTLM and Kerberos proxies are not.

## A proxy to watch

To show what zuhttp actually sends, this article starts a small logging
proxy, written in Python, next to a local test web server
([webfakes](https://webfakes.r-lib.org)). The proxy records every
request it receives and whether it carried credentials.

The logging proxy

``` r

proxy_py <- '
import base64, socket, sys, threading
port, logf, auth = int(sys.argv[1]), sys.argv[2], (sys.argv[3] if len(sys.argv) > 3 else "")

def log(line):
    with open(logf, "a") as f: f.write(line + "\\n")

def pipe(a, b):
    try:
        while (d := a.recv(65536)): b.sendall(d)
    except OSError: pass
    finally:
        for s in (a, b):
            try: s.shutdown(socket.SHUT_RDWR)
            except OSError: pass

def handle(c):
    head = b""
    while b"\\r\\n\\r\\n" not in head:
        d = c.recv(4096)
        if not d: return c.close()
        head += d
    head, rest = head.split(b"\\r\\n\\r\\n", 1)
    lines = head.decode().split("\\r\\n")
    method, target, _ = lines[0].split(" ", 2)
    hdrs = [l for l in lines[1:] if l]
    creds = [l.split(":", 1)[1].strip() for l in hdrs if l.lower().startswith("proxy-authorization:")]
    log(f"{method} {target}  (credentials: {\'yes\' if creds else \'no\'})")
    if auth and (not creds or creds[0] != "Basic " + base64.b64encode(auth.encode()).decode()):
        c.sendall(b"HTTP/1.1 407 Proxy Authentication Required\\r\\n"
                  b"Proxy-Authenticate: Basic realm=\\"proxy\\"\\r\\nContent-Length: 0\\r\\n\\r\\n")
        return c.close()
    if method == "CONNECT":
        host, p = target.rsplit(":", 1)
        u = socket.create_connection((host, int(p)))
        c.sendall(b"HTTP/1.1 200 Connection Established\\r\\n\\r\\n")
    else:
        hostport = target.split("/", 3)[2]
        host, p = (hostport.rsplit(":", 1) + ["80"])[:2]
        path = "/" + target.split("/", 3)[3] if target.count("/") >= 3 else "/"
        keep = [l for l in hdrs if not l.lower().startswith(("proxy-", "connection:"))]
        u = socket.create_connection((host, int(p)))
        u.sendall((f"{method} {path} HTTP/1.1\\r\\n" + "\\r\\n".join(keep) +
                   "\\r\\nConnection: close\\r\\n\\r\\n").encode() + rest)
    threading.Thread(target=pipe, args=(c, u), daemon=True).start()
    pipe(u, c)

srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(16)
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
'
script <- tempfile(fileext = ".py")
writeLines(proxy_py, script)

free_port <- function() {
  repeat {
    p <- sample(20000:40000, 1)
    s <- try(serverSocket(p), silent = TRUE)
    if (!inherits(s, "try-error")) { close(s); return(p) }
  }
}
start_proxy <- function(auth = "") {
  port <- free_port()
  logf <- tempfile(fileext = ".log"); file.create(logf)
  pid <- sys::exec_background("python3", c(script, port, logf, auth),
                              std_out = FALSE, std_err = FALSE)
  Sys.sleep(1)
  list(url = sprintf("http://127.0.0.1:%d", port), log = logf, pid = pid)
}
proxy_log <- function(p) cat(readLines(p$log), sep = "\n")
```

``` r

library(zuhttp)
web <- webfakes::new_app_process(webfakes::httpbin_app(), start = TRUE)
proxy <- start_proxy()
proxy$url
#> [1] "http://127.0.0.1:25292"
```

## Sending a request through a proxy

Pass the proxy’s URL as `proxy =`, on a request or on a client:

``` r

r <- zu_get(web$url("/get"), proxy = proxy$url)
zu_resp_status(r)
#> [1] 200
zu_resp_connection(r)$proxy_used
#> [1] TRUE
proxy_log(proxy)
#> GET http://127.0.0.1:42047/get  (credentials: no)
```

The proxy received the full URL in the request line — that is how a
plain HTTP request tells the proxy where to go.

On a client, the proxy applies to every request:

``` r

via_proxy <- zu_client(proxy = proxy$url)
for (p in c("/uuid", "/ip")) invisible(zu_get(web$url(p), client = via_proxy))
proxy_log(proxy)
#> GET http://127.0.0.1:42047/get  (credentials: no)
#> GET http://127.0.0.1:42047/uuid  (credentials: no)
#> GET http://127.0.0.1:42047/ip  (credentials: no)
```

## HTTPS through a proxy

For an `https://` URL zuhttp asks the proxy for a tunnel with `CONNECT`,
then performs the TLS handshake with the real server *through* it. The
proxy logs only the host and port — it never sees the path, the headers
or the body.

This needs an HTTPS server. As in the [TLS
article](https://pedrobtz.github.io/zuhttp/articles/tls.md), it uses a
certificate from an authority created for the occasion:

The HTTPS server

``` r

ssl <- function(...) system2("openssl", c(...), stdout = FALSE, stderr = FALSE)
d <- tempfile("proxy-tls-"); dir.create(d)
f <- function(x) file.path(d, x)
ssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
    "-keyout", f("ca.key"), "-out", f("ca.pem"), "-subj", "/CN=article-CA")
writeLines(c("subjectAltName=DNS:localhost", "basicConstraints=CA:FALSE",
             "keyUsage=digitalSignature,keyEncipherment",
             "extendedKeyUsage=serverAuth"), f("leaf.ext"))
ssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", f("leaf.key"),
    "-out", f("leaf.csr"), "-subj", "/CN=localhost")
ssl("x509", "-req", "-in", f("leaf.csr"), "-CA", f("ca.pem"), "-CAkey", f("ca.key"),
    "-CAcreateserial", "-days", "30", "-extfile", f("leaf.ext"), "-out", f("leaf.pem"))
writeLines(c(readLines(f("leaf.pem")), readLines(f("leaf.key"))), f("server.pem"))

tls_port <- free_port()
secure <- webfakes::new_app_process(
  webfakes::httpbin_app(), port = paste0(tls_port, "s"),
  opts = webfakes::server_opts(remote = TRUE, ssl_certificate = f("server.pem")),
  start = TRUE
)
secure_url <- function(path) sprintf("https://localhost:%d%s", tls_port, path)
```

``` r

p2 <- start_proxy()
r <- zu_get(secure_url("/get?secret=only-the-server-sees-this"),
            proxy = p2$url, tls = zu_tls(ca_extra = f("ca.pem")))
zu_resp_status(r)
#> [1] 200
zu_resp_connection(r)[c("proxy_used", "tls_protocol")]
#> $proxy_used
#> [1] TRUE
#> 
#> $tls_protocol
#> [1] "TLSv1.3"
proxy_log(p2)
#> CONNECT localhost:26603  (credentials: no)
```

The certificate was checked against the real server, not the proxy: a
proxy that tried to answer the TLS handshake itself would fail
verification.

## Proxy authentication

A proxy that needs a user name and password takes them in its URL.
zuhttp moves them out of the URL straight away, sends them to the proxy
— and only the proxy — as `Proxy-Authorization`, and never prints them:

``` r

guarded <- start_proxy(auth = "alice:wonderland")
authed <- sub("http://", "http://alice:wonderland@", guarded$url)

r <- zu_get(web$url("/headers"), proxy = authed)
zu_resp_status(r)
#> [1] 200
proxy_log(guarded)
#> GET http://127.0.0.1:42047/headers  (credentials: yes)
```

The web server behind the proxy never receives the proxy’s credentials:

``` r

names(zu_resp_json(r)$headers)
#> [1] "Host"            "User-Agent"      "Accept"          "Accept-Encoding"
#> [5] "Connection"
```

A wrong password is its own condition class, and the error message does
not repeat the password:

``` r

wrong <- sub("http://", "http://alice:guess@", guarded$url)
zu_get(web$url("/get"), proxy = wrong)
#> Error in `zu_perform()`:
#> ! GET http://127.0.0.1:42047/get failed: HTTP 407 Proxy Authentication Required
#>   The proxy refused the request. Check the user name and password in the proxy URL (http://user:password@host:port).
```

Printed clients redact it too:

``` r

zu_client(proxy = authed)$proxy |> zu_redact_url()
#> [1] "http://127.0.0.1:20484"
```

## Proxies from the environment

Most people configure a proxy once, in the environment, and zuhttp reads
the same variables as curl:

| Variable                           | Used for                               |
|------------------------------------|----------------------------------------|
| `https_proxy` / `HTTPS_PROXY`      | `https://` requests                    |
| `http_proxy` (lower case **only**) | `http://` requests                     |
| `all_proxy` / `ALL_PROXY`          | either, when the specific one is unset |
| `no_proxy` / `NO_PROXY`            | hosts to reach directly                |

Upper-case `HTTP_PROXY` is deliberately ignored: in some web-server
environments a request header can set it, which would let a caller
redirect your traffic.

``` r

p3 <- start_proxy()
Sys.setenv(http_proxy = p3$url)
invisible(zu_get(web$url("/get")))          # no proxy argument
proxy_log(p3)
#> GET http://127.0.0.1:42047/get  (credentials: no)
```

`no_proxy` lists hosts to reach directly: comma-separated names, matched
on whole labels (`example.com` covers `api.example.com`, not
`notexample.com`), with an optional port, or `*` for everything:

``` r

Sys.setenv(no_proxy = "127.0.0.1")
r <- zu_get(web$url("/get"))
zu_resp_connection(r)$proxy_used
#> [1] FALSE
Sys.unsetenv("no_proxy")
```

[`zu_info()`](https://pedrobtz.github.io/zuhttp/reference/zu_info.md)
shows what zuhttp found, with credentials redacted, and says so if the
ignored `HTTP_PROXY` is set:

``` r

zu_info()$proxy_env
#> $set
#>               http_proxy 
#> "http://127.0.0.1:38990" 
#> 
#> $ignored_uppercase_http_proxy
#> [1] FALSE
```

To ignore the environment for a client — a client talking to an internal
service, say — use `proxy = FALSE`. (`NULL` means “the default”, which
is to consult the environment.)

``` r

direct <- zu_client(proxy = FALSE)
zu_resp_connection(zu_get(web$url("/get"), client = direct))$proxy_used
#> [1] FALSE
Sys.unsetenv("http_proxy")
```

## Redirects and proxies

The proxy decision is made for every hop of a redirect, not once per
call, so a redirect from a proxied host to one in `no_proxy` goes direct
— and proxy credentials never follow a redirect to a server that is not
the proxy.

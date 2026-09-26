# TLS, certificates and trust

zuhttp does not ship cryptography or a list of trusted certificate
authorities. It uses the TLS implementation and the trust store your
operating system already has: Schannel and the Windows certificate store
on Windows, Apple’s TLS and the Keychain on macOS, and OpenSSL with the
system CA directory elsewhere. A certificate your organisation installs
on its machines is trusted by zuhttp with no configuration, and an OS
security update reaches zuhttp without a new release.

The price is that behaviour follows the platform. This article shows
what you can configure, and how zuhttp tells you — rather than quietly
doing less — when a platform cannot do what you asked.

``` r

library(zuhttp)
zu_tls_backend()
#> [1] "openssl"
```

This article was built with the backend above; what it supports is
reported by
[`zu_info()`](https://pedrobtz.github.io/zuhttp/reference/zu_info.md):

``` r

zu_info()$tls_capabilities
#> [1] "pins"     "tls13"    "ca_file"  "ca_extra"
```

## A local HTTPS server

To show trust decisions without depending on the internet, the examples
use a local HTTPS server ([webfakes](https://webfakes.r-lib.org)) with a
certificate from a certificate authority created just for this article.

Creating the throwaway certificate authority

``` r

ssl <- function(...) system2("openssl", c(...), stdout = FALSE, stderr = FALSE)
d <- tempfile("zuhttp-tls-"); dir.create(d)
f <- function(x) file.path(d, x)

# A certificate authority...
ssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
    "-keyout", f("ca.key"), "-out", f("ca.pem"), "-subj", "/CN=article-CA")
# ...and a server certificate it signs, valid for the name "localhost" only.
writeLines(c("subjectAltName=DNS:localhost", "basicConstraints=CA:FALSE",
             "keyUsage=digitalSignature,keyEncipherment",
             "extendedKeyUsage=serverAuth"), f("leaf.ext"))
ssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", f("leaf.key"),
    "-out", f("leaf.csr"), "-subj", "/CN=localhost")
ssl("x509", "-req", "-in", f("leaf.csr"), "-CA", f("ca.pem"), "-CAkey", f("ca.key"),
    "-CAcreateserial", "-days", "30", "-extfile", f("leaf.ext"), "-out", f("leaf.pem"))
writeLines(c(readLines(f("leaf.pem")), readLines(f("leaf.key"))), f("server.pem"))

free_port <- function() {
  repeat {
    p <- sample(20000:40000, 1)
    s <- try(serverSocket(p), silent = TRUE)
    if (!inherits(s, "try-error")) { close(s); return(p) }
  }
}
port <- free_port()
srv <- webfakes::new_app_process(
  webfakes::httpbin_app(), port = paste0(port, "s"),
  opts = webfakes::server_opts(remote = TRUE, ssl_certificate = f("server.pem")),
  start = TRUE
)
```

``` r

site <- sprintf("https://localhost:%d/get", port)   # the name on the certificate
ca   <- f("ca.pem")                                 # the authority that signed it
```

## Verification is on, and cannot be half-off

A certificate from an authority the system does not trust is refused,
and the condition says why:

``` r

e <- tryCatch(zu_get(site), error = function(e) e)
class(e)[1:2]
#> [1] "zu_tls_certificate_error" "zu_tls_error"
conditionMessage(e)
#> [1] "certificate verification failed for 'localhost': unable to get local issuer certificate"
```

The classes separate the causes, because the fixes differ: an unknown
issuer is `zu_tls_certificate_error`, a certificate for a different name
is `zu_tls_hostname_error`, and a failed negotiation is
`zu_tls_handshake_error`. All are `zu_tls_error`.

## Trusting your own certificate authority

Two settings, deliberately different:

- `ca_extra` **adds** an authority to the system store. The system’s
  authorities are still trusted. This is the usual choice: an internal
  CA alongside the public internet.
- `ca_file` **replaces** the system store. *Only* the authorities in the
  file are trusted, and every public site will fail.

``` r

r <- zu_get(site, tls = zu_tls(ca_extra = ca))
zu_resp_status(r)
#> [1] 200

r <- zu_get(site, tls = zu_tls(ca_file = ca))
zu_resp_status(r)
#> [1] 200
```

Both succeed here, because this server is signed by the one authority
either setting trusts. The difference shows on any other site: with
`ca_file`, a public host that verified a moment ago now fails. The
printed configuration spells out which one you have:

``` r

zu_tls(ca_extra = ca)
#> <zu_tls_config>
#>   ca_extra: /tmp/Rtmp9v0XbN/zuhttp-tls-2002311a303/ca.pem (adds to system trust)
#>   revocation: off
```

Put the setting on a client to apply it to every request:

``` r

internal <- zu_client(tls = zu_tls(ca_extra = ca))
zu_resp_status(zu_get(site, client = internal))
#> [1] 200
```

`ca_file` and `ca_extra` are not available on Windows yet; there they
raise `zu_tls_unsupported_error` rather than falling back to the system
store.

### Certificate files: `.crt`, `.cer`, `.pem`

Both settings take the path to a certificate file, whatever its
extension — your IT department’s `corporate-root.crt` works as it is,
provided it is in **PEM** format: text, starting with
`-----BEGIN CERTIFICATE-----`. A file may hold several certificates one
after another (a bundle), and each is used.

``` r

crt <- f("corporate-root.crt")
invisible(file.copy(ca, crt))
readLines(crt, n = 1)
#> [1] "-----BEGIN CERTIFICATE-----"
zu_resp_status(zu_get(site, tls = zu_tls(ca_extra = crt)))
#> [1] 200
```

The same extension is also used for **DER**, a binary encoding, and a
certificate exported from the Windows certificate manager as `.cer`
often is. zuhttp reads PEM only and says so, with the command that
converts it:

``` r

der <- f("corporate-root-der.crt")
ssl("x509", "-in", ca, "-outform", "der", "-out", der)
zu_get(site, tls = zu_tls(ca_extra = der))
#> Error:
#> ! `ca_extra` has no PEM certificate in it: /tmp/Rtmp9v0XbN/zuhttp-tls-2002311a303/corporate-root-der.crt
#>   It looks like a DER (binary) certificate. zuhttp reads PEM, the text
#>   form starting '-----BEGIN CERTIFICATE-----'. Convert it with:
#>     openssl x509 -inform der -in /tmp/Rtmp9v0XbN/zuhttp-tls-2002311a303/corporate-root-der.crt -out cert.pem
```

## The name must match

The certificate names `localhost`. The same server reached as
`127.0.0.1` is refused, even with the authority trusted, because a valid
certificate for a different name proves nothing about this one:

``` r

by_ip <- sprintf("https://127.0.0.1:%d/get", port)
e <- tryCatch(zu_get(by_ip, tls = zu_tls(ca_extra = ca)), error = function(e) e)
class(e)[1]
#> [1] "zu_tls_hostname_error"
```

## What was negotiated

``` r

r <- zu_get(site, client = internal)
str(zu_resp_connection(r)[c("tls_protocol", "tls_cipher", "trust_backend")])
#> List of 3
#>  $ tls_protocol : chr "TLSv1.3"
#>  $ tls_cipher   : chr "TLS_AES_256_GCM_SHA384"
#>  $ trust_backend: chr "openssl"
```

`trust_backend` names the store that vouched for the certificate. It is
reported separately from the protocol because on macOS the two are
different frameworks.

## Asking for more: refused, never downgraded

Every
[`zu_tls()`](https://pedrobtz.github.io/zuhttp/reference/zu_tls.md)
setting asks for a *stronger* connection. When the platform cannot
provide one, zuhttp raises `zu_tls_unsupported_error` before connecting,
instead of connecting without it. This loop asks for each setting on the
platform that built this page:

``` r

settings <- list(
  pins       = zu_tls(pins = "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
  tls13      = zu_tls(min_version = 13, ca_extra = ca),
  revocation = zu_tls(revocation = TRUE, ca_extra = ca)
)
for (nm in names(settings)) {
  res <- tryCatch(zu_resp_status(zu_get(site, tls = settings[[nm]])),
                  error = function(e) class(e)[1])
  cat(format(nm, width = 11), res, "\n")
}
#> pins        zu_tls_certificate_error 
#> tls13       200 
#> revocation  zu_tls_unsupported_error
```

Where a setting is supported you see a status or a verification error;
where it is not, `zu_tls_unsupported_error`, and no connection was
attempted. The pin above is deliberately wrong, so a platform that pins
reports `zu_tls_pin_error` — the pin was checked and did not match —
which is a different class from “cannot pin”.
[`?zuhttp_tls`](https://pedrobtz.github.io/zuhttp/reference/zuhttp_tls.md)
has the table for every platform.

### Public-key pinning

A pin says: whatever the certificate chain, the server’s key must be
this one. It is checked in addition to normal verification, never
instead of it. The pin is the SHA-256 of the server’s public key, and
`openssl` computes it:

``` r

pin <- system2("sh", c("-c", shQuote(paste(
  "openssl x509 -in", f("leaf.pem"), "-pubkey -noout |",
  "openssl pkey -pubin -outform der |",
  "openssl dgst -sha256 -binary | openssl base64 -A"))), stdout = TRUE)
pin <- paste0("sha256//", pin)

if ("pins" %in% zu_info()$tls_capabilities) {
  zu_resp_status(zu_get(site, tls = zu_tls(ca_extra = ca, pins = pin)))
} else {
  "pinning is not available on this platform yet"
}
#> [1] 200
```

## Turning verification off

`verify = FALSE` disables certificate and hostname checks for a request
or a client. It exists for local development against a self-signed
server; with it, anyone between you and the server can read and change
the traffic.

``` r

zu_resp_status(zu_get(site, verify = FALSE))
#> Warning: verify = FALSE disables certificate AND hostname checking; anyone on
#> the network path can read and alter this request.
#> [1] 200
```

Prefer `ca_extra` with the development server’s certificate: it is one
more line and keeps verification on.

## Revocation

Certificate revocation is **not** checked by default, on any platform —
`zu_info()$revocation_default` says so. Checking it costs an extra
network round trip inside the platform’s trust code, which zuhttp cannot
time out or cancel. `zu_tls(revocation = TRUE)` asks for it where the
platform can do it (macOS and Windows); OpenSSL has no revocation source
of its own and refuses.

## Proxies

HTTPS through a proxy uses `CONNECT`: the proxy relays encrypted bytes
and never sees the content, so certificate checks are between you and
the real server, exactly as without one. The [proxies
article](https://pedrobtz.github.io/zuhttp/articles/proxies.md) has
worked examples.

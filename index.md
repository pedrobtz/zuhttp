# zuhttp

A minimal HTTP/1.1 and HTTP/2 client for R that uses **each platform’s
own TLS stack and trust store** — Schannel on Windows, Network.framework
with `SecTrust` on macOS, system OpenSSL elsewhere — rather than
bundling cryptography or a CA bundle. One R dependency, its sibling
[zujson](https://github.com/pedrobtz/zujson), for JSON.

Install the released version from CRAN:

``` r

install.packages("zuhttp")
```

Or the development version from GitHub:

``` r

# install.packages("pak")
pak::pak("pedrobtz/zuhttp")
```

Every example below is a real request against a public API, and the `#>`
lines are what it actually returns.

``` r

library(zuhttp)

r <- zu_get("https://ipwho.is/8.8.8.8")
zu_resp_status(r)
#> [1] 200
zu_resp_json(r)$country
#> [1] "United States"

# Query parameters are encoded for you.
r <- zu_get("https://ipwho.is/8.8.8.8", query = list(fields = "ip,country,city"))
zu_resp_url(r)
#> [1] "https://ipwho.is/8.8.8.8?fields=ip%2Ccountry%2Ccity"
str(zu_resp_json(r))
#> List of 3
#>  $ ip     : chr "8.8.8.8"
#>  $ country: chr "United States"
#>  $ city   : chr "San Jose"

# `json =` serialises the body and sets Content-Type, unless you set it.
r <- zu_post("https://postman-echo.com/post", json = list(name = "Alice", active = TRUE))
str(zu_resp_json(r)$data)
#> List of 2
#>  $ name  : chr "Alice"
#>  $ active: logi TRUE
```

## Learn more

- [Get started](https://pedrobtz.github.io/zuhttp/articles/zuhttp.html):
  making requests, reading responses, and sending JSON and forms.
- [Trust, scope and
  limits](https://pedrobtz.github.io/zuhttp/articles/trust-and-limits.html):
  why zuhttp uses the platform’s trust store, when `curl` is the better
  choice, the known limitations, and what 0.1.0 promises.
- [TLS, certificates and
  trust](https://pedrobtz.github.io/zuhttp/articles/tls.html),
  [clients](https://pedrobtz.github.io/zuhttp/articles/clients.html),
  [failures](https://pedrobtz.github.io/zuhttp/articles/failures.html),
  [streaming](https://pedrobtz.github.io/zuhttp/articles/streaming.html),
  [proxies](https://pedrobtz.github.io/zuhttp/articles/proxies.html),
  [testing](https://pedrobtz.github.io/zuhttp/articles/testing.html) and
  [debugging](https://pedrobtz.github.io/zuhttp/articles/debugging.html).
- The [function
  reference](https://pedrobtz.github.io/zuhttp/reference/).

## Security

zuhttp has a single maintainer and no inherited security-response
process. That is a real risk for security-critical code: if your project
cannot accept it, use `curl`.

To report a vulnerability, open a private security advisory through
GitHub, or email the maintainer listed in `DESCRIPTION`. There is no
patch SLA yet; one is a 1.0 requirement.

## License

MIT. Vendored components (picohttpparser, a subset of uriparser, and
nghttp2’s library) keep their own licences; see `inst/COPYRIGHTS`.

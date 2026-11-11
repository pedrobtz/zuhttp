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

Straight to disk: the body never passes through memory, and the file
appears at its destination only once it has arrived whole.

``` r

r <- zu_get("https://raw.githubusercontent.com/pedrobtz/zuhttp/main/README.md",
            path = "README-copy.md")
zu_resp_path(r)
#> [1] "README-copy.md"
length(zu_resp_raw(r))
#> [1] 0   # it went to the file, not through memory
```

A client carries defaults; a request overrides them. Connections are
reused across requests to the same origin.

``` r

gh <- zu_client(
  base_url = "https://api.github.com",
  headers  = c(
    Accept = "application/vnd.github+json"
    # , Authorization = paste("Bearer", Sys.getenv("GITHUB_PAT"))
  ),
  retry    = zu_retry(3)
)

zu_resp_json(zu_get("/repos/pedrobtz/zuhttp", client = gh))$language
#> [1] "C"

zu_get("/repos/pedrobtz/zuhttp", client = gh)      # second request, same origin
zu_pool_stats(gh)[["hits"]]
#> [1] 1
```

A failed request raises, and what it raises is a condition you match by
class rather than by parsing a message.

``` r

tryCatch(
  zu_get("/repos/pedrobtz/no-such-repo", client = gh),
  zu_http_client_error = function(e) zu_resp_status(e$response)
)
#> [1] 404
```

JSON goes through [zujson](https://github.com/pedrobtz/zujson), written
for zuhttp, and
[`zu_set_json_backend()`](https://pedrobtz.github.io/zuhttp/reference/zu_set_json_backend.md)
swaps in another implementation.
[`zu_resp_xml()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_json.md)
and
[`zu_resp_html()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_json.md)
parse with [zuxml](https://github.com/pedrobtz/zuxml) and
[zuhtml](https://github.com/pedrobtz/zuhtml) when they are installed,
honouring the response’s charset.

## Learn more

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

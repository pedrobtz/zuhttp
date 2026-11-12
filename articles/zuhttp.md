# Get started with zuhttp

This article walks through the requests most scripts need: fetching a
page, reading the response, and sending data in the two shapes APIs ask
for, JSON and forms. Every example is a real request against a public
API that needs no key.

``` r

library(zuhttp)
```

## Make a request

[`zu_get()`](https://pedrobtz.github.io/zuhttp/reference/zu_methods.md)
sends a request and returns the response. A status of 400 or above
raises an error, so a response you hold is one that succeeded.

``` r

r <- zu_get("https://httpbin.org/get", query = list(q = "zuhttp", page = 2))
r
#> <zu_response [200 OK]>
#> GET https://httpbin.org/get?q=zuhttp&page=2
#> access-control-allow-credentials: true
#> access-control-allow-origin: *
#> access-control-expose-headers: Retry-After, RateLimit, RateLimit-Policy, WWW-Authenticate
#> content-length: 285
#> content-type: application/json
#> x-content-type-options: nosniff
#> date: Thu, 12 Nov 2026 14:45:25 GMT
#> Body: 285 B in memory
#> Total: 205 ms
#> TLS: TLSv1.3
```

The `zu_resp_*()` functions read the parts of a response:

``` r

zu_resp_status(r)
#> [1] 200
zu_resp_url(r)
#> [1] "https://httpbin.org/get?q=zuhttp&page=2"
zu_resp_header(r, "content-type")
#> [1] "application/json"
str(zu_resp_json(r)$args)
#> List of 2
#>  $ page: chr "2"
#>  $ q   : chr "zuhttp"
```

[`zu_resp_text()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_text.md)
gives the body as a string, decoded with the response’s charset, and
[`zu_resp_raw()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_raw.md)
gives the bytes.

## Send JSON

[`zu_post()`](https://pedrobtz.github.io/zuhttp/reference/zu_methods.md)
sends a body. With `json =` the list is serialised for you and
`Content-Type: application/json` is set. httpbin echoes back what it
received, which shows what went over the wire:

``` r

r <- zu_post(
  "https://httpbin.org/post",
  json = list(name = "Alice", package = "zuhttp")
)
str(zu_resp_json(r)$json)
#> List of 2
#>  $ name   : chr "Alice"
#>  $ package: chr "zuhttp"
zu_resp_json(r)$headers[["Content-Type"]]
#> [1] "application/json"
```

Most REST APIs create a resource from a JSON body and answer
`201 Created` with the new record:

``` r

r <- zu_post(
  "https://jsonplaceholder.typicode.com/posts",
  json = list(title = "hello", body = "world", userId = 1)
)
zu_resp_status(r)
#> [1] 201
str(zu_resp_json(r))
#> List of 4
#>  $ title : chr "hello"
#>  $ body  : chr "world"
#>  $ userId: int 1
#>  $ id    : int 101
```

The response need not be JSON. GitHub’s Markdown API, which needs no
token, takes JSON and returns HTML:

``` r

r <- zu_post(
  "https://api.github.com/markdown",
  json = list(text = "**hello** _world_", mode = "markdown")
)
zu_resp_text(r)
#> [1] "<p><strong>hello</strong> <em>world</em></p>\n"
```

## Send a form

Some APIs want `application/x-www-form-urlencoded` instead. Pass
`form =` and zuhttp encodes the fields. Here is a search on Wikipedia’s
API:

``` r

r <- zu_post(
  "https://en.wikipedia.org/w/api.php",
  form = list(
    action = "query",
    list = "search",
    srsearch = "R language",
    srlimit = 3,
    format = "json"
  )
)
hits <- zu_resp_json(r)$query$search
vapply(hits, function(hit) hit$title, character(1))
#> [1] "R (programming language)" "C (programming language)"
#> [3] "R"
```

[`zu_put()`](https://pedrobtz.github.io/zuhttp/reference/zu_methods.md),
[`zu_patch()`](https://pedrobtz.github.io/zuhttp/reference/zu_methods.md)
and
[`zu_delete()`](https://pedrobtz.github.io/zuhttp/reference/zu_methods.md)
take the same `json =`, `form =`, `body =` and `file =` arguments.

## Handle failure

A failed request raises a condition you match by class, not by parsing
its message. An HTTP error carries the response:

``` r

tryCatch(
  zu_get("https://httpbin.org/status/404"),
  zu_http_client_error = function(e) zu_resp_status(e$response)
)
#> [1] 404
```

## Learn more

- [Clients](https://pedrobtz.github.io/zuhttp/articles/clients.md): base
  URLs, shared headers, retries and the connection pool.
- [Failures](https://pedrobtz.github.io/zuhttp/articles/failures.md):
  the condition classes and what each carries.
- [Streaming](https://pedrobtz.github.io/zuhttp/articles/streaming.md):
  writing a body straight to disk, and reading one as it arrives.
- [TLS, certificates and
  trust](https://pedrobtz.github.io/zuhttp/articles/tls.md),
  [proxies](https://pedrobtz.github.io/zuhttp/articles/proxies.md),
  [testing](https://pedrobtz.github.io/zuhttp/articles/testing.md) and
  [debugging](https://pedrobtz.github.io/zuhttp/articles/debugging.md).
- [Trust, scope and
  limits](https://pedrobtz.github.io/zuhttp/articles/trust-and-limits.md):
  why zuhttp uses the platform’s trust store, and when `curl` is the
  better choice.

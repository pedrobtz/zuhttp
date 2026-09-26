# Clients, requests and the rest of HTTP

[`zu_get()`](https://pedrobtz.github.io/zuhttp/reference/zu_methods.md)
and
[`zu_post()`](https://pedrobtz.github.io/zuhttp/reference/zu_methods.md)
cover most scripts. This article covers what comes next: the other
methods and body types, reusable clients that hold a base URL and shared
settings, requests you build first and send later, and the connection
pool behind all of them.

Every request here goes to a local test server — an
[httpbin](https://httpbin.org)-style app from the
[webfakes](https://webfakes.r-lib.org) package, running in a background
R process — so the output is real zuhttp output, and the article builds
with no internet access.

``` r

library(zuhttp)

srv <- webfakes::new_app_process(
  webfakes::httpbin_app(),
  opts = webfakes::server_opts(remote = TRUE, enable_keep_alive = TRUE,
                               num_threads = 4)
)
base <- srv$url()
base
#> [1] "http://127.0.0.1:33471/"
```

httpbin’s endpoints echo the request back as JSON, which makes it easy
to see exactly what was sent. A small helper keeps that readable:

``` r

sent <- function(r) zu_resp_json(r)
```

## The other methods

Every method has a verb, and they share one argument list:

``` r

r <- zu_put(paste0(base, "put"), json = list(id = 7, name = "Ada"))
sent(r)$json
#> $id
#> [1] 7
#> 
#> $name
#> [1] "Ada"

r <- zu_patch(paste0(base, "patch"), json = list(name = "Ada L."))
sent(r)$json
#> $name
#> [1] "Ada L."

zu_resp_status(zu_delete(paste0(base, "delete")))
#> [1] 200
```

[`zu_head()`](https://pedrobtz.github.io/zuhttp/reference/zu_methods.md)
asks for the headers alone — useful to check a resource’s type or
freshness without downloading it. The response has headers and no body:

``` r

r <- zu_head(paste0(base, "html"))
zu_resp_status(r)
#> [1] 200
zu_resp_header(r, "content-type")
#> [1] "text/html"
length(zu_resp_raw(r))
#> [1] 0
```

## Bodies

Four body arguments, mutually exclusive. The semantic ones set the
`Content-Type` for you, unless you set it yourself.

``` r

# A form, as a browser would send it.
r <- zu_post(paste0(base, "post"), form = list(user = "ada", lang = "R"))
sent(r)$form
#> $user
#> [1] "ada"
#> 
#> $lang
#> [1] "R"

# Raw bytes or a string, with the type you choose.
r <- zu_post(paste0(base, "post"), body = "plain text body",
             headers = c("Content-Type" = "text/plain"))
sent(r)$data
#> [1] "plain text body"

# A file, streamed from disk.
f <- tempfile(fileext = ".csv")
write.csv(head(mtcars, 3), f, row.names = FALSE)
r <- zu_post(paste0(base, "post"), file = f)
sent(r)$headers[["Content-Type"]]
#> [1] "application/octet-stream"
nchar(sent(r)$data)
#> [1] 178
```

## Reusable clients

A client holds what a group of requests shares: a base URL, default
headers and query parameters, and policy such as timeouts and retries.
Pass it with `client =` — it is always a named argument.

``` r

api <- zu_client(
  base_url = base,
  headers  = c(Accept = "application/json", "X-Client" = "article"),
  query    = list(lang = "en"),
  timeout  = 10
)
api
#> <zu_client>
#>   base_url:  http://127.0.0.1:33471/
#>   Accept: application/json
#>   X-Client: article
#>   query:     lang=en
#>   timeout: 10
#>   redirects: 10  (default)
#>   verify: TRUE  (default)
#>   max_body: 16777216  (default)
#>   check: TRUE  (default)
#>   decode: TRUE  (default)
#>   retry: off (1 attempt)  (default)
```

Paths are appended to the base URL. It is a join, not RFC 3986
resolution, so a base URL ending in `/v1` keeps its `/v1`:

``` r

r <- zu_get("anything/users", query = list(page = 2), client = api)
sent(r)$url
#> [1] "http://127.0.0.1:33471/anything/users"
sent(r)$headers[c("Accept", "X-Client")]
#> $Accept
#> [1] "application/json"
#> 
#> $`X-Client`
#> [1] "article"
```

### How request settings combine with the client’s

Headers and query parameters **merge**: the request adds to the
client’s, and wins where both set the same name. `NA` removes one the
client set.

``` r

r <- zu_get("headers", headers = c(Accept = "text/csv", "X-Client" = NA),
            client = api)
h <- sent(r)$headers
h[["Accept"]]                # the request's value won
#> [1] "text/csv"
"X-Client" %in% names(h)     # removed for this request
#> [1] FALSE
```

Policy settings — `timeout`, `retry`, `redirects`, `verify` and the rest
— are **replaced** by a request value. `NULL` resets one to the package
default rather than inheriting the client’s.

``` r

zu_resp_status(zu_get("get", timeout = 2, client = api))     # 2 s, this request only
#> [1] 200
zu_resp_status(zu_get("get", timeout = NULL, client = api))  # the package default, not 10 s
#> [1] 200
```

### Deriving clients

[`zu_client_update()`](https://pedrobtz.github.io/zuhttp/reference/zu_client_update.md)
returns a new client and leaves the original alone — the usual way to
add credentials for one part of an API.

``` r

admin <- zu_client_update(api, headers = c(Authorization = "Bearer admin-token"))
sent(zu_get("headers", client = admin))$headers[["Authorization"]]
#> [1] "Bearer admin-token"
"Authorization" %in% names(sent(zu_get("headers", client = api))$headers)
#> [1] FALSE
```

If you prefer the client first, pipe-friendly wrappers read that way:

``` r

api |> zu_client_get("get") |> zu_resp_status()
#> [1] 200
```

## Build a request now, send it later

Everything the verbs do is available as a pipeline over a request
object. No network I/O happens until
[`zu_perform()`](https://pedrobtz.github.io/zuhttp/reference/zu_perform.md),
so a package can build a request in one function, inspect or test it,
and send it in another.

``` r

req <- zu_request("POST", paste0(base, "anything/orders")) |>
  zu_query(dry_run = "true") |>
  zu_headers("Idempotency-Key" = "order-2026-001") |>
  zu_body_json(list(item = "book", qty = 2)) |>
  zu_req_timeout(total = 5)

req
#> <zu_request>
#> POST http://127.0.0.1:33471/anything/orders?dry_run=true
#> Idempotency-Key: order-2026-001
#> Content-Type: application/json
#> Body: JSON, 23 bytes
#> timeout: 5
```

The printed request hides nothing it needs and shows nothing it should
not: credentials would read `<redacted>` (see the [debugging
article](https://pedrobtz.github.io/zuhttp/articles/debugging.md)).
Then:

``` r

r <- zu_perform(req, client = api)
sent(r)$args      # the query: the request's dry_run, the client's lang
#> $lang
#> [1] "en"
#> 
#> $dry_run
#> [1] "true"
sent(r)$json
#> $item
#> [1] "book"
#> 
#> $qty
#> [1] 2
```

`zu_get(url, ...)` and `zu_request("GET", url) |> ... |> zu_perform()`
lower to the same request, so they behave identically.

## Connection reuse

A client keeps a pool of open connections, so a second request to the
same host skips the TCP (and TLS) setup.
[`zu_pool_stats()`](https://pedrobtz.github.io/zuhttp/reference/zu_pool_stats.md)
shows it happening:

``` r

pooled <- zu_client(base_url = base)
for (i in 1:5) zu_get("get", client = pooled)
zu_pool_stats(pooled)[c("hits", "misses", "idle")]
#>   hits misses   idle 
#>      4      1      1
```

One miss opens the connection; the next four reuse it. A connection is
only reused when every setting that affects it matches — host, port,
proxy and the whole TLS configuration — so a request with different
trust settings never rides on a connection made without them. The pool’s
limits are set with
[`zu_pool()`](https://pedrobtz.github.io/zuhttp/reference/zu_pool.md),
and `zu_client(pool = NULL)` turns pooling off.

The pool is also safe across `fork()`: a child process never writes into
a connection its parent owns. For parallel work, use a PSOCK cluster or
`future::plan("multisession")`; on macOS, HTTPS in a forked child raises
`zu_fork_error` rather than crashing
([`?zuhttp_fork`](https://pedrobtz.github.io/zuhttp/reference/zuhttp_fork.md)).

## The default client

The one-shot calls use a package-level default client. Replace it to
change defaults for a whole session;
[`zu_info()`](https://pedrobtz.github.io/zuhttp/reference/zu_info.md)
reports what it is set to.

``` r

old <- zu_set_default_client(zu_client(timeout = 15, headers = c("X-Team" = "data")))
sent(zu_get(paste0(base, "headers")))$headers[["X-Team"]]
#> [1] "data"
zu_info()$default_client$timeout
#> [1] 15
zu_set_default_client(old)   # restore
```

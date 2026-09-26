# Seeing what happened: verbose output, traces, hooks and middleware

When a request misbehaves, the first question is what actually happened
on the wire. zuhttp answers it at several levels of detail: a printed
response, verbose logging, a full event trace, timings and connection
metadata. For behaviour you want every time, there are hooks, which
observe, and middleware, which can change the request.

All of it goes through one redaction policy, so none of it prints your
credentials.

``` r

library(zuhttp)
srv <- webfakes::new_app_process(
  webfakes::httpbin_app(),
  opts = webfakes::server_opts(remote = TRUE, enable_keep_alive = TRUE,
                               num_threads = 4)
)
url <- function(path) srv$url(path)
```

## Printing is safe

A printed request or response shows what you need to recognise it —
method, URL, headers, body size, timing — with secret values replaced:

``` r

req <- zu_request("GET", url("/get")) |>
  zu_query(api_key = "KEY-12345", page = 2) |>
  zu_headers(Authorization = "Bearer s3cret", Accept = "application/json")
req
#> <zu_request>
#> GET http://127.0.0.1:34947/get?api_key=<redacted>&page=2
#> Authorization: <redacted>
#> Accept: application/json
```

The request itself is untouched: redaction happens when formatting, so
the request above still sends the real key and token. The same applies
to error messages and condition objects, which routinely end up in logs
and bug reports.

## Verbose output

[`zu_verbose()`](https://pedrobtz.github.io/zuhttp/reference/zu_verbose.md)
narrates each request as it happens, on standard error so it never mixes
with data a script writes to standard output. Add `trace = TRUE` to see
the phases underneath — DNS, connect, request, headers, body — with
timestamps:

``` r

chatty <- zu_client(hooks = zu_verbose(to = stdout()))
r <- zu_get(url("/gzip"), trace = TRUE, client = chatty)
#> > GET http://127.0.0.1:34947/gzip
#> * 0ms     +0     request.start     http://127.0.0.1:34947/gzip
#> * 0ms     +0     dns.start         127.0.0.1
#> * 0ms     +0     dns.done          127.0.0.1
#> * 0ms     +0     connect.start     127.0.0.1
#> * 0ms     +0     connect.done      127.0.0.1
#> * 0ms     +0     request.sent      GET  (136)
#> * 18ms    +18    headers.received  200  (5)
#> * 18ms    +0     body.chunk        body  (368)
#> * 18ms    +0     request.done        (200)
#> < HTTP 200
#> <   Date: Sat, 26 Sep 2026 06:29:18 GMT
#> <   Content-Type: application/json
#> <   ETag: "3d52b48b"
#> < 368 bytes
#> < 0.019s
```

(`to = stdout()` is only so the output appears in this article.)

## The event trace

With `trace = TRUE` the same events are kept on the response, as a data
frame you can inspect or save:

``` r

r <- zu_get(url("/redirect/1"), trace = TRUE)
zu_resp_trace(r)
#>                event at_ms   n                            detail
#> 1      request.start     0   0 http://127.0.0.1:34947/redirect/1
#> 2          dns.start     0   0                         127.0.0.1
#> 3           dns.done     0   0                         127.0.0.1
#> 4      connect.start     0   0                         127.0.0.1
#> 5       connect.done     0   0                         127.0.0.1
#> 6       request.sent     0 142                               GET
#> 7   headers.received     8   5                               302
#> 8  redirect.followed     8   1        http://127.0.0.1:34947/get
#> 9  connection.reused     8   0                         127.0.0.1
#> 10      request.sent     8 135                               GET
#> 11  headers.received    50   4                               200
#> 12        body.chunk    50 271                              body
#> 13      request.done    50 200
```

A followed redirect appears as an event carrying the resolved target,
and a URL is redacted as it is recorded.

## Timings and connection details

Every response carries its timings, in seconds. A phase that did not
happen is `NA`, not zero — a reused connection has no DNS or connect
time:

``` r

api <- zu_client(base_url = srv$url())
first  <- zu_get("get", client = api)
second <- zu_get("get", client = api)
rbind(first = zu_resp_timings(first), second = zu_resp_timings(second))[
  , c("dns", "connect", "ttfb", "total")]
#>        dns connect  ttfb total
#> first    0       0 0.002 0.002
#> second  NA      NA 0.042 0.042
```

[`zu_resp_connection()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_connection.md)
answers the questions a timing cannot:

``` r

str(zu_resp_connection(first))
#> List of 9
#>  $ reused_connection: logi FALSE
#>  $ remote_ip        : chr "127.0.0.1"
#>  $ tls_protocol     : NULL
#>  $ tls_cipher       : NULL
#>  $ trust_backend    : NULL
#>  $ http_version     : chr "HTTP/1.1"
#>  $ proxy_used       : logi FALSE
#>  $ retries_performed: int 0
#>  $ redirect_count   : int 0
zu_resp_connection(second)$reused_connection
#> [1] TRUE
```

Over HTTPS it also reports the negotiated protocol and cipher, and which
trust store vouched for the certificate.

## What this build can do

[`zu_info()`](https://pedrobtz.github.io/zuhttp/reference/zu_info.md) is
the thing to paste into a bug report: the TLS backend and trust store,
the [`zu_tls()`](https://pedrobtz.github.io/zuhttp/reference/zu_tls.md)
settings this platform supports, the default client, and which proxy
variables are set (with any credentials in them redacted):

``` r

zu_info()
#> zuhttp 0.1.0
#> 
#> HTTP:               HTTP/1.1
#> TLS backend:        openssl
#> Trust:              OpenSSL system defaults
#> Revocation:         off by default
#> zu_tls() supports:  pins, tls13, ca_file, ca_extra
#> Compression:        gzip, deflate
#> IPv6:               yes
#> 
#> Default client
#>   base_url:         (none)
#>   timeout:          30s
#>   verify:           yes
#>   check:            4xx/5xx raise
#>   retry:            off
#>   pool:             max_idle 16, max_per_host 4, idle 30s
#>   proxy:            from the environment
#> 
#> Proxy environment
#>   (nothing set)
```

## Hooks: observe every request

Hooks are functions zuhttp calls at points in a request’s life:
`before_request`, `after_response`, `before_retry` and `after_retry`.
They see a redacted copy of the request and response, and their return
value is ignored — a hook can log, count or time, but cannot change what
is sent. A hook that errors is downgraded to a warning, so observability
never breaks a request.

A simple request log:

``` r

log <- data.frame()
logging <- zu_client(
  base_url = srv$url(),
  hooks = zu_hooks(after_response = function(p) {
    log <<- rbind(log, data.frame(
      method = p$request$method,
      url    = p$request$url,
      status = zu_resp_status(p$response),
      ms     = round(1000 * zu_resp_timings(p$response)[["total"]], 1)
    ))
  })
)
invisible(zu_get("get", client = logging))
invisible(zu_post("post", json = list(a = 1), client = logging))
invisible(zu_get("status/404", check = FALSE, client = logging))
log
#>   method                               url status ms
#> 1    GET        http://127.0.0.1:34947/get    200  2
#> 2   POST       http://127.0.0.1:34947/post    200 44
#> 3    GET http://127.0.0.1:34947/status/404    404 45
```

## Middleware: change requests and responses

Middleware is a function of the request and the next step, returning a
response. It wraps everything below it — including retries, so a
middleware sees one logical request however many attempts it takes. The
first in the list is the outermost.

Adding a header to every request, such as a signature or a request ID:

``` r

add_request_id <- function(req, next_fn) {
  req$headers <- c(req$headers, "X-Request-Id" = sprintf("req-%04d", sample(9999, 1)))
  next_fn(req)
}
signed <- zu_client(base_url = srv$url(), middleware = list(add_request_id))
zu_resp_json(zu_get("headers", client = signed))$headers[["X-Request-Id"]]
#> [1] "req-5293"
```

Middleware can also answer without calling `next_fn` at all. A minimal
in-memory cache:

``` r

cache <- new.env()
cached <- function(req, next_fn) {
  key <- paste(req$method, req$url)
  if (req$method == "GET" && !is.null(cache[[key]])) return(cache[[key]])
  resp <- next_fn(req)
  if (req$method == "GET" && zu_resp_ok(resp)) cache[[key]] <- resp
  resp
}
memo <- zu_client(base_url = srv$url(), middleware = list(cached))
a <- zu_get("uuid", client = memo)
b <- zu_get("uuid", client = memo)   # served from the cache
identical(zu_resp_json(a)$uuid, zu_resp_json(b)$uuid)
#> [1] TRUE
```

Use a hook when you only need to watch, and middleware when you need to
act. Policies zuhttp already has — timeouts, retries, redirects, TLS —
are set with their own arguments, not rebuilt as middleware.

## Redaction, in detail

The same rules apply everywhere output leaves zuhttp: printing, error
messages, hooks, verbose output, traces, cassettes and
[`zu_resp_url()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp.md).

- **Headers:** `Authorization`, `Proxy-Authorization`, `Cookie`,
  `Set-Cookie`, `X-Api-Key` and `X-Auth-Token`.
- **URLs:** any `user:password@` part, and the values of query
  parameters with names like `access_token`, `api_key`, `token`,
  `password` or `client_secret` (matched exactly, so `page_token` is
  left alone).
- **Form bodies:** the same parameter names.

``` r

zu_redact_url("https://user:pw@api.example.com/v1?access_token=abc&page_token=2")
#> [1] "https://api.example.com/v1?access_token=<redacted>&page_token=2"
zu_is_secret_param(c("token", "page_token"))
#> [1]  TRUE FALSE
```

Your API may use its own names. Add them for the session — they extend
the defaults and cannot remove one:

``` r

old <- getOption("zuhttp.redact_params")
zu_redact_params("ticket")
zu_redact_url("https://api.example.com/v1?ticket=T-998877")
#> [1] "https://api.example.com/v1?ticket=<redacted>"
options(zuhttp.redact_params = old)
```

# When requests fail: errors, timeouts, retries and redirects

Requests fail in two different ways, and zuhttp keeps them apart. A
**transport failure** means no usable response arrived: the host did not
resolve, the connection was refused, the certificate was wrong, the
clock ran out. An **HTTP error** means the server answered, and the
answer was no. Both are R conditions with classes you can catch, and
neither is a string you have to parse.

This article runs against two local test servers
([webfakes](https://webfakes.r-lib.org)). One gets two extra endpoints
that fail on purpose, so retries have something to retry:

``` r

library(zuhttp)

app <- webfakes::httpbin_app()
# Handlers run in the server process, so each keeps its own count there.
app$locals$flaky <- 0L
app$locals$orders <- 0L
# Fails twice with "503, try again in 1 second", then succeeds.
app$get("/flaky", function(req, res) {
  n <- req$app$locals$flaky <- req$app$locals$flaky + 1L
  if (n %% 3L != 0L) {
    res$set_status(503L)$set_header("Retry-After", "1")$send("busy")
  } else {
    res$send_json(list(ok = TRUE, attempt = n), auto_unbox = TRUE)
  }
})
# The same, for a POST.
app$post("/flaky-order", function(req, res) {
  n <- req$app$locals$orders <- req$app$locals$orders + 1L
  if (n %% 3L != 0L) res$set_status(503L)$send("busy")
  else res$send_json(list(created = TRUE, attempt = n), auto_unbox = TRUE)
})

srv   <- webfakes::new_app_process(app)
other <- webfakes::new_app_process(webfakes::httpbin_app())  # another origin
url <- function(path) srv$url(path)
```

## HTTP errors are conditions

By default a 4xx or 5xx response raises. The message says what was
attempted, what came back, and what usually fixes it:

``` r

zu_get(url("/status/404"))
#> Error in `zu_perform()`:
#> ! GET http://127.0.0.1:45189/status/404 failed: HTTP 404 Not Found
#>   The server has no such resource. If you are using a client base_url, check the join: base_url and path are concatenated, not resolved.
```

Every zuhttp condition inherits from `zu_error`, and the classes form a
tree, so you catch as broadly or as narrowly as you need:

``` r

e <- tryCatch(zu_get(url("/status/503")), error = function(e) e)
class(e)
#> [1] "zu_http_server_error" "zu_http_status_error" "zu_error"            
#> [4] "error"                "condition"

tryCatch(zu_get(url("/status/404")),
         zu_http_client_error = function(e) "a 4xx: fix the request",
         zu_http_server_error = function(e) "a 5xx: maybe try again")
#> [1] "a 4xx: fix the request"
```

The condition carries structured fields as well as a message, including
the response itself when there is one:

``` r

zu_resp_status(e$response)
#> [1] 503
zu_resp_header(e$response, "content-type")
#> [1] "text/plain"
```

To treat an error status as data instead, turn the check off, per
request or for a whole client, and decide later with
[`zu_resp_check()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_check.md):

``` r

r <- zu_get(url("/status/404"), check = FALSE)
zu_resp_status(r)
#> [1] 404
zu_resp_ok(r)
#> [1] FALSE
tryCatch(zu_resp_check(r), zu_http_status_error = function(e) "checked later")
#> [1] "checked later"
```

## Transport failures

The same tree covers failures below HTTP. Each class names the phase
that failed, which is the first thing to know when debugging one:

``` r

# Nothing listens on this port any more.
closed <- webfakes::new_app_process(webfakes::httpbin_app())
closed_url <- closed$url("/get")
closed$stop()
e <- tryCatch(zu_get(closed_url), error = function(e) e)
class(e)[1]
#> [1] "zu_connect_error"
e$phase
#> [1] "connect"
e$retryable   # a failed connection may well succeed next time
#> [1] TRUE

# Not a URL zuhttp will send.
tryCatch(zu_get("ftp://example.com/file"), zu_url_error = function(e) conditionMessage(e))
#> [1] "not a usable URL: ftp://example.com/file"
```

## Timeouts

`timeout` is a budget in seconds for the whole call: every redirect,
every retry, every backoff between them. When it runs out,
`zu_timeout_error` is raised, however far the request got:

``` r

t0 <- Sys.time()
e <- tryCatch(zu_get(url("/delay/5"), timeout = 1), error = function(e) e)
class(e)[1]
#> [1] "zu_timeout_error"
round(as.numeric(difftime(Sys.time(), t0, units = "secs")), 1)
#> [1] 1
```

The request stopped after about a second, not five. A slow download that
keeps making progress still counts against the same budget, so set
`timeout` with the largest response you expect in mind. There are no
separate connect or inactivity timeouts yet, and name resolution is not
bounded by `timeout` (see
[`?zuhttp_tls`](https://pedrobtz.github.io/zuhttp/reference/zuhttp_tls.md)).

## Retries

Retrying is **off by default**: a client that silently repeats requests
can repeat a payment. Turn it on with a policy:

``` r

r <- zu_get(url("/flaky"), retry = zu_retry(attempts = 3))
zu_resp_json(r)
#> $ok
#> [1] TRUE
#> 
#> $attempt
#> [1] 3
zu_resp_connection(r)$retries_performed
#> [1] 2
```

`attempts` counts the first try, so `attempts = 3` means at most two
retries. Between attempts zuhttp waits: exponential backoff with jitter,
or what the server asks for in `Retry-After` — here, one second — capped
by `max_retry_after` so a server cannot park your session for an hour. A
hook shows each decision as it happens:

``` r

watch <- zu_client(
  retry = zu_retry(attempts = 3),
  hooks = zu_hooks(before_retry = function(ctx) {
    message("retry ", ctx$attempt, " in ", ctx$delay, "s after ", ctx$why)
  })
)
r <- zu_get(url("/flaky"), client = watch)
#> retry 1 in 1s after HTTP 503
#> retry 2 in 1s after HTTP 503
zu_resp_status(r)
#> [1] 200
```

Only failures that might succeed next time are retried: connection
failures, timeouts with budget left, and the statuses 408, 429, 500,
502, 503 and 504. A certificate error or a 404 is never retried.

### A POST is not retried unless you say it is safe

`GET`, `PUT` and `DELETE` are idempotent: sending one twice has the same
effect as sending it once. `POST` is not, so a retry policy does not
apply to it, and the first 503 is the answer:

``` r

e <- tryCatch(
  zu_post(url("/flaky-order"), json = list(item = "book"),
          retry = zu_retry(attempts = 3)),
  error = function(e) e
)
class(e)[1]
#> [1] "zu_http_server_error"
```

When the server makes a POST safe to repeat — most payment and order
APIs do, through an `Idempotency-Key` header — say so on the request.
[`zu_req_retry()`](https://pedrobtz.github.io/zuhttp/reference/zu_req_retry.md)
generates the key and marks the request replay-safe:

``` r

req <- zu_request("POST", url("/flaky-order")) |>
  zu_body_json(list(item = "book")) |>
  zu_req_retry(attempts = 3, idempotency_key = TRUE)
zu_req_replay_safe(req)
#> [1] TRUE
zu_resp_json(zu_perform(req))
#> $created
#> [1] TRUE
#> 
#> $attempt
#> [1] 3
```

## Redirects

zuhttp follows redirects, up to 10 by default, and counts them:

``` r

r <- zu_get(url("/redirect/3"))
zu_resp_url(r)
#> [1] "http://127.0.0.1:45189/get"
zu_resp_connection(r)$redirect_count
#> [1] 3
```

A chain longer than `redirects` is an error rather than a surprise 3xx.
`redirects = 0` asks for the redirect itself:

``` r

zu_get(url("/redirect/3"), redirects = 2)
#> Error in `zu_transport_perform.zu_native_transport()`:
#> ! stopped after 2 redirects, and the server sent another; raise `redirects` if the chain is expected

r <- zu_get(url("/redirect/1"), redirects = 0)
zu_resp_status(r)
#> [1] 302
zu_resp_header(r, "location")
#> [1] "/get"
```

A 303 turns any method into a `GET` and drops the body; 307 and 308 keep
both. That is why a body you want replayed must be rewindable — memory
and files are.

``` r

see_other <- paste0(url("/redirect-to"), "?status_code=303&url=",
                    utils::URLencode(url("/anything"), reserved = TRUE))
zu_resp_json(zu_post(see_other, body = "order"))$method
#> [1] "get"
```

### Credentials stay with their origin

A redirect to a different scheme, host or port drops `Authorization`,
`Cookie` and `Proxy-Authorization`, so a token meant for one server is
never handed to another. Other headers travel on:

``` r

to_other <- paste0(url("/redirect-to"), "?url=",
                   utils::URLencode(other$url("/headers"), reserved = TRUE))
r <- zu_get(to_other, headers = c(Authorization = "Bearer s3cret",
                                  "X-Request-Id" = "abc-123"))
sent <- zu_resp_json(r)$headers
sent[["X-Request-Id"]]
#> [1] "abc-123"
is.null(sent$Authorization)
#> [1] TRUE
```

A redirect from `https://` to `http://` is refused outright with
`zu_redirect_error`.

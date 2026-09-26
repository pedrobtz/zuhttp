# Testing code that makes HTTP requests

Code that talks to a web API is awkward to test: the service may be
slow, rate-limited, need credentials, or be down on the day CRAN checks
your package. zuhttp lets you replace the network at one point — the
client’s **transport** — while everything above it (URL building,
headers, retries, response parsing, error handling) runs for real.

There are three levels, from simplest to most realistic:

| Tool | What it does | Use it for |
|----|----|----|
| `zu_mock_transport(function)` | calls your function for every request | full control, computed replies |
| [`zu_stub()`](https://pedrobtz.github.io/zuhttp/reference/zu_stub.md) | matches requests and returns canned responses | most unit tests |
| [`zu_cassette_transport()`](https://pedrobtz.github.io/zuhttp/reference/zu_cassette_transport.md) | records real traffic once, replays it after | tests shaped like the real API |

``` r

library(zuhttp)
```

## Write functions that accept a client

The one design choice that makes all of this work: functions in your
package take a `client` argument, defaulting to a real one. Tests pass a
different client; users never notice.

``` r

# In your package:
github_client <- function() {
  zu_client(base_url = "https://api.github.com",
            headers = c(Accept = "application/vnd.github+json"))
}

repo_stars <- function(repo, client = github_client()) {
  r <- zu_get(paste0("repos/", repo), client = client)
  zu_resp_json(r)$stargazers_count
}
```

## A mock transport

[`zu_mock_transport()`](https://pedrobtz.github.io/zuhttp/reference/zu_transport.md)
takes a function of the request and returns a response built with
[`zu_response()`](https://pedrobtz.github.io/zuhttp/reference/zu_response.md).
No network is involved:

``` r

fake_github <- zu_mock_transport(function(req) {
  zu_response(200L, c("Content-Type" = "application/json"),
              '{"full_name": "r-lib/httr2", "stargazers_count": 250}')
})
test_client <- zu_client_update(github_client(), transport = fake_github)

repo_stars("r-lib/httr2", client = test_client)
#> [1] 250
```

The function sees the request as zuhttp would send it — after the
client’s base URL, headers and query have been merged — so it can assert
on it too:

``` r

seen <- NULL
spy <- zu_mock_transport(function(req) {
  seen <<- req
  zu_response(200L, body = '{"stargazers_count": 1}')
})
invisible(repo_stars("r-lib/httr2",
                     client = zu_client_update(github_client(), transport = spy)))
seen$method
#> [1] "GET"
seen$url
#> [1] "https://api.github.com/repos/r-lib/httr2"
```

## Stubs: canned responses by pattern

For most tests, list the requests you expect and what each should get
back. A stub matches on method, URL (exact or by `regex`), headers and
body; every criterion you give must match.

``` r

api <- zu_client(
  base_url = "https://api.example.com",
  transport = zu_mock_transport(
    zu_stub(zu_response(200L, body = '[{"id": 1}, {"id": 2}]'),
            method = "GET", regex = "/users$"),
    zu_stub(zu_response(201L, body = '{"id": 3}'),
            method = "POST", regex = "/users$"),
    zu_stub(zu_response(404L, body = "no such user"),
            regex = "/users/[0-9]+$")
  )
)

zu_resp_json(zu_get("users", client = api))$id
#> [1] 1 2
zu_resp_status(zu_post("users", json = list(name = "Ada"), client = api))
#> [1] 201
tryCatch(zu_get("users/99", client = api),
         zu_http_client_error = function(e) "404, as expected")
#> [1] "404, as expected"
```

A request that matches no stub is an error, so a test cannot pass by
accidentally hitting an endpoint you did not plan for:

``` r

zu_get("orders", client = api)
#> Error:
#> ! no zu_stub() matched GET https://api.example.com/orders
#>   3 stub(s) were tried
```

### Testing failure paths

The cases that are hard to provoke against a real server are the ones a
mock makes easy. `times` limits how often a stub may match, so a
sequence of stubs describes a server that fails and then recovers. Here,
a 503 followed by a success tests that retries are wired up:

``` r

flaky <- zu_client(
  transport = zu_mock_transport(
    zu_stub(zu_response(503L), times = 1),
    zu_stub(zu_response(200L, body = "ok"))
  ),
  retry = zu_retry(attempts = 2, base = 0.01)
)
r <- zu_get("https://api.example.com/report", client = flaky)
zu_resp_text(r)
#> [1] "ok"
zu_resp_connection(r)$retries_performed
#> [1] 1
```

And `times = 1` with no fallback asserts the opposite — that a request
is *not* retried. A POST must not be, and if it were, the second attempt
would find no stub:

``` r

once <- zu_client(
  transport = zu_mock_transport(zu_stub(zu_response(503L), times = 1)),
  retry = zu_retry(attempts = 3, base = 0.01)
)
e <- tryCatch(zu_post("https://api.example.com/charge", body = "x", client = once),
              error = function(e) e)
class(e)[1]   # the 503 itself: no second attempt was made
#> [1] "zu_http_server_error"
```

Transport failures can be simulated by raising the condition zuhttp
would raise, with
[`zu_condition()`](https://pedrobtz.github.io/zuhttp/reference/zu_condition.md):

``` r

slow <- zu_client(transport = zu_mock_transport(function(req) {
  stop(zu_condition("zu_timeout_error", "simulated: no response in time"))
}))
tryCatch(repo_stars("r-lib/httr2", client = zu_client_update(github_client(),
                                                             transport = slow$transport)),
         zu_timeout_error = function(e) "handled the timeout")
#> [1] "handled the timeout"
```

## Cassettes: record once, replay forever

A cassette records real responses the first time a request is made and
replays them afterwards, so tests are written against the real service
but run offline. To keep this article offline too, the “real service”
below is a local test server ([webfakes](https://webfakes.r-lib.org)).

``` r

srv <- webfakes::new_app_process(webfakes::httpbin_app())
dir <- file.path(tempdir(), "cassettes")

json_url <- srv$url("/json")

recorder <- zu_client(transport = zu_cassette_transport(dir, "httpbin"))
r <- zu_get(json_url, client = recorder)
zu_resp_json(r)$firstName
#> [1] "John"
```

Now stop the server. In `"replay"` mode the cassette never touches the
network, and a request it has not seen is an error rather than a live
call:

``` r

srv$stop()
player <- zu_client(transport = zu_cassette_transport(dir, "httpbin", mode = "replay"))
zu_resp_json(zu_get(json_url, client = player))$firstName
#> [1] "John"
```

In a package, point `dir` at `tests/testthat/cassettes/`, record once
(`mode = "auto"`, the default, records only what is missing), commit the
files, and CI replays them.

### Cassettes never contain your credentials

A cassette is a file that ends up in version control, so zuhttp removes
credentials before anything is written: secret headers in both
directions, userinfo in URLs, and secret query and form parameters, all
by the same rules used for printing and error messages (see the
[debugging
article](https://pedrobtz.github.io/zuhttp/articles/debugging.md)).

``` r

srv <- webfakes::new_app_process(webfakes::httpbin_app())
rec <- zu_client(transport = zu_cassette_transport(dir, "secrets"),
                 headers = c(Authorization = "Bearer SUPER-SECRET-TOKEN"))
invisible(zu_get(srv$url("/json"), query = list(api_key = "KEY-12345", page = 2),
                 client = rec))
srv$stop()

stored <- zu_cassette_interactions(dir, "secrets")[[1]]
stored$request$url
#> [1] "http://127.0.0.1:37889/json?api_key=<redacted>&page=2"
stored$request$headers[["Authorization"]]
#> [1] "<redacted>"

# And not anywhere in the file's bytes (cassettes are stored uncompressed,
# so a byte search is a real check):
bytes <- readBin(file.path(dir, "secrets.rds"), "raw", 1e6)
length(grepRaw("SUPER-SECRET-TOKEN", bytes, fixed = TRUE))
#> [1] 0
length(grepRaw("KEY-12345", bytes, fixed = TRUE))
#> [1] 0
```

Matching uses the redacted request, so rotating a token does not
invalidate a recorded suite.

One thing redaction cannot do is read a **response body** for you. The
body is stored as the server sent it, so an endpoint that echoes your
request (httpbin’s `/get` does) or *issues* credentials (an OAuth token
endpoint) puts them in the cassette. Record those endpoints with a mock
instead, or check the cassette before committing it.

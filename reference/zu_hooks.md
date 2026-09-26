# Register lifecycle hooks

Hooks are observability (§35.3). They are handed a payload and their
return value is discarded — a hook that could modify the request would
be middleware wearing a disguise, and §31.13 keeps the two apart
deliberately.

## Usage

``` r
zu_hooks(
  before_request = NULL,
  after_response = NULL,
  before_retry = NULL,
  after_retry = NULL
)
```

## Arguments

- before_request:

  Called with `list(request)` before each attempt.

- after_response:

  Called with `list(request, response, attempt)`.

- before_retry:

  Called with `list(request, attempt, delay, why)` before sleeping —
  §33.4 requires that a retry be visible, because a retry nobody can see
  is a latency mystery for whoever debugs it later.

- after_retry:

  Called with `list(request, attempt)` when a retried attempt begins.

## Value

A `zu_hooks` object, for `zu_client(hooks = )`.

## Details

Every payload passes through the §42 redaction filter before a handler
sees it. A trace handler that logs request headers must not be the
mechanism by which a bearer token reaches a log file.

## Examples

``` r
seen <- character()
h <- zu_hooks(before_request = function(p) seen <<- c(seen, p$request$url))
cli <- zu_client(hooks = h,
                 transport = zu_mock_transport(function(r) zu_response(200L)))
invisible(zu_get("https://x.test/a", client = cli))
seen
#> [1] "https://x.test/a"
```

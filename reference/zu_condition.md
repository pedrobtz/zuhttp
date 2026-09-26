# Construct a zuhttp condition

Mostly internal, but exported so that package authors building on zuhttp
can raise conditions their users can catch with the same handlers.

## Usage

``` r
zu_condition(
  code,
  message,
  url = NULL,
  phase = NULL,
  backend = NULL,
  backend_code = NULL,
  request = NULL,
  response = NULL,
  call = sys.call(-1)
)
```

## Arguments

- code:

  Integer code or class name, e.g. `"zu_tls_certificate_error"`.

- message:

  The human-readable message (§34.4: what was attempted, what failed,
  and the most likely fix).

- url:

  Optional URL. It is **redacted** before being stored (§42.2), so a
  condition object can be printed or logged safely.

- phase:

  One of `"dns"`, `"connect"`, `"tls"`, `"write"`, `"ttfb"`, `"read"`,
  `"decode"`, or `NULL`.

- backend, backend_code:

  The platform backend and its native code, where useful. Present but
  never leading (§34.4).

- request, response:

  Objects where they exist.

- call:

  The originating call.

## Value

A condition object inheriting from the §34.1 classes, plus `error` and
`condition`.

## Examples

``` r
cnd <- zu_condition("zu_timeout_error", "the request took too long",
                    url = "https://user:pw@api.example.com/v1",
                    phase = "read")
class(cnd)
#> [1] "zu_timeout_error" "zu_error"         "error"            "condition"       
cnd$url        # redacted: the userinfo is gone
#> [1] "https://api.example.com/v1"

# Raise it, and catch it by any class in its chain.
tryCatch(stop(cnd), zu_error = function(e) conditionMessage(e))
#> [1] "the request took too long"
```

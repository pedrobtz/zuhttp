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

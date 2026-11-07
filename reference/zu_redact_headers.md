# Additional header names to redact

The defaults are `Authorization`, `Proxy-Authorization`, `Cookie`,
`Set-Cookie`, `X-Api-Key` and `X-Auth-Token` (§42.1). This adds to them;
it cannot remove a default. Each call replaces the names registered by
an earlier call, so pass the whole set at once.

## Usage

``` r
zu_redact_headers(...)
```

## Arguments

- ...:

  Header names, or a single character vector.

## Value

The character vector of extra names now registered, invisibly.

## Examples

``` r
old <- getOption("zuhttp.redact_headers")
zu_redact_headers("X-Session")
# Printed requests, traces, cassettes and conditions now hide it:
req <- zu_request("GET", "https://api.example.com")
zu_headers(req, `X-Session` = "abc123")
#> <zu_request>
#> GET https://api.example.com
#> X-Session: <redacted>
options(zuhttp.redact_headers = old)   # restore
```

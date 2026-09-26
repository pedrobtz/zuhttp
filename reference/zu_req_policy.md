# Set request policy

Per-request overrides of the client's policy defaults. Passing `NULL`
resets to the *package* default rather than the client's value (§31.9) —
which is the only way to escape a client default at the request level.

## Usage

``` r
zu_req_timeout(req, total)

zu_req_redirects(req, max)

zu_req_check(req, check = TRUE)
```

## Arguments

- req:

  A `zu_request`.

- total:

  Total seconds for the request, redirects included. A single number
  today; the phase-specific model of §24 will accept richer values
  through the same argument. DNS resolution is not bounded by it (nor by
  Ctrl-C); see
  [zuhttp_tls](https://pedrobtz.github.io/zuhttp/reference/zuhttp_tls.md).

- max:

  Maximum redirects to follow. `0` returns the 3xx response itself.

- check:

  Raise a condition for 4xx and 5xx (§31.14).

## Value

A `zu_request`.

## Examples

``` r
zu_req_timeout(zu_request("GET", "https://example.com"), total = 5)
#> <zu_request>
#> GET https://example.com
#> timeout: 5
```

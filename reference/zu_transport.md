# Transports

A transport is the object that actually performs a request. The default
is the network. `zu_mock_transport()` takes a function of one argument —
the resolved request — and returns whatever that function returns, so
package tests can exercise their own code without a network, a server,
or an internet-dependent CRAN check.

## Usage

``` r
zu_mock_transport(handler = NULL, ...)
```

## Arguments

- handler:

  A function of one argument (a `zu_request` with client configuration
  already merged in) returning a
  [`zu_response()`](https://pedrobtz.github.io/zuhttp/reference/zu_response.md);
  or one or more
  [`zu_stub()`](https://pedrobtz.github.io/zuhttp/reference/zu_stub.md)s,
  which match on method, URL, headers and body (§37).

- ...:

  Further
  [`zu_stub()`](https://pedrobtz.github.io/zuhttp/reference/zu_stub.md)s.

## Value

A transport object, for `zu_client(transport = )`.

## Lifecycle

Experimental (D-65). The testing tools are exported so that package
tests can run without a network, and may still change before 1.0; the
request functions, response accessors and conditions are the stable API.

## Examples

``` r
fake <- zu_mock_transport(function(req) {
  zu_response(status = 200L, body = charToRaw('{"ok":true}'),
              headers = c("Content-Type" = "application/json"))
})
r <- zu_get("https://example.com", client = zu_client(transport = fake))
zu_resp_status(r)
#> [1] 200
zu_resp_json(r)
#> $ok
#> [1] TRUE
#> 
```

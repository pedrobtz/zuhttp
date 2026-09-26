# Perform a request through a transport

The generic exists so that a package can supply its own transport; S3
dispatch is the extension point. Implementations receive a resolved
request and must return a
[`zu_response()`](https://pedrobtz.github.io/zuhttp/reference/zu_response.md).

## Usage

``` r
zu_transport_perform(transport, req)
```

## Arguments

- transport:

  A transport object.

- req:

  A resolved `zu_request`.

## Value

A `zu_response`.

## Examples

``` r
# This is what zu_perform() calls after resolving the request. Calling it
# directly shows the contract: one request in, one zu_response out.
tr <- zu_mock_transport(function(req) zu_response(204L))
r <- zu_transport_perform(tr, zu_request("GET", "https://api.example.com/x"))
zu_resp_status(r)
#> [1] 204
```

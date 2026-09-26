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

# Construct a response

Mostly for mock transports (§31.12) and for tests. Real responses come
back from
[`zu_perform()`](https://pedrobtz.github.io/zuhttp/reference/zu_perform.md).

## Usage

``` r
zu_response(
  status = 200L,
  headers = NULL,
  body = raw(),
  url = NULL,
  tls_version = NULL,
  redirects = 0L
)
```

## Arguments

- status:

  Integer HTTP status.

- headers:

  Named character vector. Repeated names are allowed and are preserved
  (§18.3).

- body:

  A raw vector, or a string (encoded as UTF-8).

- url:

  The final URL.

- tls_version:

  TLS version string, or `NULL` for plain HTTP.

- redirects:

  Number of redirects followed.

## Value

A `zu_response`.

## Lifecycle

Experimental (D-65). The testing tools are exported so that package
tests can run without a network, and may still change before 1.0; the
request functions, response accessors and conditions are the stable API.

## Examples

``` r
zu_response(200L, c("Content-Type" = "text/plain"), "hello")
#> <zu_response [200 OK]>
#> Content-Type: text/plain
#> Body: 5 B in memory
```

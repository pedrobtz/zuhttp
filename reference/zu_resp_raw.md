# The response body, decoded

`zu_resp_raw()` returns the **decoded** bytes. Because
`Accept-Encoding: gzip` is sent by default and decompression is
transparent (§21.2), these are not the bytes that crossed the wire; if
you are checksumming against a server-side hash, perform the request
with `decode = FALSE` and the body will be exactly what the server sent.

## Usage

``` r
zu_resp_raw(resp)
```

## Arguments

- resp:

  A `zu_response`.

## Value

A raw vector.

## Examples

``` r
r <- zu_response(200L, body = "hello")
zu_resp_raw(r)
#> [1] 68 65 6c 6c 6f
rawToChar(zu_resp_raw(r))
#> [1] "hello"
```

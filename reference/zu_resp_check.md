# Raise a condition for an error status

A 4xx raises `zu_http_client_error`, a 5xx raises
`zu_http_server_error`, and both inherit `zu_http_status_error` and
`zu_error` (§34.1). This is what requests do by default; `check = FALSE`
returns the response instead, and this function then lets you decide
later (§31.14).

## Usage

``` r
zu_resp_check(resp)
```

## Arguments

- resp:

  A `zu_response`.

## Value

`resp`, invisibly, if the status is not an error.

## Details

A transport failure and an error status are deliberately different
things: a 404 is a successful HTTP exchange whose answer is "no".

## Examples

``` r
r <- zu_response(404L, url = "https://example.com/missing")
tryCatch(zu_resp_check(r), zu_http_client_error = function(e) conditionMessage(e))
#> [1] "https://example.com/missing failed: HTTP 404 Not Found\n  The server has no such resource. If you are using a client base_url, check the join: base_url and path are concatenated, not resolved."
```

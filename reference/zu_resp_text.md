# The response body as text

Character encoding is decided by this chain (§31.7):

## Usage

``` r
zu_resp_text(resp, encoding = NULL, on_invalid = c("error", "substitute"))
```

## Arguments

- resp:

  A `zu_response`.

- encoding:

  Encoding to assume, overriding the chain above.

- on_invalid:

  `"error"` raises `zu_body_decode_error` on bytes that are not valid in
  the chosen encoding; `"substitute"` opts into lossy conversion. Silent
  corruption is not on the menu.

## Value

A single UTF-8 string.

## Details

1.  `encoding` if you pass one;

2.  the `charset` parameter of `Content-Type`, if
    [`iconv()`](https://rdrr.io/r/base/iconv.html) knows it;

3.  a UTF-8, UTF-16LE or UTF-16BE byte-order mark, which is then
    stripped;

4.  otherwise **UTF-8** — not the ISO-8859-1 that RFC 7231 nominally
    implies. That default is a historical artefact; UTF-8 is right far
    more often, and being wrong the other way produces mojibake users
    blame on the server.

For `application/json`, RFC 8259 mandates UTF-8, so steps 2–4 are
skipped.

The result is always marked UTF-8.

## Examples

``` r
zu_resp_text(zu_response(200L, c("Content-Type" = "text/plain"), "hi"))
#> [1] "hi"
```

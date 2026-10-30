# The response body as parsed JSON, XML or HTML

`zu_resp_json()` parses with `zujson` (see
[`zu_set_json_backend()`](https://pedrobtz.github.io/zuhttp/reference/zu_set_json_backend.md)
to use another implementation). `zu_resp_xml()` and `zu_resp_html()` use
the `zuxml` and `zuhtml` packages, which zuhttp suggests rather than
requires: install the one you need.

## Usage

``` r
zu_resp_json(resp, ...)

zu_resp_xml(resp, ...)

zu_resp_html(resp, ...)
```

## Arguments

- resp:

  A `zu_response`.

- ...:

  Passed to the parser:
  [`zujson::json_parse()`](https://pedrobtz.github.io/zujson/reference/json_parse.html)
  (for example `data_frame = TRUE`),
  [`zuxml::xml_parse()`](https://pedrobtz.github.io/zuxml/reference/xml_parse.html)
  or
  [`zuhtml::html_parse()`](https://pedrobtz.github.io/zuhtml/reference/html_parse.html).

## Value

`zu_resp_json()`: vectors and lists, by `zujson`'s type mapping (an
array of objects stays a list unless `data_frame = TRUE`).
`zu_resp_xml()`: a `zuxml` document. `zu_resp_html()`: a `zuhtml`
document.

## Details

The body's bytes go to the parser as they arrived. A `charset` in
`Content-Type` is passed on as the encoding, which for XML overrides the
document's own declaration, as HTTP intends; without one the parser
reads the byte-order mark or the declaration. JSON is always UTF-8 (RFC
8259). `zu_resp_html()` also passes the response's final URL as the base
for resolving relative links.

An empty body, or one the parser rejects, raises `zu_body_decode_error`
naming the format; the parser's own message comes last (§34.4).

## Examples

``` r
r <- zu_response(200L, c("Content-Type" = "application/json"),
                 '{"name": "Alice", "tags": ["a", "b"]}')
str(zu_resp_json(r))
#> List of 2
#>  $ name: chr "Alice"
#>  $ tags: chr [1:2] "a" "b"

if (requireNamespace("zuxml", quietly = TRUE)) {
  x <- zu_resp_xml(zu_response(200L, c("Content-Type" = "application/xml"),
                               "<feed><title>News</title></feed>"))
  zuxml::xml_text(zuxml::xml_find_first(x, "//title"))
}
#> [1] NA

if (requireNamespace("zuhtml", quietly = TRUE)) {
  h <- zu_resp_html(zu_response(200L, c("Content-Type" = "text/html"),
                                "<title>Hello</title><p>World</p>"))
  zuhtml::html_title(h)
}
#> [1] "Hello"
```

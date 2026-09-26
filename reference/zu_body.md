# Set the request body

`zu_body_json()` serialises with the JSON backend (see
[`zu_set_json_backend()`](https://pedrobtz.github.io/zuhttp/reference/zu_set_json_backend.md))
and sets `Content-Type: application/json`. `zu_body_form()` URL-encodes
and sets `application/x-www-form-urlencoded`. `zu_body_raw()` sends
bytes as given. `zu_body_file()` sends a file's contents.

## Usage

``` r
zu_body_json(req, x, auto_unbox = TRUE)

zu_body_form(req, x)

zu_body_raw(req, x, type = NULL)

zu_body_file(req, path, type = "application/octet-stream")
```

## Arguments

- req:

  A `zu_request`.

- x:

  For `zu_body_json()`, any object the backend can serialise; for
  `zu_body_form()`, a named list; for `zu_body_raw()`, a raw vector or a
  string.

- auto_unbox:

  Passed to the JSON backend. `TRUE` sends `list(a = 1)` as `{"a":1}`
  rather than `{"a":[1]}`, which is what R users nearly always mean.

- type:

  Content type to declare.

- path:

  A file path. The file is read into memory; streaming request bodies
  are §27's, not this stage's.

## Value

A `zu_request`.

## Details

The implied content type is only a default: a header set on the request
or the client always wins (§31.2).

## Examples

``` r
req <- zu_request("POST", "https://example.com/upload")
zu_body_raw(req, charToRaw("hello"))
#> <zu_request>
#> POST https://example.com/upload
#> Body: raw, 5 bytes
```

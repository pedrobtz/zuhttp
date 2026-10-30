# Choose the JSON implementation

`zuhttp` has no hard dependencies.
[`zu_body_json()`](https://pedrobtz.github.io/zuhttp/reference/zu_body.md)
and
[`zu_resp_json()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_json.md)
use `jsonlite` if it is installed, and this replaces it with anything
else.

## Usage

``` r
zu_set_json_backend(encode = NULL, decode = NULL)
```

## Arguments

- encode:

  A function `(x, ...)` returning a single JSON string. Must accept
  `...`, since request-level options are forwarded to it.

- decode:

  A function `(txt, ...)` returning an R object.

## Value

The previous backend, invisibly.

## Examples

``` r
# Any pair of functions will do; a real one would wrap a JSON package,
# e.g. encode = function(x, ...) RcppSimdJson::serialize(x).
old <- zu_set_json_backend(
  encode = function(x, ...) sprintf('{"n":%d}', length(x)),
  decode = function(txt, ...) list(text = txt)
)
req <- zu_body_json(zu_request("POST", "https://api.example.com"), list(1, 2))
rawToChar(req$body)
#> [1] "{\"n\":2}"

zu_set_json_backend(old$encode, old$decode)   # restore
```

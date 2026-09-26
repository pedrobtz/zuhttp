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
if (FALSE) { # \dontrun{
zu_set_json_backend(
  encode = function(x, ...) RcppSimdJson::serialize(x),
  decode = function(txt, ...) RcppSimdJson::fparse(txt)
)
} # }
```

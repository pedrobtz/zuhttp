# The response body as parsed JSON

The response body as parsed JSON

## Usage

``` r
zu_resp_json(resp, ...)
```

## Arguments

- resp:

  A `zu_response`.

- ...:

  Passed to the JSON backend's parser.

## Value

Whatever the backend returns, by default a list.

## See also

[`zu_set_json_backend()`](https://pedrobtz.github.io/zuhttp/reference/zu_set_json_backend.md)
if you would rather not use `jsonlite`.

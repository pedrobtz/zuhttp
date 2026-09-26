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

## Examples

``` r
r <- zu_response(200L, c("Content-Type" = "application/json"),
                 '{"name": "Alice", "tags": ["a", "b"]}')
str(zu_resp_json(r))
#> List of 2
#>  $ name: chr "Alice"
#>  $ tags: chr [1:2] "a" "b"
```

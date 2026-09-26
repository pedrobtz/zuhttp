# Add query parameters

Add query parameters

## Usage

``` r
zu_query(req, ...)
```

## Arguments

- req:

  A `zu_request`.

- ...:

  Named parameters. A value of length \> 1 repeats the key
  (`id = c(1, 2)` becomes `id=1&id=2`); `NULL` or `NA` removes a
  parameter inherited from the client (§31.9).

## Value

A `zu_request`.

## Examples

``` r
zu_query(zu_request("GET", "https://example.com"), q = "HTTP", limit = 20)
#> <zu_request>
#> GET https://example.com?q=HTTP&limit=20
```

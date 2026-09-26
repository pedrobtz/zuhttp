# Add headers

Add headers

## Usage

``` r
zu_headers(req, ...)
```

## Arguments

- req:

  A `zu_request`.

- ...:

  Named header values. A value of `NA` removes a header inherited from
  the client (§31.9); a same-name value replaces it, case-insensitively.

## Value

A `zu_request`.

## Examples

``` r
zu_headers(zu_request("GET", "https://example.com"), Accept = "text/plain")
#> <zu_request>
#> GET https://example.com
#> Accept: text/plain
```

# Redact credentials from a URL

Removes userinfo entirely and replaces the value of any secret query
parameter with `<redacted>` — never with a truncated prefix, which would
be enough to confirm a guess (§42.1).

## Usage

``` r
zu_redact_url(url)
```

## Arguments

- url:

  A character vector of URLs.

## Value

A character vector of the same length.

## Details

Works on text rather than on a parsed URL, because a URL that failed to
parse is exactly the one an error message is about.

## Examples

``` r
zu_redact_url("https://user:pw@api.example.com/v1?api_key=SECRET&page=2")
#> [1] "https://api.example.com/v1?api_key=<redacted>&page=2"
```

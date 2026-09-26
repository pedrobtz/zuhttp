# Additional header names to redact

The defaults are `Authorization`, `Proxy-Authorization`, `Cookie`,
`Set-Cookie`, `X-Api-Key` and `X-Auth-Token` (§42.1). This adds to them;
it cannot remove a default.

## Usage

``` r
zu_redact_headers(...)
```

## Arguments

- ...:

  Header names, or a single character vector.

## Value

The resulting character vector of extra names, invisibly.

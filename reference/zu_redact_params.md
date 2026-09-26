# Additional query parameter names to redact

The defaults are `access_token`, `api_key`, `signature` and `sig`
(§42.1).

## Usage

``` r
zu_redact_params(...)
```

## Arguments

- ...:

  Parameter names, or a single character vector.

## Value

The resulting character vector of extra names, invisibly.

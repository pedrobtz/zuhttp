# Which query parameter names carry a secret value?

Which query parameter names carry a secret value?

## Usage

``` r
zu_is_secret_param(name)
```

## Arguments

- name:

  A character vector of parameter names.

## Value

A logical vector.

## Examples

``` r
# Exact matches only: `token` is secret, `page_token` is not.
zu_is_secret_param(c("token", "page_token", "api_key", "page"))
#> [1]  TRUE FALSE  TRUE FALSE
```

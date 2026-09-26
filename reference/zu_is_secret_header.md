# Which header names carry a secret value?

Which header names carry a secret value?

## Usage

``` r
zu_is_secret_header(name)
```

## Arguments

- name:

  A character vector of header names.

## Value

A logical vector.

## Examples

``` r
zu_is_secret_header(c("Authorization", "cookie", "Accept"))
#> [1]  TRUE  TRUE FALSE
```

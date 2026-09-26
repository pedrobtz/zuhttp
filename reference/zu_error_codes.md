# Error codes used by zuhttp

A named integer vector mapping each condition class to its stable code.
The code is part of the public API; message wording is not.

## Usage

``` r
zu_error_codes()
```

## Value

A named integer vector.

## Examples

``` r
zu_error_codes()[["zu_tls_certificate_error"]]
#> [1] 7
```

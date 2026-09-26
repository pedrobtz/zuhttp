# Is an error code worth retrying?

Is an error code worth retrying?

## Usage

``` r
zu_code_retryable(code)
```

## Arguments

- code:

  An integer code, or the class name of a zuhttp condition.

## Value

`TRUE`, `FALSE`, or `NA` if the code is unknown.

## Examples

``` r
zu_code_retryable("zu_connect_error")          # a transport failure: yes
#> [1] TRUE
zu_code_retryable("zu_tls_certificate_error")  # will not fix itself: no
#> [1] FALSE
zu_code_retryable("not_a_zuhttp_class")        # unknown: NA
#> [1] NA
```

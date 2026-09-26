# Redact a set of headers for display

Returns the headers with secret values replaced. The originals are
untouched: this is for [`print()`](https://rdrr.io/r/base/print.html),
traces and conditions (§42.2). The documented asymmetry is that
`zu_req_headers()` returns real values, because a user asking for their
own header by name is not an accidental disclosure.

## Usage

``` r
zu_redact_headers_for_display(headers)
```

## Arguments

- headers:

  A named character vector or list.

## Value

The same shape, with secret values replaced by `<redacted>`.

## Examples

``` r
zu_redact_headers_for_display(c(Authorization = "Bearer abc123",
                                Accept = "application/json"))
#>      Authorization             Accept 
#>       "<redacted>" "application/json" 
```

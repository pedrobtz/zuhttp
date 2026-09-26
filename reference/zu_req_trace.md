# Record a §35.3 event trace for this request

Record a §35.3 event trace for this request

## Usage

``` r
zu_req_trace(req, trace = TRUE)
```

## Arguments

- req:

  A `zu_request`.

- trace:

  `TRUE` to collect the trace; `FALSE` (the default) to not.

## Value

The request, modified.

## See also

[`zu_resp_trace()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_trace.md)
to read it back.

## Examples

``` r
zu_req_trace(zu_request("GET", "https://example.com"))
#> <zu_request>
#> GET https://example.com
```

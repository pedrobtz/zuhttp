# Redact a form-encoded request body

Redact a form-encoded request body

## Usage

``` r
zu_redact_form(body)
```

## Arguments

- body:

  A single `application/x-www-form-urlencoded` string.

## Value

The redacted string.

## Examples

``` r
zu_redact_form("user=alice&password=hunter2&remember=1")
#> [1] "user=alice&password=<redacted>&remember=1"
```

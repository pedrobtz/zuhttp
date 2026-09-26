# Replace the default client

Replace the default client

## Usage

``` r
zu_set_default_client(client)
```

## Arguments

- client:

  A `zu_client`, or `NULL` to restore the package default.

## Value

The previous default, invisibly.

## Examples

``` r
old <- zu_set_default_client(zu_client(timeout = 5))
zu_set_default_client(old)
```

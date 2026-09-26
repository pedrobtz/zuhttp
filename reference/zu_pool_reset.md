# Close a client's idle connections

Drops every pooled connection without affecting the client's
configuration; the next request opens a fresh one. Useful when a server
has been restarted underneath a long-lived client.

## Usage

``` r
zu_pool_reset(client)
```

## Arguments

- client:

  A `zu_client`.

## Value

`client`, invisibly.

## Examples

``` r
api <- zu_client()
zu_pool_reset(api)
```

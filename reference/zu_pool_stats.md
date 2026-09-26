# Connection reuse counters

The §26.2 counters for a client's pool. `hits` is the number of requests
that reused an existing connection; without it, a pooled client and an
unpooled one are indistinguishable from R, since both simply return
responses.

## Usage

``` r
zu_pool_stats(client)
```

## Arguments

- client:

  A `zu_client`.

## Value

A named numeric vector, or `NULL` if the client has pooling disabled or
has not made a request yet. `discarded_fork` and `forks_detected` count
connections dropped by the §26.4 PID guard.

## See also

[`zu_pool()`](https://pedrobtz.github.io/zuhttp/reference/zu_pool.md),
[`zu_pool_reset()`](https://pedrobtz.github.io/zuhttp/reference/zu_pool_reset.md)

## Examples

``` r
zu_pool_stats(zu_client())
#> NULL
```

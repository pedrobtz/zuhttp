# Connection pool settings

Passed to
[`zu_client()`](https://pedrobtz.github.io/zuhttp/reference/zu_client.md)
as `pool =`. The defaults are §26.2's deliberately conservative ones: a
pool that is slightly too eager to discard costs latency, while one that
is slightly too eager to reuse corrupts responses.

## Usage

``` r
zu_pool(max_idle = 16L, max_per_host = 4L, idle_timeout = 30)
```

## Arguments

- max_idle:

  Maximum idle connections kept across all hosts.

- max_per_host:

  Maximum idle connections for one scheme/host/port.

- idle_timeout:

  Seconds an unused connection may sit in the pool.

## Value

A `zu_pool_config`, for `zu_client(pool = )`. `zu_client(pool = NULL)`
disables reuse entirely, which is what one-shot calls want.

## What is never shared

Two requests reuse a connection only if scheme, host, port, proxy
identity *including credentials*, and the whole TLS configuration match
(§26.1). That is enforced in C, on every acquisition, by comparing the
key field by field — so deriving a client with
[`zu_client_update()`](https://pedrobtz.github.io/zuhttp/reference/zu_client_update.md)
can never cause a request with `verify = FALSE` to travel over a
connection established with verification on, even though the derived
client shares its parent's pool.

## See also

[`zu_pool_stats()`](https://pedrobtz.github.io/zuhttp/reference/zu_pool_stats.md)
to see whether reuse is actually happening.

## Examples

``` r
api <- zu_client(pool = zu_pool(max_idle = 4, idle_timeout = 10))
zu_pool_stats(api)
#> NULL
```

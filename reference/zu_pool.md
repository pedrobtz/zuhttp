# Connection pool settings

Passed to
[`zu_client()`](https://pedrobtz.github.io/zuhttp/reference/zu_client.md)
as `pool =`. The defaults are §26.2's deliberately conservative ones: a
pool that is slightly too eager to discard costs latency, while one that
is slightly too eager to reuse corrupts responses.

## Usage

``` r
zu_pool(
  max_idle = 16L,
  max_per_host = 4L,
  idle_timeout = 30,
  keepalive_time = NULL,
  keepalive_timeout = NULL
)
```

## Arguments

- max_idle:

  Maximum idle connections kept across all hosts.

- max_per_host:

  Maximum idle connections for one scheme/host/port.

- idle_timeout:

  Seconds an unused connection may sit in the pool.

- keepalive_time, keepalive_timeout:

  HTTP/2 keepalive, in seconds (§65.6). An idle HTTP/2 connection silent
  for `keepalive_time` is sent a PING before it is reused, and discarded
  unless the answer arrives within `keepalive_timeout` (default 20); the
  request then opens a new one. This finds a server or middlebox that
  dropped the connection without saying so. `NULL`, the default, sends
  no PING. HTTP/1.1 connections are unaffected.

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

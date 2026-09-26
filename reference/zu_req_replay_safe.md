# Is this request safe to replay?

`TRUE` when §33.1's second condition holds: the method is idempotent, or
the caller declared it replay-safe, or the request carries an
`Idempotency-Key`.

## Usage

``` r
zu_req_replay_safe(req)
```

## Arguments

- req:

  A `zu_request`.

## Value

A logical.

## See also

[`zu_body_rewindable()`](https://pedrobtz.github.io/zuhttp/reference/zu_body_rewindable.md),
which is §33.1's third condition.

## Examples

``` r
zu_req_replay_safe(zu_request("GET", "https://x.test/"))
#> [1] TRUE
zu_req_replay_safe(zu_request("POST", "https://x.test/"))
#> [1] FALSE
```

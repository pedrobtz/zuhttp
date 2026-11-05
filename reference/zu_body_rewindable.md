# Whether a request's body can be replayed

§28.2 makes rewindability a property of the body rather than a
convention, so the retry layer (§33) and the redirect layer (§19.1) can
refuse rather than truncate.

## Usage

``` r
zu_body_rewindable(req)
```

## Arguments

- req:

  A `zu_request`.

## Value

A logical. `TRUE` for an absent body and for any in-memory body; `FALSE`
for a body from
[`zu_body_stream()`](https://pedrobtz.github.io/zuhttp/reference/zu_body.md),
which a function produces once and cannot produce again.

## See also

[`zu_req_replay_safe()`](https://pedrobtz.github.io/zuhttp/reference/zu_req_replay_safe.md)

## Examples

``` r
zu_body_rewindable(zu_request("GET", "https://x.test/"))
#> [1] TRUE
```

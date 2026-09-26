# Can this request's body be replayed?

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

A logical. `TRUE` for an absent body and for any in-memory body, which
is every body this version can construct.

## See also

[`zu_req_replay_safe()`](https://pedrobtz.github.io/zuhttp/reference/zu_req_replay_safe.md)

## Examples

``` r
zu_body_rewindable(zu_request("GET", "https://x.test/"))
#> [1] TRUE
```

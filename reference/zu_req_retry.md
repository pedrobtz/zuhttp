# Per-request retry settings

The only way to make a non-idempotent request retryable.
[`zu_retry()`](https://pedrobtz.github.io/zuhttp/reference/zu_retry.md)
on a client says *how* to retry; this says *whether this particular
request may be*.

## Usage

``` r
zu_req_retry(
  req,
  attempts = 3L,
  replay_safe = NULL,
  idempotency_key = NULL,
  ...
)
```

## Arguments

- req:

  A `zu_request`.

- attempts:

  Total attempts for this request; see
  [`zu_retry()`](https://pedrobtz.github.io/zuhttp/reference/zu_retry.md).

- replay_safe:

  Declare that replaying this request is safe even though its method is
  not idempotent. This is a promise about the server, and only the
  caller can make it.

- idempotency_key:

  `TRUE` to generate an `Idempotency-Key` header, or a string to supply
  one. A request carrying that header is replay-safe by §33.1, because
  the header is the mechanism the payment and API ecosystem standardised
  on for exactly this.

- ...:

  Further
  [`zu_retry()`](https://pedrobtz.github.io/zuhttp/reference/zu_retry.md)
  arguments.

## Value

The request, modified.

## See also

[`zu_retry()`](https://pedrobtz.github.io/zuhttp/reference/zu_retry.md)

## Examples

``` r
req <- zu_request("POST", "https://api.example.com/charges")
# A POST is never retried automatically; this is the opt-in.
req <- zu_req_retry(req, attempts = 3, idempotency_key = TRUE)
zu_req_replay_safe(req)
#> [1] TRUE
```

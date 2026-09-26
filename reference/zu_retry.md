# Retry policy

Retrying is **off by default**: the package default is `attempts = 1`.

## Usage

``` r
zu_retry(
  attempts = 3L,
  backoff = c("exponential", "constant"),
  base = 1,
  max_delay = 60,
  jitter = TRUE,
  retry_after = TRUE,
  max_retry_after = 60,
  attempt_timeout = NULL,
  on = NULL
)
```

## Arguments

- attempts:

  Total attempts *including the first*, so `attempts = 1` means no
  retrying and `attempts = 3` means at most two retries. (An earlier
  draft of the design used `attempts` and `max_attempts` with meanings
  differing by one; there is one name and one meaning.)

- backoff:

  `"exponential"` or `"constant"`.

- base:

  Seconds for the first backoff interval.

- max_delay:

  Ceiling for a single computed backoff, in seconds.

- jitter:

  Randomise each delay over `[0, delay]` ("full jitter"). On by default:
  synchronised retries from many R sessions are a real thundering-herd
  source (§33.3).

- retry_after:

  Honour a `Retry-After` response header.

- max_retry_after:

  Clamp for `Retry-After`, in seconds. A hostile or misconfigured server
  must not be able to pin an R session for hours.

- attempt_timeout:

  Optional per-attempt bound in seconds. The `total` timeout still
  bounds the whole call (§24.3); this bounds one try.

- on:

  Extra HTTP statuses to treat as retryable, beyond §33.2's 408, 429,
  500, 502, 503 and 504.

## Value

A `zu_retry_policy`, for `zu_client(retry = )` or
[`zu_req_retry()`](https://pedrobtz.github.io/zuhttp/reference/zu_req_retry.md).

## See also

[`zu_req_retry()`](https://pedrobtz.github.io/zuhttp/reference/zu_req_retry.md)
for per-request opt-in, including the replay-safety override that a POST
needs.

## Examples

``` r
zu_retry(attempts = 3)
#> <zu_retry_policy>
#>   attempts: 3 (up to 2 retries)
#>   backoff:  exponential, base 1s, max 60s, full jitter
#>   Retry-After honoured, clamped to 60s
zu_client(retry = zu_retry(attempts = 5, max_delay = 10))
#> <zu_client>
#>   timeout: 30  (default)
#>   redirects: 10  (default)
#>   verify: TRUE  (default)
#>   max_body: 16777216  (default)
#>   check: TRUE  (default)
#>   decode: TRUE  (default)
#>   retry: 5 attempts, exponential backoff, honours Retry-After
```

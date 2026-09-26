# TLS and certificate trust settings

TLS and certificate trust settings

## Usage

``` r
zu_tls(
  ca_file = NULL,
  ca_extra = NULL,
  pins = NULL,
  revocation = FALSE,
  min_version = NULL
)
```

## Arguments

- ca_file:

  Path to a PEM bundle that **replaces** the system trust store: only
  these roots are trusted. Matches curl and OpenSSL, and surprises
  people who expect it to add — for that, use `ca_extra`.

- ca_extra:

  Path to a PEM bundle that **adds to** the system trust store: the
  platform's roots are still trusted, plus these. This is the enterprise
  case — a corporate root alongside the public ones.

- pins:

  Public-key pins as `"sha256//<base64>"` strings. Checked **in addition
  to** chain and hostname verification, never instead of it (§14.4). A
  connection must satisfy both.

- revocation:

  Check certificate revocation. **Off by default**, and the default is
  deliberate — see below.

- min_version:

  Minimum TLS version: `12` or `13`.

## Value

A `zu_tls_config` object, for `zu_client(tls = )` or
`zu_get(url, tls = )`.

## Why revocation is off by default

Two measured reasons (§14.5, S0 finding F-4). It costs 7-15x on macOS —
trust evaluation went from ~4-9 ms to ~62 ms, because a positive
response requires an OCSP or CRL fetch. And that fetch happens *inside*
the platform's trust evaluator, which zuhttp neither owns nor can
deadline or cancel: it is invisible to the timeout model and punches a
hole in the cancellation guarantee. Turning it on is a reasonable
choice; making it the default would mean every request carries an
uninterruptible network call nobody asked for.

## Verification is not configured here

Use `verify = FALSE` on the client or the request. It is a merged policy
argument like `timeout`, and having a second place to set it would make
"is this connection verified?" a question with two answers.

## See also

[`zu_info()`](https://pedrobtz.github.io/zuhttp/reference/zu_info.md),
which reports the effective revocation policy.

## Examples

``` r
zu_tls(ca_extra = "corporate-root.pem")
#> <zu_tls_config>
#>   ca_extra: corporate-root.pem (adds to system trust)
#>   revocation: off
zu_tls(pins = "sha256//YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=")
#> <zu_tls_config>
#>   pins:     1
#>   revocation: off
```

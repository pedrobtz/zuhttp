# Which TLS backend was this build linked against?

Which TLS backend was this build linked against?

## Usage

``` r
zu_tls_backend()
```

## Value

A short backend identifier, e.g. `"openssl"`, `"schannel"`,
`"sectransport"`.

## Examples

``` r
zu_tls_backend()
#> [1] "openssl"
```

# What this build of zuhttp can do

Networking diagnostics in one place: which TLS engine is linked, which
store decides trust, whether revocation is checked, what the default
client is configured to do, and what the environment says about proxies.

## Usage

``` r
zu_info()
```

## Value

A `zu_info` list, printed as a report. Fields: `version`, `http`,
`tls_backend`, `trust`, `tls_available`, `revocation_default`,
`tls_capabilities` (the
[`zu_tls()`](https://pedrobtz.github.io/zuhttp/reference/zu_tls.md)
settings this backend honours, from `"pins"`, `"tls13"`, `"ca_file"`,
`"ca_extra"` and `"revocation"`; the others raise
`zu_tls_unsupported_error`), `compression`, `ipv6`, `proxy_env` and
`default_client`.

## Why the TLS engine and the trust store are listed separately

§13.1 splits them deliberately. A build can speak TLS with one library
and decide trust with another — that is exactly what the macOS build
does — and "which store trusted this certificate?" is a question users
genuinely ask when a certificate works in a browser and not here.

## Examples

``` r
zu_info()
#> zuhttp 0.1.0
#> 
#> HTTP:               HTTP/1.1
#> TLS backend:        openssl
#> Trust:              OpenSSL system defaults
#> Revocation:         off by default
#> zu_tls() supports:  pins, tls13, ca_file, ca_extra
#> Compression:        gzip, deflate
#> IPv6:               yes
#> 
#> Default client
#>   base_url:         (none)
#>   timeout:          30s
#>   verify:           yes
#>   check:            4xx/5xx raise
#>   retry:            off
#>   pool:             max_idle 16, max_per_host 4, idle 30s
#>   proxy:            from the environment
#> 
#> Proxy environment
#>   (nothing set)
```

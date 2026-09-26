# Connection metadata

§35.2: what actually happened at the transport layer for this response.
Reported for the **final** hop — after a redirect chain the earlier
connections are gone, and describing one of those would answer a
question nobody asked.

## Usage

``` r
zu_resp_connection(resp)
```

## Arguments

- resp:

  A `zu_response`.

## Value

A named list: `reused_connection`, `remote_ip`, `tls_protocol`,
`tls_cipher`, `trust_backend`, `http_version`, `proxy_used`,
`retries_performed` and `redirect_count`.

## Why the cipher is named and not numbered

`tls_cipher` reads `"ECDHE-ECDSA-CHACHA20-POLY1305"`, not `"0xcca9"`.
The question someone opens this list to ask is whether the connection
has forward secrecy and an AEAD mode, and the name answers it while the
number does not. Secure Transport and Schannel both report a numeric
suite code; it is mapped in C so all three backends say the same kind of
thing.

`trust_backend` is separate from the TLS engine because §13.1 splits
them — on macOS the protocol is Secure Transport and the trust decision
is SecTrust, and "which store trusted this?" is a question users
genuinely arrive with.

## See also

[`zu_resp_timings()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp.md),
[`zu_info()`](https://pedrobtz.github.io/zuhttp/reference/zu_info.md)
for what the build can do.

## Examples

``` r
r <- zu_response(200L)
zu_resp_connection(r)
#> $reused_connection
#> [1] FALSE
#> 
#> $remote_ip
#> NULL
#> 
#> $tls_protocol
#> NULL
#> 
#> $tls_cipher
#> NULL
#> 
#> $trust_backend
#> NULL
#> 
#> $http_version
#> NULL
#> 
#> $proxy_used
#> [1] FALSE
#> 
#> $retries_performed
#> [1] 0
#> 
#> $redirect_count
#> [1] 0
#> 
```

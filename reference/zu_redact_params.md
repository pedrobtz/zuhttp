# Additional query parameter names to redact

The defaults are `access_token`, `api_key`, `apikey`, `signature`,
`sig`, `client_secret`, `password`, `passwd`, `pwd`, `secret`, `token`,
`refresh_token`, `id_token`, `private_key`, `auth_token` and
`session_token`, matched exactly and case-insensitively (§42.1). This
adds to them; it cannot remove a default. Each call replaces the names
registered by an earlier call, so pass the whole set at once.

## Usage

``` r
zu_redact_params(...)
```

## Arguments

- ...:

  Parameter names, or a single character vector.

## Value

The character vector of extra names now registered, invisibly.

## Examples

``` r
old <- getOption("zuhttp.redact_params")
zu_redact_params("ticket")
zu_redact_url("https://api.example.com/v1?ticket=ABC123&page=2")
#> [1] "https://api.example.com/v1?ticket=<redacted>&page=2"
options(zuhttp.redact_params = old)    # restore
```

# The package-managed default client

Used by any request that does not name a client. It is re-created in a
forked child rather than inherited, so a client made in the parent never
hands its connections to
[`parallel::mclapply()`](https://rdrr.io/r/parallel/mclapply.html)
workers (§26.4).

## Usage

``` r
zu_default_client()
```

## Value

A `zu_client`.

## See also

[`zu_set_default_client()`](https://pedrobtz.github.io/zuhttp/reference/zu_set_default_client.md)

## Examples

``` r
zu_default_client()
#> <zu_client>
#>   timeout: 30  (default)
#>   redirects: 10  (default)
#>   verify: TRUE  (default)
#>   max_body: 16777216  (default)
#>   check: TRUE  (default)
#>   decode: TRUE  (default)
#>   retry: off (1 attempt)  (default)
```

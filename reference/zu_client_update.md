# Derive a client from another

Returns a copy with the named fields changed. Clients are values: this
never mutates `client`, so a derived client cannot surprise code still
holding the original (§31.10).

## Usage

``` r
zu_client_update(client, ...)
```

## Arguments

- client:

  A `zu_client`.

- ...:

  Fields to change, named as in
  [`zu_client()`](https://pedrobtz.github.io/zuhttp/reference/zu_client.md).

## Value

A new `zu_client`.

## Examples

``` r
api <- zu_client(base_url = "https://api.example.com")
admin <- zu_client_update(api, headers = c(Authorization = "Bearer xyz"))
identical(api$headers, NULL)   # unchanged
#> [1] TRUE
```

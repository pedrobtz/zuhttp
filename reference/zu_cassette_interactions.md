# Inspect or delete a cassette

Inspect or delete a cassette

## Usage

``` r
zu_cassette_interactions(
  dir = file.path(tempdir(), "zuhttp-cassettes"),
  name = "default"
)

zu_cassette_clear(
  dir = file.path(tempdir(), "zuhttp-cassettes"),
  name = "default"
)
```

## Arguments

- dir, name:

  The cassette's directory and name, as given to
  [`zu_cassette_transport()`](https://pedrobtz.github.io/zuhttp/reference/zu_cassette_transport.md).

## Value

`zu_cassette_interactions()` a list of recorded interactions, each with
`request`, `response` and `recorded_at`, all already redacted;
`zu_cassette_clear()` `TRUE` if a file was removed, invisibly.

## See also

[`zu_cassette_transport()`](https://pedrobtz.github.io/zuhttp/reference/zu_cassette_transport.md)

## Examples

``` r
zu_cassette_interactions(tempdir(), "no-such-cassette")
#> list()
```

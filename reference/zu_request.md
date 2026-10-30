# Build a request without performing it

Method and URL are request identity, so both are given here rather than
configured later (§31.5). The result is an inert value;
[`zu_perform()`](https://pedrobtz.github.io/zuhttp/reference/zu_perform.md)
is the only thing that touches the network.

## Usage

``` r
zu_request(method, url)
```

## Arguments

- method:

  HTTP method. Any token is allowed — `"PROPFIND"` works — and it is
  upper-cased.

- url:

  An absolute URL, or a path to be joined to a client's `base_url` at
  perform time.

## Value

A `zu_request`.

## See also

[`zu_headers()`](https://pedrobtz.github.io/zuhttp/reference/zu_headers.md),
[`zu_query()`](https://pedrobtz.github.io/zuhttp/reference/zu_query.md),
[`zu_body_json()`](https://pedrobtz.github.io/zuhttp/reference/zu_body.md),
[`zu_perform()`](https://pedrobtz.github.io/zuhttp/reference/zu_perform.md)

## Examples

``` r
req <- zu_request("POST", "https://api.example.com/users")
req <- zu_body_json(req, list(name = "Alice"))
req
#> <zu_request>
#> POST https://api.example.com/users
#> Content-Type: application/json
#> Body: JSON, 16 bytes
```

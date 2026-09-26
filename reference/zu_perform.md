# Perform a request

The boundary between building a request and touching the network (§31.1
principle 2). Client configuration is merged into the request here, by
the rules in
[`zu_client()`](https://pedrobtz.github.io/zuhttp/reference/zu_client.md)
and §31.9.

## Usage

``` r
zu_perform(req, client = zu_default_client())
```

## Arguments

- req:

  A `zu_request` from
  [`zu_request()`](https://pedrobtz.github.io/zuhttp/reference/zu_request.md).

- client:

  A `zu_client`. Always named, never positional (§31.3).

## Value

A `zu_response`. By default a 4xx or 5xx status raises a condition
instead; see
[`zu_resp_check()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_check.md)
and `check = FALSE`.

## Examples

``` r
fake <- zu_mock_transport(function(req) zu_response(status = 204L))
zu_perform(zu_request("DELETE", "https://example.com/x"),
           client = zu_client(transport = fake))
#> <zu_response [204 No Content]>
#> DELETE https://example.com/x
#> Body: 0 B in memory
#> Total: 0 ms
```

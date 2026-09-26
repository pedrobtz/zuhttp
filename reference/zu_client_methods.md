# Client-first wrappers

A thin layer for readers who prefer `api |> zu_client_get("/users")`.
These are wrappers, not overloads:
[`zu_get()`](https://pedrobtz.github.io/zuhttp/reference/zu_methods.md)
and friends never accept a client as their first argument (§31.3).

## Usage

``` r
zu_client_get(client, url, ...)

zu_client_head(client, url, ...)

zu_client_post(client, url, ...)

zu_client_put(client, url, ...)

zu_client_patch(client, url, ...)

zu_client_delete(client, url, ...)
```

## Arguments

- client:

  A `zu_client`.

- url:

  A URL or path.

- ...:

  Passed to
  [`zu_get()`](https://pedrobtz.github.io/zuhttp/reference/zu_methods.md)
  and friends.

## Value

A `zu_response`.

## Examples

``` r
fake <- zu_mock_transport(function(req) zu_response(200L, body = "ok"))
api <- zu_client(base_url = "https://api.example.com", transport = fake)
zu_resp_text(zu_client_get(api, "/users"))
#> [1] "ok"
```

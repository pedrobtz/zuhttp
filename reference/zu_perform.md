# Perform a request

The boundary between building a request and touching the network (§31.1
principle 2). Client configuration is merged into the request here, by
the rules in
[`zu_client()`](https://pedrobtz.github.io/zuhttp/reference/zu_client.md)
and §31.9.

## Usage

``` r
zu_perform(req, client = zu_default_client(), stream = FALSE)
```

## Arguments

- req:

  A `zu_request` from
  [`zu_request()`](https://pedrobtz.github.io/zuhttp/reference/zu_request.md).

- client:

  A `zu_client`. Always named, never positional (§31.3).

- stream:

  Return as soon as the response headers have arrived, with the body
  unread, and read it with
  [`zu_resp_read()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_read.md)
  (§65.4). Redirects and retries are complete by then. The connection
  stays with the response until the body is read to its end or
  [`zu_resp_abort()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_read.md)
  is called; a response dropped half-read is aborted when it is
  garbage-collected. Not with
  [`zu_req_path()`](https://pedrobtz.github.io/zuhttp/reference/zu_req_path.md)
  or
  [`zu_req_callback()`](https://pedrobtz.github.io/zuhttp/reference/zu_req_callback.md):
  a body has one destination. `max_body` still bounds the whole body, so
  a long stream needs it raised (`Inf` for no limit).

## Value

A `zu_response`. By default a 4xx or 5xx status raises a condition
instead; see
[`zu_resp_check()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_check.md)
and `check = FALSE`. With `stream = TRUE` the body is not read and the
condition is raised after aborting it.

## Examples

``` r
fake <- zu_mock_transport(function(req) zu_response(status = 204L))
zu_perform(zu_request("DELETE", "https://example.com/x"),
           client = zu_client(transport = fake))
#> <zu_response [204 No Content]>
#> DELETE https://example.com/x
#> Body: 0 B in memory
#> Total: 1 ms
```

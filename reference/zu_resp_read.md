# Read a streamed response body, its trailers, or stop reading

A response from
[`zu_perform()`](https://pedrobtz.github.io/zuhttp/reference/zu_perform.md)
with `stream = TRUE` arrives with its body unread (§65.4).
`zu_resp_read()` returns the next piece of it: up to `n` decoded bytes,
waiting for at least one, and a raw vector of length 0 at the end. Over
HTTP/2 the server is allowed to send only as far ahead as the caller
reads, so a body nobody reads holds the server at one flow-control
window. `max_body` is enforced across the whole body, and every wait is
bounded by the request's `timeout` afresh and interruptible with Ctrl-C.

## Usage

``` r
zu_resp_read(resp, n = 65536)

zu_resp_abort(resp)

zu_resp_trailers(resp, name = NULL)
```

## Arguments

- resp:

  A `zu_response`.

- n:

  Maximum bytes to return.

- name:

  A field name, or `NULL` for all of them.

## Value

`zu_resp_read()` a raw vector; `zu_resp_abort()` `resp`, invisibly;
`zu_resp_trailers()` a named character vector (`name = NULL`) or a
character vector, length 0 when the field is absent, or `NULL` while a
streamed body is unread.

## Details

`zu_resp_abort()` stops reading (§65.5). Over HTTP/2 it resets the
stream (`RST_STREAM(CANCEL)`) and keeps the connection for the next
request; over HTTP/1.1 it closes the connection. A second call, or a
call on a body read to its end, does nothing. A later `zu_resp_read()`
raises `zu_cancelled_error`.

`zu_resp_trailers()` returns the header fields sent after the body:
HTTP/2 trailers, or a chunked HTTP/1.1 body's trailer section (§65.3,
D-91). gRPC carries its status there. Matching is case-insensitive as in
[`zu_resp_header()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp.md).
For a streamed response they are known once `zu_resp_read()` has
returned the end of the body; before that, `zu_resp_trailers()` returns
`NULL`.

A response that was not streamed reads from its stored body, in pieces
of `n`, so code written against `zu_resp_read()` runs against
[`zu_mock_transport()`](https://pedrobtz.github.io/zuhttp/reference/zu_transport.md)
and cassettes unchanged.

## Examples

``` r
fake <- zu_mock_transport(function(req) zu_response(200L, body = charToRaw("hello")))
r <- zu_perform(zu_request("GET", "https://example.com/"),
                client = zu_client(transport = fake), stream = TRUE)
zu_resp_read(r, 3)
#> [1] 68 65 6c
zu_resp_read(r, 3)
#> [1] 6c 6f
zu_resp_read(r, 3)
#> raw(0)
```

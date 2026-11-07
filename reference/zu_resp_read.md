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
`timeout` bounds one call instead: a caller with a deadline for the
whole stream passes what is left of it, and a read that runs out raises
`zu_timeout_error` and ends the body, as any failed read does.

## Usage

``` r
zu_resp_read(resp, n = 65536, timeout = NULL)

zu_resp_abort(resp)

zu_resp_trailers(resp, name = NULL)
```

## Arguments

- resp:

  A `zu_response`.

- n:

  Maximum bytes to return.

- timeout:

  Seconds this call may wait, or `NULL` (the default) for the request's
  `timeout`. A response that was not streamed by its transport never
  waits, and ignores it.

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
returned the end of the body; before that, and after `zu_resp_abort()`
or a failed read, `zu_resp_trailers()` returns `NULL`: the trailers are
unknown, which is not the same as none (D-98).

A response that was not streamed by its transport (a mock, a cassette)
reads from its stored body, in pieces of `n`, and follows the same
rules, trailers included: build one with `zu_response(trailers = )`. So
code written against `zu_resp_read()` runs against
[`zu_mock_transport()`](https://pedrobtz.github.io/zuhttp/reference/zu_transport.md)
and cassettes unchanged. A streamed response has no body to hand to
[`zu_resp_raw()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_raw.md),
[`zu_resp_text()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_text.md)
or
[`zu_resp_json()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_json.md),
which refuse it.

## Examples

``` r
fake <- zu_mock_transport(function(req) zu_response(200L, body = "hello"))
r <- zu_perform(
  zu_request("GET", "https://example.com/"),
  client = zu_client(transport = fake),
  stream = TRUE
)
zu_resp_read(r, 3)
#> [1] 68 65 6c
zu_resp_read(r, 3)
#> [1] 6c 6f
zu_resp_read(r, 3)
#> raw(0)
```

# Set the request body

`zu_body_json()` serialises with the JSON backend (see
[`zu_set_json_backend()`](https://pedrobtz.github.io/zuhttp/reference/zu_set_json_backend.md))
and sets `Content-Type: application/json`. `zu_body_form()` URL-encodes
and sets `application/x-www-form-urlencoded`. `zu_body_raw()` sends
bytes as given. `zu_body_file()` sends a file's contents.

## Usage

``` r
zu_body_json(req, x, auto_unbox = TRUE)

zu_body_form(req, x)

zu_body_raw(req, x, type = NULL)

zu_body_file(req, file, type = "application/octet-stream")

zu_body_stream(req, f, type = "application/octet-stream")
```

## Arguments

- req:

  A `zu_request`.

- x:

  For `zu_body_json()`, any object the backend can serialise; for
  `zu_body_form()`, a named list; for `zu_body_raw()`, a raw vector or a
  string.

- auto_unbox:

  Passed to the JSON backend. `TRUE` sends `list(a = 1)` as `{"a":1}`
  rather than `{"a":[1]}`, which is what R users nearly always mean.

- type:

  Content type to declare.

- file:

  A file path. The file is read into memory; for a body too large for
  that, see `zu_body_stream()`. Named `file` as in
  [`zu_post()`](https://pedrobtz.github.io/zuhttp/reference/zu_methods.md):
  `path` is always where a *response* goes (D-45).

- f:

  For `zu_body_stream()`, a function of no arguments that returns the
  next piece of the body as a raw vector each time it is called, and
  `NULL` at the end.

## Value

A `zu_request`.

## Details

`zu_body_stream()` sends a body produced a piece at a time, for one that
is large or not known in advance (§28, §65.7). Over HTTP/2 each piece
goes out as the server's flow-control window allows, so with
[`zu_perform()`](https://pedrobtz.github.io/zuhttp/reference/zu_perform.md)'s
`stream = TRUE` the response can be read while the body is still being
sent (full duplex, as gRPC's bidirectional calls need). Over HTTP/1.1 it
is sent chunked. Such a body cannot be sent twice: a retry, or a 307 or
308 redirect, raises `zu_body_not_replayable` instead (§28.2), and an
error raised inside `f` stops the request, closes its connection, and is
re-raised unchanged. The implied content type is only a default: a
header set on the request or the client always wins (§31.2).

## Examples

``` r
req <- zu_request("POST", "https://example.com/upload")
zu_body_raw(req, charToRaw("hello"))
#> <zu_request>
#> POST https://example.com/upload
#> Body: raw, 5 bytes

# Three pieces, then the end.
pieces <- list(charToRaw("a"), charToRaw("b"), charToRaw("c"))
i <- 0
zu_body_stream(req, function() {
  i <<- i + 1
  if (i <= length(pieces)) pieces[[i]]
})
#> <zu_request>
#> POST https://example.com/upload
#> Content-Type: application/octet-stream
#> Body: streamed by a function, length unknown
```

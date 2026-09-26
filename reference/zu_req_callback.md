# Stream the response body to a callback

`f` is called with each decoded chunk as a raw vector, as it arrives.
Returning `FALSE` stops the transfer cleanly (§27.2); the connection is
then not reused, because its framing position is no longer known
(§26.3).

## Usage

``` r
zu_req_callback(req, f)
```

## Arguments

- req:

  A `zu_request`.

- f:

  A function of one argument (a raw vector). Return `FALSE` to stop.

## Value

The request, modified.

## If your callback raises an error

You get *your* error, not a transport error wrapping it (§27.3). The
callback runs inside `R_tryCatch()`, the native read loop unwinds
normally so the socket and decompressor are released, and only then is
the original condition re-signalled. That ordering is the whole point: a
longjmp straight out of the read loop would leak the connection.

## What you may not do inside it

Issue another request on the **same** client (§27.4). That would
deadlock on a pool slot or interleave writes onto the connection
currently being read, so it raises an error naming the problem instead.
A request through a *different* client is unrestricted.

## See also

[`zu_req_path()`](https://pedrobtz.github.io/zuhttp/reference/zu_req_path.md)
to stream to a file instead.

## Examples

``` r
total <- 0
req <- zu_req_callback(zu_request("GET", "https://x.test/big"),
                       function(chunk) total <<- total + length(chunk))
```

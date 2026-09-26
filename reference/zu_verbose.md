# Print a trace of each request

Returns hooks that log the request lifecycle, for
`zu_client(hooks = zu_verbose())`.

## Usage

``` r
zu_verbose(to = stderr(), body = TRUE)
```

## Arguments

- to:

  A connection to write to. Defaults to
  [`stderr()`](https://rdrr.io/r/base/showConnections.html), so a trace
  never contaminates data a script is writing to stdout.

- body:

  Show response body sizes.

## Value

A
[`zu_hooks()`](https://pedrobtz.github.io/zuhttp/reference/zu_hooks.md)
object.

## Credentials

A trace cannot leak one, and in two different ways. The request and
response lines come from §35.3 hooks, whose payloads are redacted before
any handler runs, so this function never sees a real `Authorization`
header — there is nothing here to get right or wrong, which is why
verbose logging is implemented as hooks rather than as its own path
through the request. The phase lines from `trace = TRUE` are different:
they are read off the response, so the engine redacts each URL as it
records it (§42.2, D-51). A traced URL therefore shows
`?access_token=<redacted>` rather than the token, and userinfo is
dropped entirely.

## Seeing the whole chain

Pair it with `trace = TRUE` on the request and the §35.3 phases appear —
DNS, connect, TLS handshake, request, headers, body — each with the time
it happened and the gap since the previous one. Without `trace`, the
output is the HTTP layer only.

## See also

[`zu_resp_trace()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_trace.md),
[`zu_hooks()`](https://pedrobtz.github.io/zuhttp/reference/zu_hooks.md)
for your own handlers.

## Examples

``` r
cli <- zu_client(hooks = zu_verbose(),
                 transport = zu_mock_transport(function(r) zu_response(200L)))
invisible(zu_get("https://example.test/x", client = cli))
```

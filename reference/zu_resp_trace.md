# The event trace for a request

§35.3's lifecycle events, in order, when the request was made with
`trace = TRUE`. This is the DNS-to-body view: the phases a timing
summary can only total up.

## Usage

``` r
zu_resp_trace(resp)
```

## Arguments

- resp:

  A `zu_response`.

## Value

A data frame of `event`, `at_ms`, `n` and `detail`, or `NULL` if the
request was not traced. `at_ms` is milliseconds from the start of the
operation, so the gaps between rows are the phases.

## Why a trace is collected rather than streamed

These events happen inside the connect and handshake paths, where an R
error raised from a callback would longjmp past a half-built socket and
a live TLS context — the §27.3 hazard, at six more call sites. A trace
does not need to be live to be useful, so the engine appends to a fixed
log and R renders it afterwards. Tracing off costs one NULL check per
event.

## Credentials

The `detail` of a URL-bearing event is redacted by the engine as it is
recorded (§42.2): userinfo is dropped and a secret query parameter reads
`<redacted>`. It has to happen there rather than here — the trace is
stored on the response, so anything this function could filter would
already have been written down.

## See also

[`zu_resp_timings()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp.md)
for the summary,
[`zu_verbose()`](https://pedrobtz.github.io/zuhttp/reference/zu_verbose.md)
for a printed narration.

## Examples

``` r
# A trace comes from the engine, so there is nothing a mock can stand in
# for here — hence \dontrun{}. An example that reaches a third party is
# one that fails in every offline R CMD check, the user's included.
if (FALSE) { # \dontrun{
r <- zu_get("https://example.com", trace = TRUE)
zu_resp_trace(r)
} # }
```

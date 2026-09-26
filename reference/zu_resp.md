# Response accessors

Response accessors

## Usage

``` r
zu_resp_status(resp)

zu_resp_path(resp)

zu_resp_ok(resp)

zu_resp_headers(resp)

zu_resp_header(resp, name)

zu_resp_url(resp)

zu_resp_method(resp)

zu_resp_timings(resp)
```

## Arguments

- resp:

  A `zu_response`.

- name:

  A header name. Matching is case-insensitive (§18.3).

## Value

`zu_resp_status()` an integer; `zu_resp_ok()` a logical;
`zu_resp_headers()` a named character vector; `zu_resp_header()` a
character vector, length 0 when the header is absent and longer than 1
when it repeats; `zu_resp_url()` the final URL after redirects, with
credentials removed (§42.1: userinfo dropped, and a secret query
parameter shown as `<redacted>` — see the Credentials section);
`zu_resp_path()` the file the body was written to, or `NULL` when it was
not written to one — a response replayed from a cassette or produced by
[`zu_mock_transport()`](https://pedrobtz.github.io/zuhttp/reference/zu_transport.md)
has no file, so it reports `NULL` even if the request asked for a
`path`; `zu_resp_method()` the method actually sent, which a 303 may
have rewritten to `GET`; `zu_resp_timings()` §35.1's nine measurements —
seven phase durations in seconds, then two byte counts. `NA` for a phase
that did not happen, which a pooled connection and a plain http://
request both produce.

## Credentials

`zu_resp_url()` is an egress, so it applies the §42.1 policy in full: a
URL that went out as `?access_token=SECRET` comes back as
`?access_token=<redacted>`, and userinfo is dropped entirely. Redaction
happens in the engine as the URL is recorded, not here, so `resp$url`
holds the redacted string too — there is no unredacted copy to reach
for. That is deliberate: after a redirect chain the final URL is the one
most likely to carry a short-lived token, and a value that exists only
to be pasted into a log should not be the one that leaks. The original
request URL, which the caller already has, is unaffected.

## Examples

``` r
r <- zu_response(200L, c("Set-Cookie" = "a=1", "Set-Cookie" = "b=2"))
zu_resp_header(r, "set-cookie")
#> [1] "a=1" "b=2"
```

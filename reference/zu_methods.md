# Perform a request in one call

The short form. `zu_get(url)` is the whole API for the common case; the
arguments below are the same options
[`zu_client()`](https://pedrobtz.github.io/zuhttp/reference/zu_client.md)
takes, applied to this request only.

## Usage

``` r
zu_get(
  url,
  query = NULL,
  headers = NULL,
  timeout = NULL,
  redirects = NULL,
  verify = NULL,
  max_body = NULL,
  user_agent = NULL,
  check = NULL,
  decode = NULL,
  retry = NULL,
  path = NULL,
  callback = NULL,
  proxy = NULL,
  tls = NULL,
  trace = FALSE,
  client = zu_default_client()
)

zu_head(
  url,
  query = NULL,
  headers = NULL,
  timeout = NULL,
  redirects = NULL,
  verify = NULL,
  max_body = NULL,
  user_agent = NULL,
  check = NULL,
  decode = NULL,
  retry = NULL,
  path = NULL,
  callback = NULL,
  proxy = NULL,
  tls = NULL,
  trace = FALSE,
  client = zu_default_client()
)

zu_post(
  url,
  query = NULL,
  headers = NULL,
  body = NULL,
  json = NULL,
  form = NULL,
  file = NULL,
  timeout = NULL,
  redirects = NULL,
  verify = NULL,
  max_body = NULL,
  user_agent = NULL,
  check = NULL,
  decode = NULL,
  retry = NULL,
  path = NULL,
  callback = NULL,
  proxy = NULL,
  tls = NULL,
  trace = FALSE,
  client = zu_default_client()
)

zu_put(
  url,
  query = NULL,
  headers = NULL,
  body = NULL,
  json = NULL,
  form = NULL,
  file = NULL,
  timeout = NULL,
  redirects = NULL,
  verify = NULL,
  max_body = NULL,
  user_agent = NULL,
  check = NULL,
  decode = NULL,
  retry = NULL,
  path = NULL,
  callback = NULL,
  proxy = NULL,
  tls = NULL,
  trace = FALSE,
  client = zu_default_client()
)

zu_patch(
  url,
  query = NULL,
  headers = NULL,
  body = NULL,
  json = NULL,
  form = NULL,
  file = NULL,
  timeout = NULL,
  redirects = NULL,
  verify = NULL,
  max_body = NULL,
  user_agent = NULL,
  check = NULL,
  decode = NULL,
  retry = NULL,
  path = NULL,
  callback = NULL,
  proxy = NULL,
  tls = NULL,
  trace = FALSE,
  client = zu_default_client()
)

zu_delete(
  url,
  query = NULL,
  headers = NULL,
  body = NULL,
  json = NULL,
  form = NULL,
  file = NULL,
  timeout = NULL,
  redirects = NULL,
  verify = NULL,
  max_body = NULL,
  user_agent = NULL,
  check = NULL,
  decode = NULL,
  retry = NULL,
  path = NULL,
  callback = NULL,
  proxy = NULL,
  tls = NULL,
  trace = FALSE,
  client = zu_default_client()
)
```

## Arguments

- url:

  An absolute URL, or a path joined to the client's `base_url`.

- query:

  Named list of query parameters. Merged with the client's.

- headers:

  Named character vector. Merged with the client's; `NA` removes an
  inherited header.

- timeout:

  Total seconds, redirects included. DNS resolution is not bounded by it
  (nor by Ctrl-C); see
  [zuhttp_tls](https://pedrobtz.github.io/zuhttp/reference/zuhttp_tls.md).

- redirects:

  Maximum redirects to follow.

- verify:

  Verify the certificate and hostname. Leave this `TRUE`.

- max_body:

  Maximum decoded body size in bytes.

- user_agent:

  `User-Agent` to send.

- check:

  Raise a condition for 4xx and 5xx (§31.14). `FALSE` returns the
  response whatever its status.

- decode:

  Decompress transparently. `FALSE` returns the wire bytes and asks the
  server not to encode (§21.2).

- retry:

  A
  [`zu_retry()`](https://pedrobtz.github.io/zuhttp/reference/zu_retry.md)
  policy for this request. Overrides the client's; `NULL` inherits it
  (§31.9).

- path:

  Write the response body to this file instead of holding it in memory
  (§27). The download is written beside the destination and renamed on
  success, so a failed or interrupted transfer never leaves a truncated
  file at `path`. An existing file at `path` is **replaced**, and only
  once the body has arrived whole. Note what that does and does not
  cover: a *transfer* that fails leaves the old file untouched, but a
  request that completes with a non-2xx status is a successful transfer
  of an error page, so a 404 body is written and does replace it —
  `check` raises afterwards, too late to prevent that. Mutually
  exclusive with `callback`: a response body has one destination. Note
  the asymmetry with `file`, which is a request *body* source (§31.6):
  `path` is where the response goes, `file` is where a request body
  comes from.

- callback:

  A function of one argument called with each decoded chunk as it
  arrives (§27). Returning `FALSE` stops the transfer. See
  [`zu_req_callback()`](https://pedrobtz.github.io/zuhttp/reference/zu_req_callback.md)
  for what happens when it raises an error.

- proxy:

  Proxy URL for this request, or `FALSE` for a direct connection. See
  [`zu_client()`](https://pedrobtz.github.io/zuhttp/reference/zu_client.md)
  for why disabling is `FALSE`, not `NULL`.

- tls:

  Certificate trust settings from
  [`zu_tls()`](https://pedrobtz.github.io/zuhttp/reference/zu_tls.md)
  for this request.

- trace:

  Collect a §35.3 event trace, readable with
  [`zu_resp_trace()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_trace.md).
  Off by default.

- client:

  A `zu_client`. Always named.

- body:

  Raw vector or string, sent as-is.

- json:

  An object to serialise as JSON. Sets `Content-Type: application/json`
  unless you set that header yourself.

- form:

  A named list, sent as `application/x-www-form-urlencoded`.

- file:

  A path whose contents become the body.

## Value

A `zu_response`.

## Details

Passing `NULL` for a policy argument resets it to the *package* default
rather than to the client's value — that is the documented way to escape
a client default (§31.9). Omitting it inherits the client's.

## See also

[`zu_request()`](https://pedrobtz.github.io/zuhttp/reference/zu_request.md)
and
[`zu_perform()`](https://pedrobtz.github.io/zuhttp/reference/zu_perform.md)
to build a request without performing it.

## Examples

``` r
if (FALSE) { # \dontrun{
zu_get("https://api.example.com/search", query = list(q = "HTTP", limit = 20))
zu_post("https://api.example.com/users", json = list(name = "Alice"))

# Download straight to disk: the body never passes through memory, and the
# file appears at its destination only once it has arrived whole.
r <- zu_get("https://example.com/big.bin", path = "big.bin")
zu_resp_path(r)                       # "big.bin"
zu_resp_header(r, "content-type")     # the response is still a response

# A non-2xx body is still a body: this raises AND leaves the 404 page at
# out.bin, replacing whatever was there. §27.1's atomicity covers a failed
# transfer, and a 404 is a successful transfer of an error page. Check
# first if the destination matters.
r <- zu_get("https://example.com/missing", path = "out.bin", check = FALSE)
if (zu_resp_ok(r)) file.rename("out.bin", "wanted.bin")
} # }
```

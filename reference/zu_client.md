# Create a reusable client

A client carries what many requests share: a base URL, default headers
and query parameters, policy defaults, and the connection pool. It is
never the first argument of a request function — see below.

## Usage

``` r
zu_client(
  base_url = NULL,
  headers = NULL,
  query = NULL,
  timeout = NULL,
  redirects = NULL,
  verify = NULL,
  max_body = NULL,
  user_agent = NULL,
  check = NULL,
  decode = NULL,
  transport = zu_native_transport(),
  pool = zu_pool(),
  retry = NULL,
  middleware = NULL,
  hooks = NULL,
  proxy = NULL,
  tls = NULL
)
```

## Arguments

- base_url:

  Optional base URL, so that `zu_get("/users", client = api)` works.
  Joining is textual, not RFC 3986 resolution: see Details.

- headers:

  Named character vector of default headers.

- query:

  Named list of default query parameters.

- timeout:

  Total seconds for a request, redirects included. DNS resolution is not
  bounded by it (nor by Ctrl-C); see
  [zuhttp_tls](https://pedrobtz.github.io/zuhttp/reference/zuhttp_tls.md).

- redirects:

  Maximum redirects to follow. `0` returns the 3xx itself.

- verify:

  Verify the certificate and hostname. Leave this `TRUE`.

- max_body:

  Maximum decoded body size in bytes.

- user_agent:

  Default `User-Agent`.

- check:

  Raise a condition for 4xx and 5xx responses (§31.14). `FALSE` returns
  the response whatever its status.

- decode:

  Decompress the body transparently (§21.2).

- transport:

  The object that actually performs requests. Defaults to
  [`zu_native_transport()`](https://pedrobtz.github.io/zuhttp/reference/zu_transport.md);
  [`zu_mock_transport()`](https://pedrobtz.github.io/zuhttp/reference/zu_transport.md)
  replaces the network in tests.

- pool:

  Connection reuse settings from
  [`zu_pool()`](https://pedrobtz.github.io/zuhttp/reference/zu_pool.md),
  or `NULL` to open a fresh connection for every request.

- retry:

  A
  [`zu_retry()`](https://pedrobtz.github.io/zuhttp/reference/zu_retry.md)
  policy. The default retries nothing.

- middleware:

  A function of `(req, next_fn)`, or a list of them, wrapping request
  execution (§31.13). The first is outermost.

- hooks:

  Lifecycle observers from
  [`zu_hooks()`](https://pedrobtz.github.io/zuhttp/reference/zu_hooks.md).

- proxy:

  Proxy URL, e.g. `"http://proxy:3128"`. Leave unset to honour the
  environment (§20.1); pass `FALSE` to force a direct connection. **Not
  `NULL`** — under the §31.9 merge rules `NULL` means "reset to the
  package default", which for a proxy is "consult the environment".
  `FALSE` is the only spelling that can mean "definitely do not proxy"
  without making this one argument an exception to a rule every other
  policy argument follows.

- tls:

  Certificate trust settings from
  [`zu_tls()`](https://pedrobtz.github.io/zuhttp/reference/zu_tls.md).

## Value

A `zu_client` object.

## Details

`base_url` is **joined** to a request path, not resolved against it: a
client with `base_url = "https://api.example.com/v1"` and a request path
of `"/users"` produces `https://api.example.com/v1/users`. RFC 3986
resolution would give `https://api.example.com/users` — the `/v1`
silently dropped — which is the single most common surprise in libraries
that resolve here. An absolute request URL ignores `base_url` entirely.

## The client is never the first argument

`zu_get(url, ..., client = api)`, never `zu_get(api, url)`. Overloading
argument one by type breaks autocomplete, makes dispatch murky, and
turns a misplaced argument into a confusing error instead of a clear one
(§31.3). For client-first phrasing there are thin wrappers:
`api |> zu_client_get("/users")`.

## See also

[`zu_client_update()`](https://pedrobtz.github.io/zuhttp/reference/zu_client_update.md)
to derive a client without mutating it.

## Examples

``` r
api <- zu_client(
  base_url = "https://api.example.com",
  headers  = c(Accept = "application/json")
)
api
#> <zu_client>
#>   base_url:  https://api.example.com
#>   Accept: application/json
#>   timeout: 30  (default)
#>   redirects: 10  (default)
#>   verify: TRUE  (default)
#>   max_body: 16777216  (default)
#>   check: TRUE  (default)
#>   decode: TRUE  (default)
#>   retry: off (1 attempt)  (default)
```

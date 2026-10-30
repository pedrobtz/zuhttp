# zuhttp 0.1.0

First release.

A minimal HTTP/1.1 client that uses the platform's own TLS stack and trust
store — Schannel, Network.framework with `SecTrust`, or system OpenSSL — and
bundles neither cryptography nor a CA bundle. One R dependency, its sibling
`zujson`, for JSON.

## What is in it

* One-shot verbs (`zu_get()`, `zu_post()`, `zu_put()`, `zu_patch()`,
  `zu_delete()`, `zu_head()`) and a composable request pipeline
  (`zu_request()` → `zu_perform()`), which are the same implementation rather
  than two.
* Reusable clients (`zu_client()`) carrying base URL, headers, query, and
  policy defaults, with per-request overrides.
* Response bodies to memory, to a file (`path =`), or to a callback
  (`callback =`), the last two without holding the body in memory.
* Connection pooling with keep-alive, and a PID guard that drops connections
  inherited across `fork()`.
* Redirects with method rewriting and cross-origin credential stripping
  (up to 10 by default; a longer chain raises `zu_too_many_redirects`);
  transparent gzip and deflate under explicit limits: 16 MiB of decoded body,
  and at most 1000 bytes out per compressed byte, so a decompression bomb
  fails after kilobytes rather than megabytes. Either raises
  `zu_body_limit_error`.
* A total timeout across a redirect chain, and Ctrl-C cancellation that
  unwinds without leaking sockets or TLS contexts. Neither bounds DNS
  resolution, which is synchronous.
* Retry policies, middleware, and observability hooks.
* JSON request and response bodies through `zujson` (`json =`,
  `zu_body_json()`, `zu_resp_json()`), replaceable with
  `zu_set_json_backend()`; XML and HTML responses through `zuxml` and
  `zuhtml` when installed (`zu_resp_xml()`, `zu_resp_html()`), with the
  response's charset honoured.
* Structured conditions (`zu_tls_certificate_error`, `zu_timeout_error`,
  `zu_fork_error`, …) rather than parsed message strings.
* On macOS the TLS engine is Network.framework, with trust still decided by
  `SecTrustEvaluateWithError`: TLS 1.3, and DNS and connection setup that
  `timeout` and Ctrl-C both interrupt. It replaced Secure Transport, which
  Apple deprecated, before this release.
* A `zu_tls()` setting the linked backend cannot honour — pins, TLS 1.3, a
  custom CA, or revocation — raises `zu_tls_unsupported_error` before any
  connection, rather than connecting without it. `zu_info()$tls_capabilities`
  lists what the build supports.
* Credential redaction applied at every output path — printing, conditions,
  traces, verbose logging, recordings, and `zu_resp_url()`.
* `zu_mock_transport()` and a record/replay cassette transport, so packages
  depending on `zuhttp` can test offline.
* Per-phase timings and an event trace (`zu_resp_trace()`, `zu_verbose()`),
  and `zu_info()` for a bug-report-ready configuration dump.

## API surface

63 exported functions. Every condition inherits `zuhttp_error`,
directly above `error`, so `tryCatch(..., zuhttp_error = )` catches anything
zuhttp raises and nothing else. The testing tools — `zu_mock_transport()`,
`zu_stub()`, `zu_response()` and the cassette functions — are experimental
and may still change before 1.0; the rest is the stable API.

Trimmed before this release, from the development version some packages may
have used: the client-first wrappers `zu_client_get()` and friends (use
`zu_get(url, client = api)`), and `zu_transport_perform()`,
`zu_native_transport()`, `zu_error_codes()`, `zu_code_retryable()`,
`zu_is_secret_header()`, `zu_is_secret_param()`, `zu_redact_form()` and
`zu_redact_headers_for_display()`, which are now internal.

## Fixed before release

* **A redirect to another origin no longer carries credentials.**
  `Authorization`, `Cookie` and `Proxy-Authorization` set by the caller were
  re-sent on every hop, including to a different host, port or scheme. They
  are now dropped at the first cross-origin hop and stay dropped for the rest
  of the chain.
* The `Host` header includes the port when it is not the scheme's default.
* A redirect chain longer than `redirects` raises `zu_too_many_redirects`
  instead of returning its last 3xx as if it were the final response.
  `redirects = 0` still returns the 3xx itself.
* An HTTP status missing from zuhttp's table of status texts (412, 451, a
  proxy's 407, ...) crashed `zu_resp_check()` with "subscript out of bounds"
  instead of raising `zu_http_client_error` or `zu_http_server_error`.
* A 407 from a proxy on a plain `http://` request is `zu_proxy_auth_error`,
  the class the same failure already had over `https://`.
* `ca_file` and `ca_extra` explain a certificate file that is not PEM, and
  show the `openssl` command that converts a DER (binary) `.crt` or `.cer`;
  the backends' own message was "cannot read CA file".
* A printed client shows its retry policy and TLS configuration as readable
  lines rather than their fields pasted together.
* `zu_resp_timings()` no longer reports a `total` shorter than one of its own
  phases on very fast requests.
* A connection on which the server sent bytes beyond a response's declared
  length (or after a chunked body, or on a response that has no body) is no
  longer returned to the pool. Those bytes were already discarded, but the
  connection was out of step with its responses, so the next request on it
  could have read an answer to a question it never asked.
* A time limit reached during a request (`setTimeLimit()`,
  `R.utils::withTimeout()`) surfaces as its own error. It used to be printed
  to the console, discarded, and reported as `zu_interrupted_error`
  ("interrupted by the user"), so `withTimeout()` never saw it. A real Ctrl-C
  is still `zu_interrupted_error`.

* The default `User-Agent` is `zuhttp/<version>`; it said `zuhttp/0.0.0.9000`.
* A response header value that is not valid UTF-8 (a Latin-1 filename, say)
  arrives marked Latin-1. It was marked UTF-8, so `nchar()`, `grepl()` and
  `print()` failed on it.
* A request header longer than 8 KB (a large bearer token) is sent; it was
  refused as `zu_body_limit_error`. A header with CR, LF or another control
  character is refused as `zu_http_parse_error` before connecting, naming the
  header and never its value.
* `zu_resp_connection()` reports `proxy_used` and `remote_ip` for a reused
  connection too; both were reset on every pool hit.
* A redirect back to a URL already requested raises `zu_redirect_error` at
  once, rather than after `redirects` round trips.
* A client with `pool = NULL` sends `Connection: close`.
* `verify`, `check` and `decode` must be `TRUE` or `FALSE`. `verify = NA` used
  to turn verification off with only a warning, and `check = NA` and
  `decode = NA` turned theirs off silently.
* `max_body = Inf` means no limit, and `zu_pool(idle_timeout = Inf)` keeps
  connections as long as the server does; the second used to mean 30 seconds.
* A `before_request`, `before_retry` or `after_response` hook no longer sees
  a form body's secret fields.
* On OpenSSL, a server that closes the connection without a TLS
  `close_notify` ends the body as on the other backends, rather than failing
  as `zu_closed`, a class that was not part of the condition tree; a closed
  connection is now always `zu_io_error`. A pooled connection whose server
  had already closed it is no longer reused.
* On Windows, a response whose server closes the connection straight after
  it (`Connection: close`, or a server that always does) is delivered; its
  last bytes were discarded when they arrived with the TLS `close_notify`,
  as `zu_http_parse_error` "connection closed before the response headers
  ended".
* On OpenSSL, a failed HTTPS request (an expired certificate, say) no longer
  makes the next request on a pooled connection fail with that same error.
* Retry jitter and `zu_req_retry(idempotency_key = TRUE)` no longer advance
  the session's random number stream, and parsing a `Retry-After` date no
  longer switches `LC_TIME` for the whole session.
* `zu_body_file()` takes `file =` rather than `path =`, as `zu_post()` does,
  and `zu_req_callback()` takes `callback =` rather than `f =`: in zuhttp
  `path` is always where a response goes.

## Known limitations

See the README. In brief: TLS 1.2 maximum on Windows; pinning on OpenSSL
only; no custom CA on Windows; HTTPS through a proxy needs macOS 14 on macOS;
revocation off by default and refused on OpenSSL; a single total timeout,
which DNS resolution ignores outside HTTPS on macOS; HTTPS in a forked child
raises on macOS; and no parallel or asynchronous requests.

## Not in this release

Asynchronous and parallel requests, R connection sinks, and client
certificates are deferred to 0.2.0. HTTP/2, Brotli, zstd and Unix-domain
sockets are not planned.

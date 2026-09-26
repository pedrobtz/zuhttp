# zuhttp 0.1.0

First release.

A minimal HTTP/1.1 client that uses the platform's own TLS stack and trust
store — Schannel, Secure Transport with `SecTrust`, or system OpenSSL — and
bundles neither cryptography nor a CA bundle. No hard R dependencies.

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
  transparent gzip and deflate under explicit size limits.
* A total timeout across a redirect chain, and Ctrl-C cancellation that
  unwinds without leaking sockets or TLS contexts. Neither bounds DNS
  resolution, which is synchronous.
* Retry policies, middleware, and observability hooks.
* Structured conditions (`zu_tls_certificate_error`, `zu_timeout_error`,
  `zu_fork_error`, …) rather than parsed message strings.
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

## Known limitations

See the README. In brief: TLS 1.2 maximum on macOS and Windows; pinning on
OpenSSL only; no custom CA on Windows; revocation off by default and refused
on OpenSSL; a single total timeout, which DNS resolution ignores; HTTPS in a
forked child raises on macOS; and no parallel or asynchronous requests.

## Not in this release

Asynchronous and parallel requests, R connection sinks, and client
certificates are deferred to 0.2.0. HTTP/2, Brotli, zstd and Unix-domain
sockets are not planned.

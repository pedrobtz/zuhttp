# zuhttp

<!-- badges: start -->
[![R-CMD-check](https://github.com/pedrobtz/zuhttp/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/pedrobtz/zuhttp/actions/workflows/R-CMD-check.yaml)
[![c-core](https://github.com/pedrobtz/zuhttp/actions/workflows/c-core.yaml/badge.svg)](https://github.com/pedrobtz/zuhttp/actions/workflows/c-core.yaml)
[![fuzz](https://github.com/pedrobtz/zuhttp/actions/workflows/fuzz.yaml/badge.svg)](https://github.com/pedrobtz/zuhttp/actions/workflows/fuzz.yaml)
![coverage](https://raw.githubusercontent.com/pedrobtz/zuhttp/develop/.github/badges/coverage.svg)
<!-- badges: end -->

A minimal HTTP/1.1 client for R that uses **each platform's own TLS stack and
trust store** — Schannel on Windows, Secure Transport with `SecTrust` on macOS,
system OpenSSL elsewhere — rather than bundling cryptography or a CA bundle.
Zero hard R dependencies.

```r
# install.packages("remotes")
remotes::install_github("pedrobtz/zuhttp")
```

```r
library(zuhttp)

r <- zu_get("https://api.example.com/search", query = list(q = "HTTP", limit = 20))
zu_resp_status(r)
zu_resp_json(r)

zu_post("https://api.example.com/users", json = list(name = "Alice", active = TRUE))

# Straight to disk: the body never passes through memory, and the file
# appears at its destination only once it has arrived whole.
zu_get("https://example.com/big.bin", path = "big.bin")
```

A client carries defaults; a request overrides them.

```r
api <- zu_client(
  base_url = "https://api.example.com",
  headers  = c(Authorization = paste("Bearer", Sys.getenv("API_TOKEN"))),
  retry    = zu_retry(3)
)
zu_get("/users/7", client = api)
```

## Why this rather than `curl`

Because the trust decision is the platform's. There is no bundled CA bundle to
go stale, and no vendored TLS library to track for CVEs — an enterprise MDM
root or a corporate proxy CA already installed on the machine simply works.
The package is small enough to audit, and its behaviour under malformed input
is fuzzed rather than assumed.

**When `curl` is the better choice**, stated plainly rather than left to
inference:

- Anything needing HTTP/2, HTTP/3, or a non-HTTP protocol.
- Anything needing NTLM, Kerberos, or cloud-provider request signing.
- Anything relying on libcurl's decade of workarounds for badly behaved servers.
- **Any project that cannot accept a single-maintainer dependency for
  security-critical code.** `curl` inherits libcurl's security response;
  `zuhttp` has none to inherit. See [Security](#security).
- Forked parallelism with HTTPS on macOS — see below.

Choosing `curl` after reading that list is a reasonable decision.

## Known limitations

These are documented limits, not open defects. Each is a consequence of using
the platform's TLS stack instead of shipping one.

| Limitation | Where | Detail |
|---|---|---|
| TLS 1.2 maximum | macOS, Windows | Secure Transport has no TLS 1.3 constant; the Schannel build in Rtools lacks `SCH_CREDENTIALS`. `zu_tls(min_version = 13)` **raises** rather than silently giving you 1.2. `?zuhttp_tls` |
| No certificate pinning | macOS | Security.framework will not yield the SubjectPublicKeyInfo without hand-parsing DER. Pinning raises rather than silently comparing the wrong bytes. |
| No additive custom CA | Windows | `ca_extra` is not yet implemented on Schannel. `ca_file` (replace) works everywhere. |
| HTTPS in a forked child fails | macOS | The system trust evaluator does not survive `fork()`. Raises `zu_fork_error` instead of killing the worker. Use a `PSOCK` cluster or `future::plan("multisession")`. `?zuhttp_fork` |
| Revocation off by default, and opting in is backend-dependent | all | No platform checks revocation by default. `zu_tls(revocation = TRUE)` opts in, but on OpenSSL it currently fails *every* chain (a CRL check with no CRL source), and on macOS it also rejects valid certificates from CAs that no longer answer revocation queries. `?zuhttp_tls` |
| No parallel or async requests | all | One request at a time. Parallelism is the caller's, via a non-forking plan. |
| Ctrl-C timing unverified | all | Cancellation works; the 200 ms bound is not yet measured on every front-end. |

## Status

**v0.1.0 — a first release, not a 1.0.** The API is expected to be stable, but
it has not been through the external security review that 1.0 requires, and it
is not on CRAN yet. Suitable for use; pin the version if you depend on it.

## Security

`zuhttp` has a single maintainer and no inherited security-response process.
That is a real risk for security-critical code and is stated here rather than
buried: if your project cannot accept it, use `curl`.

To report a vulnerability, open a private security advisory through GitHub, or
email the maintainer listed in `DESCRIPTION`. There is no patch SLA yet; one is
a 1.0 requirement.

## License

MIT. Vendored components — picohttpparser and a subset of uriparser — retain
their own licences; see `inst/COPYRIGHTS`.

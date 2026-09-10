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

Every example below is a real request against a public API, and the `#>` lines
are what it actually returns.

```r
library(zuhttp)

r <- zu_get("https://ipwho.is/8.8.8.8")
zu_resp_status(r)
#> [1] 200
zu_resp_json(r)$country
#> [1] "United States"

# Query parameters are encoded for you.
r <- zu_get("https://ipwho.is/8.8.8.8", query = list(fields = "ip,country,city"))
zu_resp_url(r)
#> [1] "https://ipwho.is/8.8.8.8?fields=ip%2Ccountry%2Ccity"
str(zu_resp_json(r))
#> List of 3
#>  $ ip     : chr "8.8.8.8"
#>  $ country: chr "United States"
#>  $ city   : chr "San Jose"

# `json =` serialises the body and sets Content-Type, unless you set it.
r <- zu_post("https://postman-echo.com/post", json = list(name = "Alice", active = TRUE))
str(zu_resp_json(r)$data)
#> List of 2
#>  $ name  : chr "Alice"
#>  $ active: logi TRUE
```

Straight to disk: the body never passes through memory, and the file appears at
its destination only once it has arrived whole.

```r
r <- zu_get("https://raw.githubusercontent.com/pedrobtz/zuhttp/main/README.md",
            path = "README-copy.md")
zu_resp_path(r)
#> [1] "README-copy.md"
length(zu_resp_raw(r))
#> [1] 0   # it went to the file, not through memory
```

A client carries defaults; a request overrides them. Connections are reused
across requests to the same origin.

```r
gh <- zu_client(
  base_url = "https://api.github.com",
  headers  = c(
    Accept = "application/vnd.github+json"
    # , Authorization = paste("Bearer", Sys.getenv("GITHUB_PAT"))
  ),
  retry    = zu_retry(3)
)

zu_resp_json(zu_get("/repos/pedrobtz/zuhttp", client = gh))$language
#> [1] "C"

zu_get("/repos/pedrobtz/zuhttp", client = gh)      # second request, same origin
zu_pool_stats(gh)[["hits"]]
#> [1] 1
```

A failed request raises, and what it raises is a condition you match by class
rather than by parsing a message.

```r
tryCatch(
  zu_get("/repos/pedrobtz/no-such-repo", client = gh),
  zu_http_client_error = function(e) zu_resp_status(e$response)
)
#> [1] 404
```

`zu_resp_json()` uses `jsonlite` when it is installed, and says so plainly when
it is not — everything else here, including sending a JSON body you have
already encoded, works with no packages at all.

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

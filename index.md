# zuhttp

A minimal HTTP/1.1 client for R that uses **each platform’s own TLS
stack and trust store** — Schannel on Windows, Network.framework with
`SecTrust` on macOS, system OpenSSL elsewhere — rather than bundling
cryptography or a CA bundle. One R dependency, its sibling
[zujson](https://github.com/pedrobtz/zujson), for JSON.

zuhttp is not on CRAN yet. Install it from GitHub:

``` r

# install.packages("remotes")
remotes::install_github("pedrobtz/zuhttp")
```

Every example below is a real request against a public API, and the `#>`
lines are what it actually returns.

``` r

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

Straight to disk: the body never passes through memory, and the file
appears at its destination only once it has arrived whole.

``` r

r <- zu_get("https://raw.githubusercontent.com/pedrobtz/zuhttp/main/README.md",
            path = "README-copy.md")
zu_resp_path(r)
#> [1] "README-copy.md"
length(zu_resp_raw(r))
#> [1] 0   # it went to the file, not through memory
```

A client carries defaults; a request overrides them. Connections are
reused across requests to the same origin.

``` r

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

A failed request raises, and what it raises is a condition you match by
class rather than by parsing a message.

``` r

tryCatch(
  zu_get("/repos/pedrobtz/no-such-repo", client = gh),
  zu_http_client_error = function(e) zu_resp_status(e$response)
)
#> [1] 404
```

JSON goes through [zujson](https://github.com/pedrobtz/zujson), written
for zuhttp, and
[`zu_set_json_backend()`](https://pedrobtz.github.io/zuhttp/reference/zu_set_json_backend.md)
swaps in another implementation.
[`zu_resp_xml()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_json.md)
and
[`zu_resp_html()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_json.md)
parse with [zuxml](https://github.com/pedrobtz/zuxml) and
[zuhtml](https://github.com/pedrobtz/zuhtml) when they are installed,
honouring the response’s charset.

## Why this rather than `curl`

Because the trust decision is the platform’s. There is no bundled CA
bundle to go stale, and no vendored TLS library to track for CVEs — an
enterprise MDM root or a corporate proxy CA already installed on the
machine simply works. The package is small enough to audit, and its
behaviour under malformed input is fuzzed rather than assumed.

The [eMudhra incident](https://emudhra.we-have-a-problem.com/) of
October 2026 is the measured example. Eight intermediate CA certificates
had private keys anyone could recover, and they sit under roots that
stay trusted. A CA bundle lists roots, so it has no way to exclude an
intermediate beneath one; a platform’s trust evaluator does. Apple
blocked these intermediates on 22 October. On a Mac that had received
that update (macOS 15.7, 30 October), zuhttp refused every test host,
and R’s `curl` package, which on macOS trusts the PEM file at
`/etc/ssl/cert.pem`, connected to every one:

``` r

u <- "https://dv-g3b-emudhra.we-have-a-problem.com/"
tryCatch(zu_get(u), zu_tls_certificate_error = conditionMessage)
#> [1] "certificate verification failed for 'dv-g3b-emudhra.we-have-a-problem.com': “dv-g3b-emudhra.we-have-a-problem.com” certificate is blocked"
curl::curl_fetch_memory(u)$status_code
#> [1] 200
```

On a Mac that had not yet received it, zuhttp still refused the two
hosts whose certificates were never logged for Certificate Transparency,
which Apple’s evaluator requires; `curl` connected to those as well.

The difference is the platform’s, and it is not the same everywhere. On
Linux zuhttp reads the distribution’s bundle, a file like any other. On
Ubuntu 24.04 both clients refused these hosts, but only because the
bundle lacks their issuer, not because of a block. On a GitHub Windows
runner, which had not received Microsoft’s block, both connected. The
[TLS
article](https://pedrobtz.github.io/zuhttp/articles/tls.html#when-the-platform-blocks-a-certificate)
has the table for each platform, and `tools/check-trust-blocks.R` in the
repository repeats the measurement.

**When `curl` is the better choice**, stated plainly rather than left to
inference:

- Anything needing HTTP/2, HTTP/3, or a non-HTTP protocol.
- Anything needing NTLM, Kerberos, or cloud-provider request signing.
- Anything relying on libcurl’s decade of workarounds for badly behaved
  servers.
- **Any project that cannot accept a single-maintainer dependency for
  security-critical code.** `curl` inherits libcurl’s security response;
  `zuhttp` has none to inherit. See [Security](#security).
- Forked parallelism with HTTPS on macOS — see below.

Choosing `curl` after reading that list is a reasonable decision.

## Known limitations

These are documented limits, not open defects. Most are a consequence of
using the platform’s TLS stack instead of shipping one.
[`zu_info()`](https://pedrobtz.github.io/zuhttp/reference/zu_info.md)
reports which
[`zu_tls()`](https://pedrobtz.github.io/zuhttp/reference/zu_tls.md)
settings this build supports; a setting it cannot honour raises before
any connection is made, never downgrades.

| Limitation | Where | Detail |
|----|----|----|
| TLS 1.2 maximum | Windows | The Schannel build in Rtools lacks `SCH_CREDENTIALS`. `zu_tls(min_version = 13)` **raises** rather than silently giving you 1.2. [`?zuhttp_tls`](https://pedrobtz.github.io/zuhttp/reference/zuhttp_tls.md) |
| HTTPS through a proxy needs macOS 14 | macOS 11–13 | Network.framework runs the proxy’s `CONNECT` itself, and its API for that starts with macOS 14. Earlier, a proxied HTTPS request **raises** `zu_proxy_error` rather than going direct. Plain HTTP through a proxy works everywhere. [`?zuhttp_tls`](https://pedrobtz.github.io/zuhttp/reference/zuhttp_tls.md) |
| No certificate pinning | macOS, Windows | Pinning needs the leaf’s SubjectPublicKeyInfo, which neither platform yields without hand-parsing DER, and that parser is not written yet. `zu_tls(pins = )` **raises** `zu_tls_unsupported_error` rather than connecting unpinned. OpenSSL pins. |
| No custom CA | Windows | Neither `ca_file` (replace) nor `ca_extra` (add) is implemented on Schannel yet. Both **raise** rather than falling back to the Windows store. They work on macOS and OpenSSL. |
| HTTPS in a forked child fails | macOS | The system TLS engine does not survive `fork()`. Raises `zu_fork_error` instead of killing the worker. Use a `PSOCK` cluster or `future::plan("multisession")`. [`?zuhttp_fork`](https://pedrobtz.github.io/zuhttp/reference/zuhttp_fork.md) |
| Revocation off by default, and opting in is backend-dependent | all | zuhttp asks for no revocation check by default; macOS may check Apple’s own revocation data anyway, run by run, and OpenSSL and Schannel check nothing. `zu_tls(revocation = TRUE)` opts in on macOS and Windows; macOS also rejects valid certificates from CAs that no longer answer revocation queries. On OpenSSL, which has no CRL or OCSP source, it **raises** rather than failing every chain. [`?zuhttp_tls`](https://pedrobtz.github.io/zuhttp/reference/zuhttp_tls.md) |
| Trust freshness on Linux | Linux | Trust comes from the distribution’s `ca-certificates` bundle through OpenSSL’s default verify paths, a file updated at the distribution’s pace. A bundle can drop a root but cannot block an intermediate beneath one, which is how Apple blocked the eMudhra intermediates (see above). |
| No parallel or async requests | all | One request at a time. Parallelism is the caller’s, via a non-forking plan. |
| Only a total timeout | all | `timeout` bounds the whole request, redirects and retries included. There are no separate connect, first-byte or inactivity timeouts yet. |
| DNS ignores `timeout` and Ctrl-C | Linux, Windows; macOS for `http://` | Name resolution calls the system resolver synchronously (`getaddrinfo`), so a stalled resolver can hold R until it gives up. Every later phase is bounded. HTTPS on macOS is bounded throughout: Network.framework resolves the name itself. [`?zuhttp_tls`](https://pedrobtz.github.io/zuhttp/reference/zuhttp_tls.md) |
| Ctrl-C timing unverified | all | Cancellation works once a request is past DNS; the 200 ms bound is not yet measured on every front-end. |

## Status

**v0.1.0 — a first release, not a 1.0.** The request functions, response
accessors and conditions are the stable API: from 0.1.0 on, an export is
removed only after a deprecation release (§53). The testing tools
([`zu_mock_transport()`](https://pedrobtz.github.io/zuhttp/reference/zu_transport.md),
[`zu_stub()`](https://pedrobtz.github.io/zuhttp/reference/zu_stub.md),
[`zu_response()`](https://pedrobtz.github.io/zuhttp/reference/zu_response.md),
the cassettes) are experimental and may still change. It has not been
through the external security review that 1.0 requires. Suitable for
use.

## Security

`zuhttp` has a single maintainer and no inherited security-response
process. That is a real risk for security-critical code and is stated
here rather than buried: if your project cannot accept it, use `curl`.

To report a vulnerability, open a private security advisory through
GitHub, or email the maintainer listed in `DESCRIPTION`. There is no
patch SLA yet; one is a 1.0 requirement.

## License

MIT. Vendored components — picohttpparser and a subset of uriparser —
retain their own licences; see `inst/COPYRIGHTS`.

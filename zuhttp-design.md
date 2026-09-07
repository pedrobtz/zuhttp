# zuhttp Design Document

**Status:** Draft — macOS spike GO (S0); Windows headers probed (S1, R-3 confirmed)  
**Target:** R package / CRAN-compatible source package  
**Primary implementation language:** C  
**Primary protocol scope:** HTTP/1.1 over HTTP and HTTPS  
**TLS strategy:** Native/system trust; protocol engine per platform (§13.1)  
**Estimated effort to 1.0:** 9–11 person-months (§64)  
**Last updated:** 2026-09-07 (S0 findings folded in)

---

## Decision Register

Firm decisions and open questions were previously indistinguishable in this document. This register is the index; each row links to the section that argues it. **Nothing marked Blocked or Open may be treated as settled by implementation work.**

| # | Decision | Status | §  |
|---|---|---|---|
| D-1 | R prefix `zu_`, response accessors `zu_resp_`, C macros `ZUHTTP_` | **Accepted** | 1.1 |
| D-2 | No `zuhttp` export may collide with an httr2 export | **Accepted** | 1.1, 5 |
| D-3 | Separate TLS protocol engine from trust evaluation | **Accepted** | 13.1 |
| D-4 | macOS: portable engine + `SecTrustEvaluateWithError` for Keychain trust | **Accepted** — validated by S0 | 13.2 |
| D-5 | Windows: Schannel for both engine and trust | **Accepted, effort unquantified** | 13.4 |
| D-6 | Unix: system OpenSSL for both | **Accepted** | 13.5 |
| D-7 | Link system zlib; do not vendor miniz | **Accepted** | 21.1 |
| D-8 | Send `Accept-Encoding: gzip` by default; decode transparently | **Accepted** | 21.2 |
| D-9 | `zu_resp_raw()` returns decoded bytes | **Accepted** | 21.2, 31.7 |
| D-10 | HTTP parser: **picohttpparser** (vendored, commit f4d94b4) | **Accepted** 2026-09-07 | 8.1, A.3 |
| D-11 | URI: vendor a SUBSET of uriparser (parse/resolve/recompose only) | **Accepted** | 8.2 |
| D-12 | `ca_file`/`ca_data` REPLACE system trust; `ca_extra` adds to it | **Accepted** | 14.2 |
| D-13 | Certificate pinning supported; no custom OCSP/CRL | **Accepted** | 14.4, 14.5 |
| D-31 | Revocation checking **off by default**, opt-in via `zu_tls(revocation=)` | **Accepted** — S0 F-4 | 14.5 |
| D-32 | HTTPS in a forked child raises an actionable error, never a segfault | **Accepted** — S0 F-5 | 26.4 |
| D-14 | Reject non-ASCII (IDN) hostnames rather than mis-handle them | **Accepted** | 4 |
| D-15 | Strict framing: reject CL+TE, duplicate CL, non-chunked TE | **Accepted** | 18.1 |
| D-16 | `zu_resp_header()` returns a character vector, never comma-joined | **Accepted** | 18.3 |
| D-17 | Redirect method/body rewriting per the normative table | **Accepted** | 19.1 |
| D-18 | `total` timeout spans all retries and redirects | **Accepted** | 24.3 |
| D-19 | Client is always a named `client =` argument, never positional | **Accepted** | 31.3 |
| D-20 | Policy objects (`retry =`) are distinct from `middleware =` | **Accepted** | 31.13 |
| D-21 | Interrupt safety via external-pointer ownership + `R_UnwindProtect` | **Accepted** | 25.2 |
| D-22 | PID guard covers the pool **and the trust evaluator** | **Accepted** — S0 F-5 | 26.4 |
| D-23 | Clients lazily re-create pools after serialization | **Accepted** | 26.5 |
| D-24 | Body rewindability is a checked property, not a convention | **Accepted** | 28.2 |
| D-25 | `jsonlite` in Suggests, not Imports; pluggable backend | **Accepted** | 31.7 |
| D-26 | Conditions built with base R; no rlang dependency | **Accepted** | 34.3 |
| D-27 | Redaction is one policy applied at every egress | **Accepted** | 42 |
| D-28 | Own tests use a `zu_stream` mock, not the R transport mock | **Accepted** | 50.1 |
| D-29 | Concurrency, if built, integrates with `later`; no bespoke event loop | **Proposed** | 30.2 |
| D-30 | DNS is not interruptible in v1; documented limitation | **Accepted** | 8.4, 25.4 |

---

## Part 1 — Scope and Positioning

### 1. Executive Summary

`zuhttp` is a proposed small, portable HTTP client for R intended to provide a focused alternative to the `curl` package for common HTTP(S) workloads.

The project is deliberately **not** a reimplementation of libcurl. Its competitive position is:

- HTTP(S)-only rather than multi-protocol.
- Small and auditable native codebase, **subject to the size budget in §51**.
- Native/system TLS rather than vendored cryptography.
- Native operating-system trust stores where possible.
- First-class R cancellation and interrupt behavior.
- Structured request, response, timeout, retry, and error semantics.
- Pluggable transports and middleware.
- Straightforward CRAN source builds.
- Minimal external dependencies.
- Clear resource limits and secure defaults.
- A functional, ergonomic R API combining one-shot convenience with composable request objects and reusable clients.

The intended architecture combines a small amount of `zuhttp` C code with a few focused dependencies:

- **HTTP/1.1 response parsing** — parser choice open between picohttpparser and llhttp; see Appendix A.3.
- **URI parsing** — a vendored subset of `uriparser` (parse/resolve/recompose), wrapped by a zuhttp policy layer; see §8.2.
- **zlib** (system, not vendored) for gzip/deflate response decompression; see §21.
- **TLS**, split into a protocol engine and a trust evaluator; see §13.

DNS and TCP use native OS APIs directly.

The project should remain intentionally small. Features should be rejected when they substantially increase implementation complexity without serving common R HTTP workloads.

#### 1.1 Naming conventions

To avoid ambiguity throughout this document:

| Surface | Prefix | Example |
|---|---|---|
| R functions | `zu_` | `zu_get()`, `zu_client()`, `zu_perform()` |
| R response accessors | `zu_resp_` | `zu_resp_status()`, `zu_resp_json()` |
| R condition classes | `zu_` | `zu_tls_certificate_error` |
| C symbols | `zu_` | `zu_stream`, `zu_tls_connect()` |
| C macros | `ZUHTTP_` | `ZUHTTP_NO_COMPRESSION` |

The `zu_resp_` prefix is deliberate. httr2 **exports** `resp_status()`, `resp_status_desc()`, `resp_header()`, `resp_headers()`, `resp_url()`, `resp_body_raw()`, `resp_body_string()`, `resp_body_json()` and `resp_check_status()`. Since §5 positions `zuhttp` to coexist with httr2 in the same session, a bare `resp_` prefix would mask four httr2 functions on attach. No `zuhttp` export may collide with an httr2 export.

#### 1.2 Honest claims

Several claims in this document are **hypotheses pending the prototype in §63**, not established facts. They are marked as such where they appear:

- "Smaller native code than the alternative" — depends on final vendoring choices, and is false on Linux where the `curl` package links *system* libcurl and vendors nothing. See §51.
- "Competitive performance" — unmeasured. See §51.
- "An httr2 backend" — requires upstream collaboration that is not under this project's control. See §5.

### 2. Motivation

R has mature HTTP support through `curl`, `httr`, and `httr2`. These packages are powerful and appropriate for broad use, but `curl` exposes libcurl, a very large multi-protocol networking library whose capabilities extend far beyond HTTP.

For many R packages, the actual requirement is narrower:

> Perform reliable HTTPS requests, with system certificate trust, redirects, streaming, timeouts, proxy support, cancellation, and useful diagnostics.

`zuhttp` aims to serve this narrower requirement with a simpler architecture.

Potential advantages include:

1. Smaller native code and dependency surface.
2. Easier auditing.
3. Native operating-system TLS behavior.
4. R-specific cancellation and error semantics.
5. Structured APIs instead of large sets of libcurl options.
6. Easier transport mocking for package tests.
7. Cleaner observability and timing information.
8. Minimal builds suitable for constrained containers and embedded R deployments.
9. More predictable behavior across common R HTTP use cases.

### 3. Goals

#### 3.1 Primary goals

RFC 2119 keywords are used normatively from here on: **MUST** is a requirement whose violation is a bug, **SHOULD** is a strong default that may be traded away with a recorded reason, and **MAY** is optional. Earlier drafts used "SHOULD" for everything, including items that §56 treats as inviolable constraints.

`zuhttp` **MUST**:

- Support HTTP/1.1.
- Support HTTP and HTTPS.
- Support GET, HEAD, POST, PUT, PATCH, DELETE, and arbitrary methods.
- Support request headers.
- Support request bodies from memory and files.
- Support response bodies to memory, files, R connections, and callbacks.
- Support `Content-Length`.
- Support chunked transfer encoding.
- Support redirects.
- Support gzip and deflate response decompression.
- Support IPv4 and IPv6.
- Support HTTP proxies.
- Support HTTPS proxies using CONNECT.
- Support `http_proxy`, `HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY` (§20.1).
- Use system/native TLS.
- Use native/system trust stores.
- Support custom CA files/data.
- Support configurable TLS verification.
- Support request deadlines and phase-specific timeouts.
- Support reliable interruption from R.
- Support connection reuse.
- Support bounded resource usage.
- Expose structured timing information.
- Expose structured error classes.
- Provide a pluggable transport layer.
- Provide middleware/interceptor support at the R level.
- Build from source on CRAN using standard R toolchains.
- Be safe across `fork()` and across R session serialization (§26.4, §26.5).
- Never mask an httr2 export (§1.1).

#### 3.2 Secondary goals

`zuhttp` SHOULD eventually support:

- Safe automatic retries.
- Idempotency-aware retry policy.
- `Retry-After`.
- Bearer authentication helpers.
- Basic authentication.
- Client certificates.
- Record/replay testing transport.
- Structured tracing hooks.
- OpenTelemetry integration at the R layer.
- Connection-pool metrics.
- Unix-domain sockets where meaningful.

### 4. Non-Goals

The first versions of `zuhttp` will NOT attempt to support the following. Each entry here represents a decision someone might reasonably argue with; obvious non-features (FTP, SMTP, Telnet, MQTT, and other unrelated protocols) are simply out of scope and are not listed.

| Not supported | Why, and what to do instead |
|---|---|
| **HTTP/2** | Concurrency is achievable with parallel HTTP/1.1 connections (§30). Revisit only under §60. |
| **HTTP/3 / QUIC** | Requires a UDP stack and a QUIC implementation; far outside the size budget. |
| **WebSockets** | Different lifecycle and framing model; belongs in a separate package that could borrow this one's stream layer. |
| **Persistent cookie jars** | Browser-grade cookie semantics (public-suffix list, SameSite, partitioning) are a project of their own. See §22. |
| **HSTS persistence / Alt-Svc** | Requires durable client-side state and a storage policy. |
| **DNS-over-HTTPS** | Bootstrapping problem, and system resolvers are the more predictable default. |
| **Full MIME machinery / multipart** | See §23. If added, it is a body encoder, not a networking feature. |
| **OAuth flows** | Belongs in middleware or a higher-level package. See §38. |
| **AWS SigV4 and other cloud signing** | Same. Provider-specific and fast-moving. |
| **NTLM / Kerberos / GSSAPI** | Large, platform-entangled, and rarely needed by R packages. |
| **IDN / punycode hostnames** | libcurl uses libidn2 for this. `zuhttp` will **reject** non-ASCII hostnames with a clear error rather than mis-handle them. Callers may pre-encode with `base::intToUtf8`-based helpers or an IDN package. Revisit if demand appears. |
| **A general event-loop framework** | Integrate with `later` instead (§30). |
| **A general-purpose TLS or networking abstraction** | The stream interface (§9) is internal, sized for this project only. |
| **Reimplementation of httr2** | `zuhttp` competes at the transport layer. See §5. |

If a feature moves the project toward becoming a second libcurl, it should be treated skeptically.

### 5. Positioning in the R Ecosystem

The aspirational layering is:

```text
Higher-level R HTTP APIs
        |
      httr2
        |
  -----------------
  |               |
 curl backend    zuhttp backend
```

**This diagram describes a hypothesis, not a plan.** httr2 has no pluggable transport backend today; `req_perform()` calls into `curl` directly. Realising this layering would require design work and buy-in from the httr2 maintainers, which is outside this project's control. Nothing in the `zuhttp` roadmap may depend on it, and no success criterion in §61 assumes it.

What `zuhttp` *can* control is being a good backend candidate: a coherent request/response model, deterministic configuration merging, and a transport seam (§36) that someone else could adapt.

`zuhttp` should primarily compete with `curl` at the **transport layer**, not with `httr2` at the high-level user API layer.

At the same time, `httr2` should be treated as the **R-native ergonomic baseline** for request composition. The public API should preserve the strengths of functional request transformation and an explicit execution boundary, while also providing a lower-friction one-shot API inspired by Requests/HTTPX and a reusable-client model inspired by HTTPX/reqwest.

Because both packages will often be attached in the same session, `zuhttp` must not mask any httr2 export. See §1.1.

### 6. Comparison with R curl

`curl` strengths:

- Extremely mature.
- Huge protocol support.
- HTTP/2.
- HTTP/3 in some builds.
- Broad authentication.
- Mature proxy support.
- Battle-tested edge cases.
- High performance.
- Extensive ecosystem use.

`zuhttp` proposed strengths:

- Much smaller scope.
- Native/system trust on every platform.
- Structured R-native errors and conditions.
- First-class deadlines and cancellation.
- Pluggable transports and R-level middleware.
- Retries that are safe by construction (§33.1).
- Built-in observability.
- Easier mocking, at two levels (§50.1).
- Explicit resource limits.
- No libcurl dependency.
- Smaller native source — **claimed, not yet measured** (§1.2, §51.3), and false on Linux, where the `curl` package links system libcurl and vendors nothing.

#### 6.1 Where `curl` is the better choice

This must be stated plainly rather than left for the reader to infer:

- Any workload needing HTTP/2, HTTP/3, or a protocol other than HTTP.
- Any workload needing NTLM, Kerberos, or cloud-provider request signing.
- Anything depending on libcurl's decade of accumulated interoperability workarounds for badly behaved servers.
- **Any project that cannot accept a single-maintainer dependency for security-critical code** (§46.3, Appendix B R-6). `curl` inherits libcurl's security response; `zuhttp` does not have one to inherit.
- **Forked parallelism with HTTPS on macOS** (`mclapply`, `future::plan("multicore")`). `zuhttp`'s native-trust design cannot work in a forked child there and will raise an error; `curl` degrades less abruptly (§26.4). Use a `PSOCK`/`multisession` plan with either package.

`zuhttp` should not claim universal superiority, and a user choosing `curl` after reading §6.1 has made a reasonable decision.


---

## Part 2 — Architecture

### 7. High-Level Architecture

```text
                         R API
                           |
                     Request object
                           |
               Middleware / policies
                           |
                   zuhttp C API
                           |
              HTTP request engine
                           |
       +-------------------+------------------+
       |                                      |
   URI handling                           HTTP parser
   (§8.2, decided)                       (§8.1, decided)
       |                                      |
       +-------------------+------------------+
                           |
                    Body framing (§18)
                           |
                    Stream interface (§9)
                           |
               +-----------+-----------+
               |           |           |
            Windows      macOS       Unix
               |           |           |
         +-----+-----+-----+-----+-----+-----+
         |           |           |           |
      Schannel   engine:?    OpenSSL     (mock, §50.1)
         |       (§13.2)         |
      trust:     trust:       trust:
      Windows    Keychain     OpenSSL
      cert store SecTrust     verify paths
         |           |           |
         +-----------+-----------+
                           |
                       TCP sockets
                           |
                      getaddrinfo()
```

Two things this diagram encodes that the earlier version did not:

1. **The TLS protocol engine and the trust evaluator are separate** (§13.1). Only the trust side must be native for the project to deliver on "system trust", which is what makes the macOS problem in §13.2 tractable.
2. **The mock stream sits at the same seam as the real transports** (§50.1), which is what makes the HTTP engine testable without a network.

Decompression sits above body framing and below the sink:

```text
HTTP body stream
      |
 Transfer-Encoding (chunked only, §18.1)
      |
 Content-Encoding  ->  zlib  (§21)
      |
 limit enforcement (§21.4)
      |
 body sink (§27)
```

### 8. Component Selection

Every vendored line counts against the size budget in §51 and becomes a fuzz target in §43. The table below is the running tally; the prototype (§63) must produce real numbers to replace these estimates.

| Component | Role | Est. LOC | Status |
|---|---|---|---|
| picohttpparser | response parsing, chunked decoding | **0.8k** (measured) | **Decided** — §8.1 |
| URI parser | RFC 3986 parse + relative resolution | 3.9k | **Decided** — uriparser subset, §8.2 |
| zlib | gzip/deflate | 0 (system) | **Decided** — §21 |
| TLS engine + trust | see §13 | 4k–6k | **Blocked on spike** — §13 |
| Project-owned engine | framing, pool, redirects, proxy, R glue | 5k–8k | Estimate |

#### 8.1 HTTP parser — **picohttpparser** (D-10, decided)

**Decision: vendor picohttpparser** (`src/vendor/picohttpparser/`, upstream commit `f4d94b4`, 803 LOC, MIT).

Appendix A.3 argued that llhttp was favoured *because* picohttpparser makes no framing decisions, leaving ~800–1,200 lines of security-critical strictness code for this project to write and fuzz. That argument was answered by building the strictness layer first: `src/zu_framing.c` implements every §18.1 rule with a test per row, and `zu_headers` re-validates every field independently of what the parser accepted. The cost A.3 warned about is now incurred, tested, and bounded, which removes its main objection while keeping picohttpparser's size advantage.

The consequence must be stated plainly and kept visible: **picohttpparser rejects no smuggling attempt on our behalf.** Anything §18.1 does not catch, nothing does.

Given that:

- `zuhttp` must not expose the parser type in any public or semi-public interface.
- A wrapper translates parser output into internal `zu_*` structures.
- The security-critical framing decisions in §18 live in project-owned code (`zu_framing.c`) and are the primary fuzz target in §43, regardless of which parser sits underneath.

If picohttpparser is chosen, note two properties that shape the buffering design: it requires the entire header block in one contiguous buffer, and it re-parses from offset 0 on each call (the `last_len` argument bounds but does not eliminate the repeated scan). `max_header_bytes` (§40) is therefore both a security limit and the bound on that quadratic term.

#### 8.2 URI parser

**Decided (D-11): vendor a SUBSET of `uriparser` 0.9.8.** The parse / resolve /
recompose closure only — eight `.c` files, ~3.9k code lines — plus a zuhttp
policy layer in `zu_uri.c`. See `src/vendor/uriparser/VENDOR` for the file list
and `tools/update-uriparser` for the refresh procedure.

What a client actually needs from RFC 3986 is narrow:

- absolute URI parsing,
- relative-reference resolution for `Location` (RFC 3986 §5),
- IPv6 literal handling,
- scheme/host/port/path/query decomposition.

The earlier estimate in this section — "vendoring `uriparser` costs roughly 15k
LOC, more than the entire rest of the HTTP core" — was measuring the whole
distribution, including its test suite and command-line tool. The library
sources are 7.9k lines, and the closure this project needs is **~3.9k code
lines (7.0k including license headers and doxygen)**. That is still six times a
project-owned parser's estimated ~600 lines, so the trade is real; it is just
much narrower than recorded.

Three things settled it:

1. **The excluded modules are where the bugs were.** Six of uriparser's eight
   historical CVEs are in files the subset does not vendor:
   `UriQuery.c` (CVE-2024-34402, CVE-2024-34403, CVE-2018-19198,
   CVE-2018-19199) and `UriNormalize.c` (CVE-2021-46141, CVE-2021-46142).
   Two are in retained files (CVE-2018-19200 in `UriCommon.c`, CVE-2018-20721
   in `UriParse.c`). This is structural rather than lucky: the excluded modules
   *build* strings — allocating, sizing and concatenating — while the retained
   ones mostly *scan* a caller-owned buffer and record ranges into it.
   Allocation arithmetic is where the overflow bugs live.

2. **It integrates with our allocator.** `UriMemoryManager` routes every
   parser allocation through `zu_alloc`, so the OOM injection of §50.1 and the
   leak accounting in `zu_alloc_stats` cover the parser rather than stopping at
   its edge. Measured: 226 allocations over the resolve path, and **0 of 400
   OOM injection points leaked**, under ASan and UBSan.

3. **A hand-written parser would need the same policy layer anyway.** RFC 3986
   is a grammar, not a client policy, and the security-relevant decisions are
   in the policy layer either way (see below). Writing our own would have
   bought ~3.3k fewer vendored lines at the cost of owning the grammar, which
   is the part with a 17-year public bug record to learn from.

**The policy layer is where the security decisions live.** `zu_uri.c` rejects
what a grammar accepts but an HTTP client must not:

| Input | RFC 3986 | zuhttp |
|---|---|---|
| `http://h:65536/` | valid (`port = DIGIT*`) | **rejected** — would truncate to 0 in `uint16_t` |
| `http://h:0443/` | valid | accepted, port `443` (numeric compare, per RFC 6454) |
| `https://example.com../` | valid | **rejected** — empty DNS label |
| `https://example.com./` | valid | accepted, root dot stripped so origins compare equal |
| `ftp://h/`, `file:///`, `mailto:` | valid | **rejected** — not an HTTP request target |
| embedded `NUL` | n/a | **rejected** — truncates `getaddrinfo()` and the request line differently |
| fragment | valid | dropped; never sent (RFC 7230 §5.3) |

uriparser is correspondingly *stricter* than a browser where that helps: a
space, tab, newline or backslash in the authority is a syntax error, and
`https://good.com@evil.com/` yields `host = evil.com`, `userinfo = good.com` —
the origin-confusion case that governs whether credentials survive a redirect
(§19.2).

**Percent-encoding in a supplied path is preserved verbatim, not normalised.**
This reverses the fifth bullet of the original list. Rewriting a request target
can change what the origin server resolves; neither curl nor httr2 normalises
it either. Normalisation applies only to query strings *this library*
constructs, below. Dropping that requirement is also what lets `UriNormalize.c`
stay out of the subset.

Neither option provides IDN/punycode; non-ASCII hostnames are rejected outright (§4).

The flat struct remains the boundary, so the parser stays replaceable:

```c
typedef struct {
    char    *scheme;      /* lowercased */
    char    *host;        /* lowercased; IPv6 literals without brackets */
    char    *path_query;  /* origin-form target, always starting "/" */
    char    *userinfo;    /* credentials, moved out of the URL (§20.4) */
    uint16_t port;        /* explicit or scheme default */
    int      is_https;
    int      port_explicit;
} zu_uri;
```

Nothing above `zu_uri.h` sees a uriparser type; `src/zu_uriparser.h` is the
only file that includes `<uriparser/Uri.h>`.

**Query encoding must be specified, not inherited.** `zu_query()` builds `application/x-www-form-urlencoded` pairs: space encodes as `%20` (not `+`), and every character outside RFC 3986 `unreserved` is percent-encoded. Values are encoded from UTF-8 bytes. Callers who need different semantics build the query string themselves.

#### 8.3 Compression

**Decided: link system zlib; do not vendor miniz.** See §21 for the full rationale and for `Accept-Encoding` policy.

#### 8.4 DNS

Use native `getaddrinfo()`.

Requirements:

- IPv4 and IPv6.
- Happy-Eyeballs-like behavior may be considered later.
- DNS resolution should participate in total cancellation/deadline behavior.

`getaddrinfo()` is synchronous and not cancellable on most platforms, which is a real hole in the §25 cancellation guarantee: a request blocked in DNS cannot be interrupted. Options, in preference order:

1. Accept the gap for v1, document it, and bound it with the platform resolver timeout where one is configurable.
2. Use `getaddrinfo_a()` where available (glibc only, and it uses threads internally).
3. Resolve on a detached helper thread that never touches the R API, with the main thread polling a self-pipe — this is the only fully cancellable option, and it is the one place where §29's no-threads rule may need a carefully scoped exception.

Option 1 for the MVP. §25 must state the limitation rather than imply cancellation is universal.

#### 8.5 TCP

Unix/macOS: `socket`, `connect`, `send`, `recv`, `shutdown`, `close`, `poll`.

Windows: Winsock equivalents (`WSAPoll`).

Sockets are non-blocking throughout, so that deadlines (§24) and R interrupts (§25) are enforced by the polling loop rather than by the kernel.

### 9. Generic Stream Interface

HTTP code should depend only on:

```c
typedef struct zu_stream zu_stream;

ssize_t zu_stream_read(
    zu_stream *,
    void *,
    size_t,
    zu_deadline,
    zu_error *
);

ssize_t zu_stream_write(
    zu_stream *,
    const void *,
    size_t,
    zu_deadline,
    zu_error *
);

void zu_stream_close(zu_stream *);
```

Possible stream implementations:

```text
plain TCP
TLS TCP
proxy tunnel
mock
record/replay
Unix-domain socket
```

This interface is one of the most important architectural boundaries.

### 10. Platform Abstraction

Project-owned platform layer:

```text
src/platform/
    zu_platform.h

    unix_socket.c
    windows_socket.c

    tls_openssl.c
    tls_schannel.c
    tls_apple.c

    time_unix.c
    time_windows.c
```

Platform macros should be isolated.

Avoid sprinkling:

```c
#ifdef _WIN32
```

through generic HTTP logic.

### 11. Proposed Source Tree

```text
zuhttp/
├── DESCRIPTION
├── NAMESPACE
├── LICENSE
├── R/
│   ├── client.R
│   ├── request.R
│   ├── response.R
│   ├── timeout.R
│   ├── retry.R
│   ├── middleware.R
│   ├── transport.R
│   ├── redact.R
│   └── conditions.R
│
├── src/
│   ├── init.c
│   ├── r_api.c            R glue; the only file that touches SEXPs
│   │
│   ├── zu_client.c
│   ├── zu_request.c
│   ├── zu_response.c
│   ├── zu_headers.c
│   ├── zu_framing.c       §18.1 — strict framing; primary fuzz target
│   ├── zu_body.c
│   ├── zu_inflate.c       §21
│   ├── zu_redirect.c
│   ├── zu_proxy.c
│   ├── zu_pool.c          §26, incl. PID guard
│   ├── zu_timeout.c
│   ├── zu_uri.c           §8.2, policy layer over the uriparser subset
│   ├── zu_error.c
│   ├── zu_buffer.c
│   │
│   ├── platform/
│   │   ├── zu_platform.h
│   │   ├── socket_unix.c
│   │   ├── socket_windows.c
│   │   ├── time_unix.c
│   │   ├── time_windows.c
│   │   ├── tls_openssl.c
│   │   ├── tls_schannel.c
│   │   ├── tls_macos.c        engine, §13.2
│   │   ├── trust_openssl.c    §13.1
│   │   ├── trust_windows.c
│   │   └── trust_macos.c      SecTrustEvaluateWithError
│   │
│   ├── mock/
│   │   └── stream_mock.c      §50.1 — canned bytes through the real engine
│   │
│   ├── Makevars / Makevars.win   explicit OBJECTS: R does not compile
│   │                             src/ subdirectories automatically
│   └── vendor/
│       ├── picohttpparser/    D-10, decided; VENDOR records the commit
│       └── uriparser/        D-11: parse/resolve/recompose subset only
│
├── inst/
│   └── COPYRIGHTS             §49.2 — required for vendored code
├── tests/
├── fuzz/                      §43 harnesses; not shipped in the tarball
├── tools/
│   └── update-<vendored>      §48
├── configure
├── cleanup
└── src/Makevars.in / Makevars.win
```

Two structural rules the tree encodes:

- **`r_api.c` is the only file that touches `SEXP`.** Everything below it is plain C and can be compiled into a fuzz harness with no R runtime (§43).
- **`platform/` splits engine from trust**, one file each, so that a platform can mix them per §13.1 and a new platform port has an obvious file list.

`fuzz/` is listed in `.Rbuildignore` so it never reaches CRAN.

### 12. Recommended Architectural Decision

For `zuhttp`, the preferred architecture is:

```text
Small R API
   |
small C HTTP engine
   |
HTTP parser + URI parser (D-10, D-11)
   |
generic stream abstraction
   |
native/system TLS
   |
OS sockets
```

with:

```text
            engine          trust
Windows ->  Schannel        Windows cert store
macOS   ->  see §13.2       Keychain (SecTrust)
Unix    ->  OpenSSL         OpenSSL verify paths
```

This design provides a credible path to a small, R-native, secure HTTP client without carrying libcurl or another complete runtime — **conditional on D-4 resolving favourably (§13.2) and on the size and performance budgets in §51.3 being met.** Neither is established yet.

The package should compete through:

- simplicity,
- native TLS,
- R-aware cancellation,
- structured errors,
- middleware,
- pluggable transports,
- safe retries,
- observability,
- and a small auditable implementation,

rather than through protocol breadth.


---

## Part 3 — TLS and Trust

### 13. TLS Architecture

**Status: validated.** The S0 spike (`spike/macos-tls/`, [FINDINGS.md](spike/macos-tls/FINDINGS.md)) confirmed this design on macOS 26.6.2 / OpenSSL 3.6.3: TLS 1.3 negotiated, chain evaluated against the system Keychain, driven entirely from a caller-owned non-blocking `poll()` loop with no dispatch queue. **Appendix B R-1 is retired.** The spike also produced four findings that changed this section and §14.5, §26.4 — see F-1 and F-5 below.

#### 13.1 Separate the protocol engine from trust evaluation

Earlier drafts of this document conflated two questions that have different answers on each platform:

1. **Who speaks the TLS protocol?** — handshake, record layer, key schedule.
2. **Who decides whether a certificate chain is trusted?** — root store, enterprise policy, revocation.

Only the second needs to be native for `zuhttp` to deliver on "native system trust". Splitting them collapses a three-backend matrix into something far smaller and resolves the macOS contradiction below:

| Platform | Protocol engine | Trust evaluation |
|---|---|---|
| Windows | Schannel | built in (`CertGetCertificateChain` + `CertVerifyCertificateChainPolicy`) |
| macOS | OpenSSL-family engine | `SecTrustEvaluateWithError` against the system Keychain |
| Linux/Unix | system OpenSSL | OpenSSL default verify paths |

The trust evaluator is a separate internal interface from the engine, so a platform can mix them:

```c
typedef struct zu_trust zu_trust;

/* Called from the engine's chain-verification callback. Returns 0 on trusted. */
int zu_trust_evaluate(
    zu_trust        *trust,
    const uint8_t  **chain_der,   /* leaf first */
    const size_t    *chain_len,
    size_t           chain_n,
    const char      *hostname,
    zu_error        *err
);
```

#### 13.2 Why macOS forces this

§8.3 of the previous draft asked for Keychain trust, modern non-deprecated APIs, and no bundled OpenSSL, while §25 and §29 require a synchronous, single-threaded, poll-driven design with no background threads touching R. **Those requirements are not jointly satisfiable with either Apple TLS API:**

- **Secure Transport** (`SSLSetIOFuncs`, `SSLHandshake`) fits the architecture exactly — it lets `zuhttp` supply its own read/write callbacks over a non-blocking socket it owns. It has been deprecated since macOS 10.15.
- **Network.framework** (`nw_connection`) is the supported replacement. It is asynchronous, dispatch-queue-driven, and owns the socket. Driving it from a synchronous poll loop requires a background thread plus a wakeup pipe, contradicting §29.

The engine/trust split escapes the dilemma: use a portable engine for the protocol, and `SecTrustEvaluateWithError` — a current, non-deprecated API (`API_AVAILABLE(macos(10.14))`, verified in SDK 26.5) — for trust. Enterprise-deployed roots in the Keychain are honoured, which is the property users actually care about.

**Measured result (S0):**

```text
engine=openssl  OK TLSv1.3 / TLS_AES_256_GCM_SHA384 / trust=SecTrust:yes
timing   connect=7.8ms handshake=12.7ms trust=3.9ms total=35.5ms
loop     checkpoints=3  longest_block=12934us  (tick=100ms)
```

**The fallback is worse than this document previously assumed.** Secure Transport has no `kTLSProtocol13` — the enum in SDK 26.5 stops at `kTLSProtocol12`, and against a server offering 1.3 it negotiates 1.2. Falling back therefore means shipping a **TLS 1.2-only** macOS backend, not merely a deprecated one. It remains a fallback of last resort with a sunset trigger, but it is not equivalent and must not be treated as such.

**Open on this path (§62.1):** the spike linked Homebrew OpenSSL. CRAN macOS binaries need a static OpenSSL from the recipes toolchain, or another portable engine. That is now the top unresolved question for macOS.

#### 13.2.1 Trust evaluation is not fork-safe

Security.framework opens an XPC connection to `trustd` on first use — the process goes from 1 thread to 3 and stays there. **That connection does not survive `fork()`:** a child that calls `SecTrustEvaluateWithError` after the parent has done so is killed by SIGSEGV. A child in a process that never touched Security.framework is fine.

This is a first-class constraint on the R API, not a footnote. See §26.4 and §29.2.

#### 13.3 TLS must be hidden behind the stream interface

The HTTP layer must not know whether the underlying stream is plain TCP, Schannel, OpenSSL, a proxy tunnel, or a mock. See §9 and §15.

```c
typedef struct zu_stream zu_stream;

typedef struct {
    ssize_t (*read)(zu_stream *, void *, size_t);
    ssize_t (*write)(zu_stream *, const void *, size_t);
    int     (*wait_readable)(zu_stream *, int timeout_ms);
    int     (*wait_writable)(zu_stream *, int timeout_ms);
    int     (*close)(zu_stream *);
} zu_stream_vtable;
```

#### 13.4 Windows / Schannel

Use Winsock, Schannel, and the Windows certificate trust store.

Benefits: no OpenSSL dependency, native enterprise trust, native certificate updates, Windows policy integration.

Requirements: SNI, hostname verification, chain validation, TLS 1.2+, TLS 1.3 where the platform supports it, custom CA support that does not undermine native trust (§14.3).

**Effort warning.** Schannel is not a drop-in. A correct client requires the `AcquireCredentialsHandle` / `InitializeSecurityContext` loop with manual `SecBuffer` framing, `SECBUFFER_EXTRA` handling, `SEC_I_CONTINUE_NEEDED` and `SEC_E_INCOMPLETE_MESSAGE` state, `EncryptMessage`/`DecryptMessage` against `SECPKG_ATTR_STREAM_SIZES`, renegotiation, graceful shutdown via `ApplyControlToken`, and manual chain policy validation. Realistically **1,500–2,500 lines of security-critical code** — a material fraction of the entire size budget, and the single largest line item in §64.

Two specific hazards:

- TLS 1.3 requires `SCH_CREDENTIALS` (Windows 10 1809+); the older `SCHANNEL_CRED` path caps at TLS 1.2.
- **Measured (S1, 2026-09-07):** Rtools' mingw-w64 11.0 `schannel.h` does **not** declare `SCH_CREDENTIALS` or `TLS_PARAMETERS`, and raising the target to `_WIN32_WINNT=0x0A00` does not help — it is an incomplete header, not a version gate. See [spike/windows-schannel/FINDINGS.md](spike/windows-schannel/FINDINGS.md).

#### 13.5 Unix/Linux

Use system OpenSSL (`libssl`, `libcrypto`).

Requirements: distro trust configuration, OpenSSL default verification paths, custom CA file/path, hostname verification (`X509_VERIFY_PARAM_set1_host`, never a hand-rolled comparison), SNI, TLS 1.2+.

LibreSSL/BoringSSL compatibility is desirable but not guaranteed for v1.

### 14. Certificate Trust Model

#### 14.1 Defaults

```text
verify_peer     = TRUE
verify_hostname = TRUE
trust           = "system"
```

`zuhttp` must never default to disabling verification, and must not offer a single "insecure" switch that disables both peer and hostname checking without naming what it turns off.

```r
zu_request(
  "https://example.com",
  tls = zu_tls(verify = TRUE, ca = "system")
)
```

#### 14.2 Custom CA semantics

This is security-relevant and must not be left to implementation accident. **`ca_file` and `ca_data` REPLACE the system trust store; they do not add to it.**

```r
zu_tls(ca_file = "company.pem")   # ONLY company.pem is trusted
zu_tls(ca_data = raw_ca_bytes)    # ONLY these roots are trusted
```

This matches curl and OpenSSL behavior, but it routinely surprises users who expect additive behavior. To serve the common enterprise case explicitly, provide a separate additive argument:

```r
zu_tls(ca_extra = "corporate-root.pem")   # system trust PLUS this root
```

Both forms must be documented with the word "replaces" or "adds to" in the first sentence of their help text.

#### 14.3 Custom CAs and native trust stores

Additive trust is straightforward with OpenSSL (`X509_STORE_add_cert`). On Windows it requires building a temporary in-memory store with `CertOpenStore(CERT_STORE_PROV_MEMORY, ...)`, adding the extra roots, and passing it to `CertGetCertificateChain` as an additional store so that the system chain engine is still consulted. The engine/trust split in §13.1 keeps this confined to the trust evaluator.

**On macOS this is confirmed working (S0, F-6):**

```c
SecTrustSetAnchorCertificates(trust, anchors);
SecTrustSetAnchorCertificatesOnly(trust, replace ? true : false);   /* false => additive */
```

Proven by test: with a locally generated CA supplied additively, a public host still validates through system trust; with the same CA supplied as a replacement, the public host is correctly rejected. Both `ca_extra` and `ca_file` semantics are therefore implementable and distinguishable.

This also gives §50.5 a way to test custom-CA handling **without modifying the developer's or CI machine's Keychain**, which removes the main obstacle noted in §62 Q11.

#### 14.4 Certificate pinning

Support public-key pinning:

```r
zu_tls(pinned_public_key = "sha256//YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=")
```

Pinning is cheap to implement (hash the leaf `SubjectPublicKeyInfo` in the verify callback, compare against the pin set), and it is high-value for exactly the API-client workloads this package targets. It fits the "secure defaults" story better than several items currently in §3.2. Pinning is checked **in addition to**, never instead of, chain and hostname verification.

#### 14.5 Revocation

**Policy: revocation checking is OFF by default and opt-in.** An earlier draft claimed the platforms perform it "according to system policy". The S0 spike measured that claim and it is false on macOS:

```text
revoked.badssl.com, default policy   -> trust=SecTrust:yes   (ACCEPTED)
revoked.badssl.com, +revocation      -> TRUST REJECTED
```

`SecPolicyCreateSSL()` alone does no revocation checking. It must be combined explicitly:

```c
SecPolicyCreateRevocation(kSecRevocationUseAnyAvailableMethod |
                          kSecRevocationRequirePositiveResponse);
```

Two reasons to leave it off by default:

1. **Cost.** Trust evaluation went from ~4–9 ms to ~62 ms — 7–15× — because a positive response requires an OCSP/CRL fetch.
2. **It is an uninterruptible network call.** That fetch happens *inside* `SecTrustEvaluateWithError`. `zuhttp` neither owns it nor can deadline or cancel it, so it is invisible to the §24 timeout model and punches a hole in the §25 cancellation guarantee — the same class of gap as DNS (§8.4), but incurred by choice rather than by necessity.

Exposed as:

```r
zu_tls(revocation = TRUE)   # documents both the latency cost and the uninterruptible fetch
```

OpenSSL does not check revocation by default either. Windows/Schannel behavior must be measured in S3 rather than assumed. **Whatever the three platforms do, `zu_info()` (§39) must report the effective revocation policy**, because this is exactly the kind of silent asymmetry that produces "it works on my machine" bug reports.

OCSP stapling verification may be added later on the engine path; `zuhttp` performing its own OCSP fetching remains out of scope.

#### 14.6 Diagnosable failures

The library must expose enough information to distinguish, as separate condition classes (§34):

- certificate expired or not yet valid,
- hostname mismatch,
- unknown or untrusted issuer,
- revoked chain, where the platform reports it,
- handshake failure (version, cipher, or protocol-level),
- unsupported TLS version,
- pin mismatch.

A `zu_tls_error` whose message is only the backend's numeric code fails success criterion §61.9.

### 15. Native TLS Backend Interface

Proposed internal interface:

```c
typedef struct zu_tls_config zu_tls_config;
typedef struct zu_tls_conn zu_tls_conn;

int zu_tls_connect(
    zu_tls_conn **out,
    int socket_fd,
    const char *hostname,
    const zu_tls_config *config,
    zu_deadline deadline,
    zu_error *err
);

ssize_t zu_tls_read(
    zu_tls_conn *,
    void *buf,
    size_t len,
    zu_deadline deadline,
    zu_error *err
);

ssize_t zu_tls_write(
    zu_tls_conn *,
    const void *buf,
    size_t len,
    zu_deadline deadline,
    zu_error *err
);

void zu_tls_close(zu_tls_conn *);
```

Platform implementation must normalize backend-specific retry states such as:

```text
want-read
want-write
closed
fatal-error
```

### 16. Native System Configuration

Where practical, `zuhttp` should behave like the host system.

Windows:

- Schannel trust.
- potentially system proxy settings.

macOS:

- Keychain trust.
- potentially SystemConfiguration proxy settings.

Linux:

- OpenSSL default trust paths.
- environment proxy settings.

Environment variables should still permit explicit overrides.


---

## Part 4 — HTTP Semantics

### 17. HTTP Request Construction

Request builder responsibilities:

- Method.
- Request target (origin-form, or absolute-form when talking to an HTTP proxy).
- `Host`.
- Headers.
- `Content-Length`, or `Transfer-Encoding: chunked` for streaming request bodies (§28).
- Connection semantics.
- CONNECT requests (§20).

Example generated request:

```text
GET /api?q=1 HTTP/1.1\r\n
Host: example.com\r\n
User-Agent: zuhttp/0.1\r\n
Accept: */*\r\n
Accept-Encoding: gzip\r\n
Connection: keep-alive\r\n
\r\n
```

Implementation uses a checked growable buffer. All integer-to-string conversions must be overflow-safe.

#### 17.1 Header injection

- User header names must not contain CR, LF, NUL, or any character outside RFC 7230 `token`.
- User header values must not contain CR, LF, or NUL.
- Rejection is an error, never silent stripping — silent stripping turns an injection attempt into a subtly different request.
- The same rules apply to values `zuhttp` generates from user input: URLs in the request target, `Host` derived from a parsed URI, and proxy credentials.

#### 17.2 Default headers

`zuhttp` sends by default, each overridable and each removable:

| Header | Default | Notes |
|---|---|---|
| `Host` | from the URI | never user-settable to a conflicting value |
| `User-Agent` | `zuhttp/<version>` | |
| `Accept` | `*/*` | |
| `Accept-Encoding` | `gzip` | see §21.2 |
| `Connection` | `keep-alive` | `close` when pooling is disabled |

#### 17.3 `Expect: 100-continue`

**Policy: `zuhttp` does not send `Expect: 100-continue` automatically.**

Sending it requires waiting for a `100 Continue` before streaming the body, with a timeout for servers that never send one, and it interacts badly with the retry model. Users who need it may set the header explicitly, in which case `zuhttp` must honour the semantics: wait up to the `expect` timeout (default 1s) for a `100`, and send the body anyway on timeout.

Informational `1xx` responses are parsed and skipped in all cases (§18).

### 18. Response Parsing and Body Framing

The parser must correctly handle:

- status line,
- multiple informational `1xx` responses before the final response,
- response headers,
- `Content-Length` framing,
- `Transfer-Encoding: chunked` framing,
- connection-close framing,
- HEAD responses (headers may advertise a body length; no body is read),
- `204` and `304` responses (never have a body, regardless of headers).

#### 18.1 Framing precedence and smuggling defenses

The client is **strict, not permissive**. These rules are project-owned code, not delegated to the vendored parser (§8.1), and are the primary fuzz target (§43).

| Condition | Behavior |
|---|---|
| `Transfer-Encoding` present and final encoding is `chunked` | chunked framing; ignore any `Content-Length` |
| `Transfer-Encoding` present, final encoding is not `chunked` | **reject** — `zu_http_parse_error` |
| Both `Transfer-Encoding` and `Content-Length` present | **reject**, do not prefer one |
| Multiple `Content-Length` headers, differing values | **reject** |
| Multiple `Content-Length` headers, identical values | **reject** — permissiveness here has no upside for a client |
| `Content-Length` not a plain decimal, or overflows `uint64` | **reject** |
| Chunk size not valid hex, or overflows | **reject** |
| Chunk size exceeds `max_chunk_size` | **reject** |
| Neither framing header, response may have a body | read to connection close; connection is not poolable |
| Obsolete line folding (`obs-fold`) in headers | **reject** |
| Status line malformed, or status not three digits | **reject** |

A connection on which any of these rejections fires must be **closed, never returned to the pool** (§26.3).

#### 18.2 Chunked trailers

Trailer fields after the last chunk must be parsed, counted against `max_header_count` and `max_header_bytes`, and then **discarded** for v1. They must not be silently merged into the response header set — a trailer that overwrote `Content-Type` after the caller had already inspected headers would be a correctness trap. If trailers are ever exposed, it is through a separate `zu_resp_trailers()` accessor.

#### 18.3 Duplicate response headers

The response header container preserves order and repetition. Accessor semantics (§31.7):

- `zu_resp_headers(res)` returns all fields, in wire order, as a named character vector that may contain repeated names.
- `zu_resp_header(res, name)` is case-insensitive and returns a **character vector**, length 0 when absent, length > 1 when repeated. It never comma-joins.
- `zu_resp_header(res, name, join = TRUE)` returns the comma-joined value for the list-valued fields where that is well defined by RFC 7230.

`Set-Cookie` is explicitly *not* comma-joinable and is the reason the default is a vector rather than a scalar.

#### 18.4 Header limits

Every limit in §40 must be enforced **before** bytes reach the parser, not after. If the parser requires a contiguous header block (§8.1), then `max_header_bytes` is the allocation bound for that buffer and must be checked as the buffer grows.

### 19. Redirect Handling

#### 19.1 Method and body rewriting

"Correct method rewrite rules" is too vague to implement against. The table is normative:

| Status | Method rewrite | Body | Notes |
|---|---|---|---|
| 301 | POST → GET; others unchanged | dropped when rewritten | historical browser behavior, matches curl |
| 302 | POST → GET; others unchanged | dropped when rewritten | as above |
| 303 | any → GET (except HEAD, which stays HEAD) | **always dropped** | |
| 307 | **never** rewritten | **preserved** | body source must be rewindable (§28.2) |
| 308 | **never** rewritten | **preserved** | body source must be rewindable (§28.2) |

A 307/308 redirect with a non-rewindable body source is a `zu_redirect_error`, not a silent truncation.

#### 19.2 Header stripping

Strip on **any** change of scheme, host, or port — not only host:

- `Authorization`
- `Cookie`
- `Proxy-Authorization` (never forwarded to an origin under any circumstances, §20.4)
- any header the user has marked sensitive via `zu_headers(..., .sensitive = ...)`

Stripping is on cross-origin redirect, where origin is the (scheme, host, port) triple. A redirect from `https://api.example.com` to `https://other.example.com` strips credentials even though the registrable domain is shared.

#### 19.3 Downgrade policy

```text
allow HTTPS -> HTTP downgrade = FALSE   (default)
```

An HTTPS→HTTP redirect with the default policy is a `zu_redirect_error`, not a silent stop.

#### 19.4 Limits applied across the chain

These are chain-wide, not per-hop — otherwise a redirect chain multiplies every budget:

- `max_redirects` (default 10), exceeded → `zu_too_many_redirects`.
- The **total deadline** (§24) spans the entire chain.
- `max_body_bytes` applies to the cumulative body read across all hops.
- Loop detection: maintain the set of visited (method, absolute URL) pairs and fail on repeat.

#### 19.5 Interaction with sinks

**Redirect response bodies must never reach the caller's sink.** A `zu_get(url, file = "out.bin")` that follows two redirects must write only the final 200 body to `out.bin`. Intermediate bodies are read to completion (so the connection stays poolable) into a discard sink, subject to a small cap; a redirect response with a body larger than `max_redirect_body` closes the connection instead of draining it.

#### 19.6 Resolving the `Location` header

Relative `Location` values are resolved against the *current* request URL per
RFC 3986 §5 — that is, against the URL of the request that produced this
response, not against the original one. `zu_uri_resolve()` implements it
(§8.2).

Three rules that are not obvious from RFC 3986 alone:

- **Strict mode.** Resolution uses RFC 3986 §5.2.2 strict semantics, so an
  absolute `Location` with the same scheme as the base is *not* folded into the
  base. The non-strict variant exists only for legacy parsers.
- **A `Location` is a byte range, not a C string.** It points into the response
  buffer and is not NUL-terminated, so the parser is called with an explicit
  end pointer. Anything that scans for a terminator here reads other headers.
- **Resolution must not carry credentials.** The base is rebuilt as text
  *without* its userinfo before resolution, so the result never inherits
  credentials through the round-trip. Whether the redirect target may keep them
  is §19.2's decision, and §19.2 works on the struct.

The result is re-validated by the full §8.2 policy layer: a `Location` of
`ftp://…`, `//host:65536/`, or one containing a NUL is a `zu_url_error`, not a
followed redirect.

### 20. Proxy Support

#### 20.1 Environment variables

| Variable | Read | Notes |
|---|---|---|
| `http_proxy` | lowercase **only** | uppercase `HTTP_PROXY` is deliberately ignored |
| `https_proxy`, `HTTPS_PROXY` | both | |
| `all_proxy`, `ALL_PROXY` | both | fallback for both schemes |
| `no_proxy`, `NO_PROXY` | both | |

The lowercase-only rule for `http_proxy` follows curl and exists because in CGI-like environments the `HTTP_Proxy` request header is mapped into the environment as `HTTP_PROXY` (the "httpoxy" class of bug). R is not usually a CGI host, but matching curl's rule costs nothing and avoids a class of surprise.

An explicit `proxy =` argument or client setting always wins over the environment. `zu_client(proxy = NULL)` disables proxying entirely, distinctly from "not configured".

#### 20.2 `NO_PROXY` matching

Comma-separated. For each entry, matching against the request host is:

- `*` alone bypasses everything.
- A leading dot is ignored: `.example.com` and `example.com` both match `example.com` and any subdomain of it.
- Matching is on **domain-label boundaries**, case-insensitively. `example.com` matches `api.example.com` but not `notexample.com`.
- An entry may carry a port (`example.com:8080`), which must then also match.
- IP literals match exactly. **CIDR ranges are not supported** — curl does not support them either, and silently ignoring a CIDR entry would be worse than documenting the gap.

#### 20.3 Request forms

HTTP through a proxy uses absolute-form:

```text
GET http://example.com/path HTTP/1.1
```

HTTPS through a proxy tunnels:

```text
TCP -> proxy
CONNECT example.com:443 HTTP/1.1
200 Connection Established
TLS -> example.com
HTTP request
```

The CONNECT response must be parsed with the same strictness as any other response (§18). A non-2xx CONNECT is a `zu_proxy_error` carrying the proxy's status and any body, which is frequently the only diagnostic a user gets in a corporate environment.

#### 20.4 Credentials

Initial proxy authentication: none, and Basic. NTLM and Kerberos are non-goals (§4).

Rules:

- `Proxy-Authorization` is sent **only** on the connection to the proxy, and only on the CONNECT request for tunnelled HTTPS. It is never sent to the origin, never carried across a redirect (§19.2), and never present in a request the caller can observe through middleware aimed at the origin.
- Credentials embedded in a proxy URL (`http://user:pass@proxy:3128`) are parsed and immediately moved out of the URL, so the URL that appears in errors, traces, and `zu_resp_url()` is credential-free.
- Proxy credentials are redacted everywhere per §42.
- A pooled connection established through an authenticated proxy is keyed by proxy identity **including credentials** (§26.1), so that two clients with different proxy credentials cannot share a tunnel.

### 21. Content Encoding

#### 21.1 zlib, not miniz

**Decision: link system zlib. Do not vendor miniz.**

zlib is present on every platform R targets — R itself requires it, and Rtools ships it — so `PKG_LIBS = -lz` is standard, well-trodden practice for CRAN packages. Using it deletes roughly 10k vendored LOC, one fuzz target, and one security-tracking obligation, at essentially no portability cost.

`inflateInit2(&strm, 15 + 32)` enables automatic gzip/zlib header detection, which handles both wrappers with one code path.

A `--with-bundled-zlib` configure option may vendor miniz as a fallback for exotic platforms, but it is not the default and is not maintained as a first-class path.

```c
#define ZUHTTP_NO_COMPRESSION   /* compile-time removal of the whole module */
```

Brotli and zstd remain out of scope for v1 (§59).

#### 21.2 `Accept-Encoding` policy

**Decision: send `Accept-Encoding: gzip` by default and decompress transparently.** This matches httr2 and user expectation for REST workloads; curl's opt-in default is a libcurl-ism that surprises R users.

Consequences that must be documented:

- `zu_resp_raw(res)` returns the **decoded** body. Compression is a transport detail by default.
- The wire bytes are available only when the user opts out of transparent decoding via `zu_get(url, decode = FALSE)`, in which case `Content-Encoding` is left on the response and `zu_resp_raw()` returns exactly what arrived.
- `zu_resp_timings()` reports both `body_bytes_wire` and `body_bytes_decoded`.

#### 21.3 `deflate`

Servers disagree about `Content-Encoding: deflate`: some send zlib-wrapped data (RFC 1950, correct), others send raw DEFLATE (RFC 1951, common in the wild). The decoder attempts zlib-wrapped first and falls back to raw on a header error, which is what every practical client does.

#### 21.4 Decompression limits

Decompression is the cheapest denial-of-service vector in an HTTP client. Both limits from §40 are enforced *during* inflation, not after:

- `max_decompressed_bytes` — absolute cap on output.
- `max_decompression_ratio` — cap on output÷input, checked incrementally so a bomb fails early rather than after allocating.

Exceeding either raises `zu_body_limit_error` and closes the connection. The §50.2 corpus must include decompression bombs.

`Transfer-Encoding: gzip` (as opposed to `Content-Encoding: gzip`) is rejected under §18.1's rule that the only accepted transfer coding is `chunked`.

### 22. Cookies

Initial policy:

- No persistent cookie jar.

Support:

- manually supplied `Cookie`.
- exposing `Set-Cookie`.

A lightweight in-memory cookie implementation may be considered later only if there is clear demand.

Browser-grade cookie semantics are out of scope initially.

### 23. Multipart

Multipart support should not be part of the first implementation.

If added later, it should be a high-level request-body encoder, not embedded in the networking core.


---

## Part 5 — Runtime Model

### 24. Timeout Model

Structured timeout semantics are a key differentiator, so the semantics must be exact rather than suggestive.

```r
zu_timeout(
  connect = 5,
  tls     = 10,
  write   = 30,
  read    = 30,
  pool    = 2,
  total   = 60
)
```

#### 24.1 Definitions

| Phase | Meaning | Kind |
|---|---|---|
| `connect` | DNS resolution **and** TCP establishment | elapsed |
| `tls` | TLS handshake, from first byte sent to handshake complete | elapsed |
| `write` | maximum interval with **no forward progress** writing | inactivity |
| `read` | maximum interval with **no forward progress** reading | inactivity |
| `pool` | maximum wait to acquire a pooled connection (§26) | elapsed |
| `total` | deadline for the whole operation | elapsed |

`write` and `read` are inactivity timers, reset on every byte transferred. They bound stalls, not transfers — a legitimate 100 MB download must not fail because it took longer than `read`.

#### 24.2 Composition

The earlier phrasing "the total deadline overrides all phase deadlines" was ambiguous. The rule is:

```text
effective_deadline(phase) = min(now + phase_timeout, request_deadline)
```

where `request_deadline` is set once, from `total`, when the operation begins. Whichever fires first determines the error: a `total` expiry raises `zu_timeout_error` with `phase = "total"`, a phase expiry with `phase = "read"` and so on. The phase is part of the condition object (§34) because "which timeout fired" is the first thing a user needs to know.

#### 24.3 Scope of `total` across retries and redirects

**Decision: `total` is a wall-clock budget for the entire `zu_perform()` call — it spans all redirect hops and all retry attempts, and it is not reset between them.**

This is the safer default: it is the only reading under which `zu_get(url, timeout = 30)` actually returns within 30 seconds. Under the per-attempt reading, three retries with exponential backoff can run for minutes.

For the cases where a per-attempt bound is genuinely wanted, `zu_retry()` carries its own `attempt_timeout`:

```r
zu_retry(attempts = 3, attempt_timeout = 10)   # each try ≤ 10s, all tries ≤ total
```

The retry layer must check the remaining budget *before* sleeping for backoff, and fail immediately rather than sleep past the deadline.

#### 24.4 Clocks

All deadlines use a monotonic clock (`clock_gettime(CLOCK_MONOTONIC)`, `QueryPerformanceCounter`), never wall time — a system clock adjustment mid-request must not extend or collapse a deadline.

#### 24.5 Defaults

No timeout may be infinite by default. A client with no configured timeout still gets `total = 300`, on the reasoning that a hung R session is a worse failure than a spuriously failed request.

### 25. R Cancellation and Interrupts

Cancellation is a first-class architectural property, and it is the property most likely to be quietly broken by an implementation shortcut.

```r
zu_get("https://slow.example.com")
# Ctrl-C reliably aborts the operation
```

#### 25.1 Model

1. All sockets are non-blocking.
2. Poll in bounded intervals (≤ 100 ms).
3. Return to an R-safe checkpoint between polls.
4. Call `R_CheckUserInterrupt()` only at such a checkpoint.
5. Unwind cleanly.

Native code must never sit inside an indefinitely blocking call. No worker thread may call the R API.

#### 25.2 The longjmp problem

Steps 4 and 5 above are in tension, and previous drafts glossed over it. **`R_CheckUserInterrupt()` does not return when an interrupt is pending — it longjmps past every C stack frame between it and the enclosing `tryCatch`.** Local variables holding sockets, TLS contexts, zlib streams, and buffers are simply abandoned. The same applies to any error raised by R code called from C (§27.3).

Exactly one of these disciplines must be adopted, and the choice recorded:

**(a) `R_UnwindProtect()`** (R ≥ 3.5). Wrap the request loop; the cleanup handler closes the stream, frees buffers, and marks the connection unpoolable. Explicit and local, but every native entry point must be wrapped.

**(b) Ownership by external pointer.** All native state reachable from an R external pointer with a registered finalizer *before* any interrupt checkpoint is reached. A longjmp then leaks nothing, because the GC will run the finalizer. Requires that no allocation live only in a C local across a checkpoint — a rule that is easy to state and easy to violate silently.

**Recommendation: (b) as the invariant, (a) as the enforcement mechanism.** State ownership is by external pointer, and the request loop is additionally wrapped in `R_UnwindProtect()` so that resources are released promptly rather than at the next GC. This is checked by the ASan/valgrind interrupt tests in §45.

#### 25.3 Connection state after cancellation

**An interrupted connection must never return to the pool.** After a longjmp the framing position is unknown — the response may be half-read — and reusing it would splice one caller's response into another's. Cancellation closes the socket. This is the same rule as §18.1's rejection path and §26.3.

#### 25.4 Platform notes

- On Windows, interrupt delivery in GUI front-ends is tied to the event loop; a long poll loop may need `R_ProcessEvents()` alongside `R_CheckUserInterrupt()` for Ctrl-C to be observed in Rgui and RStudio. This must be verified on all three front-ends, not just the terminal.
- **DNS is not interruptible** in the MVP (§8.4). A request blocked in `getaddrinfo()` will not respond to Ctrl-C until the resolver returns. This limitation must be documented in user-facing help, not just here.

#### 25.5 Explicit cancellation

A request-scoped cancellation token may later support programmatic cancellation independent of user interrupts, which is a prerequisite for §30. It uses the same checkpoint machinery.

### 26. Connection Pool

Connection reuse is essential for competitive performance (§51).

#### 26.1 Pool key

Two requests may share a connection only if **every** component matches:

- scheme,
- host (as written, pre-resolution),
- port,
- proxy identity **including credentials** (§20.4),
- full TLS configuration: verify flags, CA source, pin set, minimum version, ALPN,
- client certificate identity,
- the owning process ID (§26.4).

TLS configuration must be compared by value, not by pointer identity, or two clients built from the same settings will fail to share a pool for no reason. Conversely, a coarse key that ignores any of the above is a security bug, not a performance optimisation.

#### 26.2 Policy

- keep-alive, honouring `Connection: close` from either side,
- maximum idle connections (global),
- idle timeout,
- per-host limit,
- global limit,
- stale-connection detection: a pooled socket that is readable before a request is written has been closed or has unread data, and is discarded.

Initial defaults are conservative.

```r
client <- zu_client(
  pool = zu_pool(max_idle = 16, max_per_host = 4, idle_timeout = 30)
)
```

#### 26.3 When a connection must NOT be reused

Reuse requires that the response body was read to completion and the framing is unambiguous. Discard the connection when:

- the body was not fully consumed (including an early `return()` from a streaming callback),
- the request was cancelled or timed out (§25.3),
- any framing rejection from §18.1 fired,
- the response used connection-close framing,
- either side sent `Connection: close`,
- a redirect response body exceeded `max_redirect_body` (§19.5),
- a TLS error occurred at any point.

The safe default is to close. A pool that is slightly too eager to discard costs latency; one that is slightly too eager to reuse corrupts responses.

#### 26.4 Fork safety

**This is the failure mode most likely to reach a user first, and the S0 spike showed it is worse on macOS than this section originally assumed.**

`parallel::mclapply()`, `parallel::mcparallel()`, and `future`'s `multicore` plan all fork the R process. There are **two** distinct hazards.

##### Hazard 1: inherited connections

A forked child inherits the parent's descriptors, including live pooled TLS connections. If parent and child both write into the same TLS session, the session is corrupted and the failure is nondeterministic and remote.

This is not hypothetical. Measured against R's `curl` — a mature, unrelated implementation — on macOS:

```text
parent https request               ok
mclapply after parent request ->   200 | ERR: Error in the HTTP2 framing layer
```

Required behavior:

- Every pool records the `getpid()` of the process that created it.
- Every acquisition compares the current PID. On mismatch, **all inherited connections are dropped without a graceful TLS shutdown** — a graceful close from the child would write to a socket the parent still owns — the descriptors are released, and the pool is re-initialised.

##### Hazard 2: the trust evaluator does not survive fork (macOS)

Security.framework opens an XPC connection to `trustd` on first use. **That connection does not survive `fork()`.** Measured (S0, F-5):

```text
A. parent evaluates trust, then forks -> child KILLED by signal 11 (SIGSEGV)
B. parent never evaluates, then forks -> child SURVIVED
```

It is fork-*after-use*, not fork-at-all. So this ordinary-looking R code kills the worker processes:

```r
zu_get("https://api.example.com/x")               # parent does one HTTPS request
parallel::mclapply(urls, function(u) zu_get(u))   # every child segfaults
```

**Dropping inherited connections does not help here.** The sockets are not the problem; the child cannot call the trust API at all.

Required behavior: **the PID guard extends from the pool to the trust evaluator.** On a PID mismatch, refuse to evaluate trust and raise an actionable condition rather than letting the process die:

```text
Error: zuhttp cannot make HTTPS requests in a forked process on macOS.
  The system trust evaluator (Security.framework) does not survive fork().
  * Use a PSOCK cluster or future::plan("multisession") instead of
    mclapply() / future::plan("multicore").
  * See ?zuhttp_fork.
```

`PSOCK` clusters and `plan("multisession")` are safe because they `exec` fresh R processes.

Turning a SIGSEGV into a named condition is the whole mitigation. It does not make forked HTTPS work; it makes the limitation diagnosable. **Until it exists, `zuhttp` has a worse macOS fork failure mode than `curl`** — a crash rather than an error — and §6.1 must say so.

`pthread_atfork()` is not sufficient and is unavailable on Windows; the PID check is the portable mechanism and must run on every pool acquisition and every trust evaluation.

#### 26.5 Serialization and session lifetime

A `zu_client` is an ordinary R object holding an external pointer to native pool state. Users will `saveRDS()` clients, put them in package-level variables that survive `save.image()`, and restore them in a new session, where the external pointer address is meaningless.

Required behavior:

- The external pointer is tagged, and a restored (null) pointer is detected on first use.
- A client whose pool pointer is dead **lazily re-creates** its pool from the retained configuration rather than erroring. Configuration is plain R data and survives serialization; connections do not.
- This is what makes §31.1 Principle 6's "value-like semantics" claim actually true across sessions.

### 27. Streaming Model

One core body-sink abstraction powers in-memory responses, file downloads, R connections, and callback streaming.

```c
typedef int (*zu_body_sink)(
    const unsigned char *data,
    size_t               size,
    void                *context
);
```

Built-in sinks: `memory`, `file`, `discard`, R connection, R callback.

Large responses must not require whole-body allocation.

#### 27.1 Sinks and limits

`max_body_bytes` (§40) applies to every sink including `file` — an unbounded download to disk is still a denial-of-service vector, just against a different resource. The file sink writes to a temporary file in the same directory as the destination and renames on success, so an interrupted or failed download never leaves a truncated file at the target path.

#### 27.2 Calling back into R

R callbacks are subject to hard rules:

- Only on the main R thread. Never from an asynchronous worker.
- All R objects reachable from the callback are protected across the call.
- The callback's return value controls flow: a sentinel return stops the transfer cleanly, which then makes the connection unpoolable (§26.3).

#### 27.3 Callback errors and the longjmp hazard

A user callback can raise an R error. That error longjmps out of the middle of the C read loop, past the socket, the TLS context, and the inflate stream — the identical hazard to §25.2, and it must use the identical mechanism. "Convert callback errors into controlled cancellation" is only implementable as:

1. Invoke the callback through `R_tryCatch()` / `R_UnwindProtect()`, never as a bare `Rf_eval()`.
2. On a caught condition, record it, unwind the native loop normally, release the connection, and **re-signal** the original condition to the caller so that the user's error is what they see — not a `zu_*` error that has swallowed it.

#### 27.4 Re-entrancy

A streaming callback runs arbitrary R code, which may call `zu_get()` again — directly, or indirectly through some package the user calls.

**Policy: re-entrant requests are permitted, but a callback may not issue a request on the client whose connection it is currently reading from.** That is detected (a per-client "in callback" depth counter) and raises an error naming the problem, rather than deadlocking on a pool slot or interleaving writes onto a live connection. Requests through a *different* client are unrestricted.

#### 27.5 R connections as sinks

R connections are convenient but go through R's own buffering and may not be performant enough for high-throughput streaming (§62). The connection sink must therefore be implemented in terms of the same `zu_body_sink` contract, so it can be benchmarked against, and swapped for, the raw file sink without touching the engine.

### 28. Request Body Sources

Initial sources: raw vector, character scalar, file, `NULL`.

Later: R connection, callback producer, streaming generator.

#### 28.1 Framing

A body of known size sets `Content-Length`. A body of unknown size requires `Transfer-Encoding: chunked` on the request, which some servers and many proxies reject — so `zuhttp` prefers a known length wherever it can compute one, including stat-ing a file body.

Streaming request bodies may be deferred past v1 (§57), but the body abstraction below must exist from the start so that adding them is not a breaking change.

#### 28.2 Rewindability

§33 requires that retried and 307/308-redirected requests replay their body. §19.1 requires the same. Neither is implementable unless rewindability is a **property of the body object**, checked mechanically rather than by convention:

| Source | Rewindable | Replay mechanism |
|---|---|---|
| `NULL` | yes | trivially |
| raw vector | yes | re-read from memory |
| character scalar | yes | re-read from memory |
| file | yes | `lseek()` to origin; the file must not have changed size |
| R connection | **no** | — |
| callback producer | **no** unless the caller supplies a `rewind` function | caller-provided |

```r
zu_body_stream(producer, rewind = NULL)   # not replayable
zu_body_stream(producer, rewind = function() ...)  # replayable
```

The retry layer (§33) and the redirect layer (§19.1) both query `zu_body_rewindable(req)` and refuse rather than truncate. A non-rewindable body that would need replay produces `zu_body_not_replayable`, a distinct condition class, so the caller can tell it apart from a transport failure.

#### 28.3 Body and content type

Semantic body constructors set `Content-Type` unless the user has set one explicitly:

| Constructor | `Content-Type` |
|---|---|
| `zu_body_json()` | `application/json` |
| `zu_body_form()` | `application/x-www-form-urlencoded` |
| `zu_body_file()` | none — the caller sets it |
| `zu_body_raw()` | none — the caller sets it |

An explicit user header always wins; a semantic constructor never overwrites one.

### 29. Threading and Process Model

#### 29.1 Threading

Initial version: **single-threaded**.

- The R API is touched only on the main R thread.
- No background networking threads.
- Concurrency, when it comes, arrives via poll-based multiplexing and multiple connection state machines (§30), not hidden threads.

The one candidate exception is a DNS helper thread (§8.4), which would never call the R API and would communicate only through a self-pipe. It is not in the MVP.

#### 29.2 Process model

R programs fork. This has three consequences that the design must handle rather than discover:

1. **Connection pools must not be shared across a fork** — §26.4.
2. **Native RNG or global state must not be assumed unique** — `zuhttp` keeps no mutable process-global state beyond the default client, which is itself PID-guarded.
3. **Finalizers may run in a forked child** for objects the parent still owns. External-pointer finalizers must therefore also check the PID before closing a descriptor, or a child's GC will close the parent's socket.
4. **On macOS, Security.framework cannot be used at all in a forked child** once the parent has used it (§26.4, hazard 2). This is a platform constraint `zuhttp` cannot engineer around; it can only be detected and reported.

Note that after the first HTTPS request the R process is **multithreaded** whether or not `zuhttp` creates any threads: Security.framework's XPC connection to `trustd` adds two threads (measured: 1 → 3, stable thereafter). §29.1's "single-threaded" claim describes threads `zuhttp` manages, not the process.

#### 29.3 Object lifetime across sessions

Covered in §26.5. Summarised as an invariant: **configuration is R data and survives serialization; native resources are external pointers and do not.** Any public object must be usable after a `saveRDS()`/`readRDS()` round-trip, re-creating native state lazily.

#### 29.4 Thread safety of public objects

A `zu_client` is not thread-safe and does not need to be, since R is single-threaded. It must, however, be safe to use the *same* client from nested contexts on the one thread — see the re-entrancy rule in §27.4.

### 30. Async / Multiplexing Roadmap

#### 30.1 Phases

**Phase 1** — synchronous requests, one at a time. This is the MVP (§57).

**Phase 2** — multiple in-flight HTTP/1.1 requests over separate connections, driven by poll/select from a single thread.

HTTP/2 is explicitly not required to achieve concurrency; parallel HTTP/1.1 connections are sufficient for the workloads in scope (§60).

#### 30.2 Integrate with `later`, do not invent an event loop

A bespoke `zu_multi()` / `zu_submit()` / `zu_poll()` API would be a third event loop in the R ecosystem and would not compose with anything.

If concurrency ships, it should integrate with **`later`** — the event loop already used by shiny, httpuv, and plumber — by registering the request's file descriptors and resuming state machines from `later` callbacks. That is compatible with §29's no-hidden-threads stance, and it makes `zuhttp` usable from inside a Shiny app or plumber route without blocking the server.

A `promises`-returning surface is the natural public API:

```r
p <- zu_perform_async(client, req)   # returns a promise
```

The synchronous `zu_perform()` remains the primary API and must never be implemented as "start async, then block" — that would drag the event loop into every synchronous call.

#### 30.3 Not planned

- HTTP pipelining. It is unsafe with intermediaries and superseded by parallel connections.
- Request multiplexing over a single connection. That is HTTP/2 (§60).

Whether asynchronous concurrency belongs in this package at all remains an open question (§62); a strong case exists for leaving it to a higher layer.

## Part 6 — R API

### 31. Functional R API Design

The public R API is a major part of the project's differentiation. The goal is not merely to expose the C transport cleanly; it is to provide an API that feels idiomatic in R while incorporating the strongest ergonomic ideas from modern HTTP libraries.

The design should combine:

- **httr2**: immutable-style request composition and a clear build/perform boundary.
- **Python Requests**: obvious one-line GET/POST calls for common cases.
- **HTTPX**: reusable clients, connection pooling, explicit transports, and clear client/request configuration merging.
- **JavaScript Fetch**: simple `Request -> perform -> Response` conceptual model and separation of response metadata from body decoding.
- **Ky**: concise policy configuration for retries, hooks, timeouts, and derived clients.
- **Rust reqwest**: separation of reusable client configuration from request construction and execution.

The API should offer **three levels of abstraction**, all backed by the same request representation rather than three unrelated implementations.

---

#### 31.1 Design principles

##### Principle 1: Simple things must be simple

A normal GET should require only:

```r
res <- zu_get("https://example.com")
```

A JSON POST should be similarly obvious:

```r
res <- zu_post(
  "https://api.example.com/users",
  json = list(name = "Alice")
)
```

Users should not be forced through a request-builder pipeline for ordinary operations.

##### Principle 2: Composition must remain first-class

Package authors and advanced users should be able to build a request without performing I/O:

```r
req <- zu_request("POST", "https://api.example.com/users") |>
  zu_headers(Accept = "application/json") |>
  zu_body_json(list(name = "Alice")) |>
  zu_req_timeout(total = 10)
```

Execution occurs only at an explicit boundary:

```r
res <- zu_perform(req)
```

This preserves the important separation between **request construction** and **network effects**.

##### Principle 3: One internal request model

These:

```r
zu_post(url, json = x, timeout = 10)
```

and:

```r
zu_request("POST", url) |>
  zu_body_json(x) |>
  zu_req_timeout(total = 10) |>
  zu_perform()
```

must lower to the same internal request representation.

Convenience functions are syntax, not separate implementations.

##### Principle 4: Clients own reusable policy and resources

A client should own:

```text
base URL
default headers
connection pool
TLS policy
proxy policy
timeouts
retry policy
middleware
transport
```

Requests own request-specific state.

Responses own response-specific state.

##### Principle 5: Response decoding is explicit

Receiving a successful HTTP response and interpreting its body are separate operations.

```r
res <- zu_get(url)

zu_resp_status(res)
zu_resp_headers(res)

zu_resp_raw(res)
zu_resp_text(res)
zu_resp_json(res)
```

The transport should not guess that JSON should automatically become an R object merely because the content type is JSON.

##### Principle 6: Functional rather than R6-first

The primary API should use ordinary R objects and functions.

```r
client2 <- zu_client_update(client, timeout = 5)
```

should return a modified client without mutating the original client configuration from the user's perspective.

The internal implementation may use external pointers or mutable connection-pool state, but the public configuration API should retain value-like semantics.

---

#### 31.2 API level 1: one-shot convenience functions

The lowest-friction API should resemble Requests/HTTPX:

```r
zu_get(url)
zu_head(url)
zu_post(url)
zu_put(url)
zu_patch(url)
zu_delete(url)
```

Examples:

```r
zu_get(
  "https://api.example.com/search",
  query = list(q = "HTTP", limit = 20)
)
```

```r
zu_post(
  "https://api.example.com/users",
  json = list(
    name = "Alice",
    active = TRUE
  )
)
```

```r
zu_post(
  "https://example.com/upload",
  body = raw_data,
  headers = c("Content-Type" = "application/octet-stream")
)
```

Common arguments SHOULD include:

```text
query
headers
body
json
form
file
timeout
retry
client
```

Body arguments such as `body`, `json`, `form`, and `file` are mutually exclusive.

Semantic body arguments should automatically set appropriate HTTP metadata where unambiguous. For example, `json =` should JSON-encode the body and set `Content-Type: application/json` unless explicitly overridden.

---

#### 31.3 API level 2: reusable clients

Reusable clients should follow the strongest ideas from HTTPX and reqwest.

Example:

```r
api <- zu_client(
  base_url = "https://api.example.com",
  headers = c(
    Accept = "application/json",
    Authorization = paste("Bearer", token)
  ),
  timeout = zu_timeout(total = 30),
  retry = zu_retry(attempts = 3)
)
```

Requests can then be concise:

```r
zu_get("/users", client = api)

zu_post("/users", json = list(name = "Alice"), client = api)
```

##### The client is never the first argument

An earlier draft overloaded argument 1 by type — `zu_get(url)` *and* `zu_get(client, path)`. That is rejected. Positional polymorphism breaks autocomplete, makes S3 dispatch murky, and turns a misplaced argument into a confusing error rather than a clear one. **The first argument of every request function is always the URL or path; the client is always a named `client =` argument.**

```r
zu_get(url, ..., client = zu_default_client())
zu_perform(req, client = zu_default_client())
```

For readers who prefer client-first phrasing, pipe-friendly wrappers are provided as a thin layer, not as an overload:

```r
api |> zu_client_get("/users")
```

The client owns the connection pool, so reuse is both an ergonomic and performance feature.

A one-shot call without an explicit client uses a package-managed default client and pool. That default is PID-guarded (§26.4), is configurable through `zu_set_default_client()`, and is reported by `zu_info()` so its configuration is never invisible.

---

#### 31.4 API level 3: explicit functional request composition

For advanced use:

```r
req <- zu_request("POST", "/users") |>
  zu_query(verbose = TRUE) |>
  zu_headers(Accept = "application/json") |>
  zu_body_json(list(name = "Alice")) |>
  zu_req_timeout(total = 10) |>
  zu_req_retry(attempts = 3)
```

Then:

```r
res <- zu_perform(req, client = api)
```

or, for an absolute URL and the default client:

```r
res <- zu_perform(req)
```

The request object should be inspectable and printable before execution.

Example print:

```text
<zu_request>
POST https://api.example.com/users?verbose=true
Accept: application/json
Content-Type: application/json
Body: JSON, 16 bytes
Timeout: 10 s
Retries: 3
```

This makes debugging and testing easier than opaque transport options.

---

#### 31.5 Method and URL are request identity

Unlike APIs where the HTTP method is configured later as a modifier, `zuhttp` should treat method and target as fundamental request identity:

```r
zu_request("POST", url)
```

rather than requiring:

```r
zu_request(url) |>
  zu_method("POST")
```

Method-specific helpers:

```r
zu_get()
zu_post()
zu_put()
zu_patch()
zu_delete()
```

are convenience wrappers around `zu_request()`.

Arbitrary methods remain possible:

```r
zu_request("PROPFIND", url)
```

even though non-HTTP/1.1 protocol families remain out of scope.

---

#### 31.6 Request body ergonomics

The one-shot API should use semantic mutually exclusive body arguments:

```r
zu_post(url, json = x)
zu_post(url, form = x)
zu_post(url, body = raw)
zu_post(url, file = path)
```

The composable equivalents are:

```r
req |> zu_body_json(x)
req |> zu_body_form(x)
req |> zu_body_raw(raw)
req |> zu_body_file(path)
```

This keeps the common API concise while preserving explicit request transformation for package code.

Future streaming bodies may add:

```r
zu_body_stream()
```

without changing the existing model.

---

#### 31.7 Response ergonomics

Responses should be deliberately simple and inspectable.

```text
<zu_response [200 OK]>
GET https://api.example.com/users
Content-Type: application/json
Body: 8.2 kB in memory
Total: 124 ms
TLS: OpenSSL 3.0 (TLS 1.3) / trust: system
Connection: reused
```

Primary accessors:

```r
zu_resp_status(res)
zu_resp_ok(res)

zu_resp_headers(res)
zu_resp_header(res, "content-type")

zu_resp_raw(res)
zu_resp_text(res)
zu_resp_json(res)

zu_resp_url(res)
zu_resp_timings(res)

zu_resp_check(res)
```

The accessor-function API is the stable contract; `$status`, `$body` and friends are not. This leaves room for lazy or streaming response representations later — and it is why §35 exposes timings as `zu_resp_timings(res)` rather than `res$timings`.

`zu_resp_check()` raises structured conditions for HTTP error statuses according to the policy in §31.14.

##### Header accessors

Semantics are specified in §18.3: `zu_resp_header()` is case-insensitive and returns a character vector (length 0 when absent, length > 1 when repeated), never a comma-joined scalar. `Set-Cookie` is why.

##### `zu_resp_raw()` returns decoded bytes

Because `Accept-Encoding: gzip` is sent by default and decompression is transparent (§21.2), `zu_resp_raw()` returns the **decoded** body. Wire bytes require `decode = FALSE` on the request. This must be the first line of the function's documentation — a user who checksums `zu_resp_raw()` against a server-side hash needs to know which bytes they have.

##### `zu_resp_text()` and character encoding

Text decoding is where R HTTP clients traditionally go wrong, so the rule is explicit:

1. If the caller passes `encoding =`, use it.
2. Otherwise use the `charset` parameter of `Content-Type`, if present and recognised by `iconv`.
3. Otherwise, if the body begins with a UTF-8, UTF-16LE, or UTF-16BE BOM, use that and strip the BOM.
4. Otherwise default to **UTF-8**, not the ISO-8859-1 that RFC 7231 nominally implies. The RFC default is a historical artifact; UTF-8 is right far more often, and being wrong in the other direction produces mojibake that users misattribute to the server.
5. For `application/json`, RFC 8259 mandates UTF-8, so steps 2–4 are skipped.

The result is always marked UTF-8. Invalid byte sequences raise `zu_body_decode_error` rather than producing silently corrupted strings; `zu_resp_text(res, on_invalid = "substitute")` opts into lossy conversion.

##### JSON

`zu_resp_json()` and `zu_body_json()` need a JSON implementation, which is in tension with the minimal-dependency goal in §1. **Decision: `jsonlite` in `Suggests`, not `Imports`.**

- The JSON helpers check for it and raise an informative error naming the package if it is absent.
- Everything else in `zuhttp` — including sending a JSON body the caller has already serialised — works without it.
- `zu_set_json_backend()` allows substituting another implementation, so a package author with a different preference is not forced to take `jsonlite` transitively.

This keeps the hard dependency count at zero while making the common path work for anyone who has `jsonlite`, which in practice is nearly everyone.

---

#### 31.8 Response body lifecycle

The API should distinguish:

```text
response headers available
          |
          +--> in-memory body
          |
          +--> streaming body
          |
          +--> file sink
```

A response object may therefore represent either:

- a fully consumed body, or
- a live body stream.

The exact streaming API can evolve, but body decoding helpers must clearly document whether they consume the stream.

This follows the useful conceptual separation in Fetch/HTTPX between response metadata and body consumption.

---

#### 31.9 Client/request configuration merge rules

Configuration merging must be deterministic and documented.

Adopt an HTTPX-like rule:

##### Collection-like options merge

Client and request values are combined for:

```text
headers
query parameters
possibly cookies if later supported
```

Example:

```r
api <- zu_client(
  headers = c(
    Accept = "application/json",
    Authorization = "Bearer xxx"
  )
)

zu_get("/users", headers = c("X-Debug" = "1"), client = api)
```

produces all three headers unless the request explicitly replaces a same-name client header.

##### Scalar/policy options override

Request-level values replace client defaults for:

```text
timeout
retry policy
TLS override
proxy override
redirect policy
body
method
```

Example:

```r
api <- zu_client(timeout = 30)

zu_get("/slow", timeout = 5, client = api)
```

uses five seconds for that request.

##### Removing an inherited value

Merging needs an eraser, or a client header becomes impossible to unset at the request level. `NA` in a header vector removes the inherited field:

```r
zu_get("/public", headers = c(Authorization = NA), client = api)
```

`NULL` for a policy option resets it to the package default rather than to the client's value:

```r
zu_get("/slow", timeout = NULL, client = api)   # package default, not api's 30s
```

Both forms must be documented next to the merge table, since "how do I turn this off" is the first question the merge rules provoke.

---

#### 31.10 Derived clients

Configured clients should be easy to derive without mutation:

```r
api <- zu_client(
  base_url = "https://api.example.com",
  headers = c(Accept = "application/json")
)

admin_api <- zu_client_update(
  api,
  headers = c(Authorization = paste("Bearer", admin_token))
)
```

`api` remains unchanged from the caller's perspective.

This is useful for:

```text
base API client
  |
  +-- authenticated API client
  |
  +-- admin API client
  |
  +-- test transport client
```

The underlying connection pool may optionally be shared when configuration is compatible.

---

#### 31.11 Client and request naming

The API should avoid redundant or overly long prefixes while preserving discoverability.

Core constructors/execution:

```r
zu_client()
zu_client_update()

zu_request()
zu_get()
zu_head()
zu_post()
zu_put()
zu_patch()
zu_delete()

zu_perform()
```

Request transformers:

```r
zu_query()
zu_headers()

zu_body_json()
zu_body_form()
zu_body_raw()
zu_body_file()

zu_req_timeout()
zu_req_retry()
zu_req_redirects()
```

Response functions use a distinct `zu_resp_` prefix:

```r
zu_resp_status()
zu_resp_headers()
zu_resp_json()
zu_resp_text()
zu_resp_raw()
zu_resp_check()
```

Exact naming should be evaluated through prototype usage before being frozen.

---

#### 31.12 Transport as an explicit client dependency

Borrow HTTPX's low-level transport concept.

Default:

```r
client <- zu_client(
  transport = zu_native_transport()
)
```

Testing:

```r
client <- zu_client(
  transport = zu_mock_transport(function(req) {
    zu_response(
      status = 200,
      body = charToRaw('{"ok":true}'),
      headers = c("Content-Type" = "application/json")
    )
  })
)
```

This makes transport substitution a supported architectural mechanism rather than a testing hack.

Potential transports:

```text
native
mock
record/replay
Unix-domain socket
custom package-provided transport
```

---

#### 31.13 Middleware and hooks

Middleware should compose around request execution rather than becoming flags in the C core.

##### Policy is not middleware

An earlier draft passed `zu_retry()` both as a `retry =` policy argument and as an entry in `middleware = list(...)`. It cannot be both. The split is:

- **Policy objects** are declarative configuration with dedicated arguments: `timeout =`, `retry =`, `redirects =`, `tls =`, `proxy =`. They are built by `zu_timeout()`, `zu_retry()` and friends, and they are merged per §31.9.
- **Middleware** is user-supplied behavior: a function of `(req, next)` returning a response. `middleware =` takes only these.

Built-in policies are implemented internally as middleware, but they are not *configured* that way — otherwise ordering, merging, and `zu_client_update()` all become ambiguous.

```r
client <- zu_client(
  retry      = zu_retry(attempts = 3),
  auth       = zu_bearer_token(token),
  middleware = list(my_logging_middleware, my_signing_middleware)
)
```

Conceptually:

```text
request
   |
middleware 1
   |
middleware 2
   |
middleware 3
   |
transport
```

The transport remains responsible only for network semantics.

Hooks may expose lifecycle events such as:

```text
before_request
after_response
before_retry
after_retry
```

Lower-level observability events remain separate from policy middleware.

---

#### 31.14 Error-status philosophy

The project should distinguish:

```text
transport failure
HTTP response with error status
body-decoding failure
```

A valid `404` is still an HTTP response, even if high-level convenience APIs choose to signal it.

Recommended design:

```r
res <- zu_get(url)
```

uses a configurable default HTTP-status policy.

Users can always opt into raw response semantics:

```r
res <- zu_get(url, check = FALSE)
```

and then:

```r
zu_resp_check(res)
```

This gives R users convenient defaults without conflating network failures with HTTP status codes internally.

---

#### 31.15 API design references

These projects are **design references, not runtime dependencies**.

| Project | Ideas to borrow | Reference |
|---|---|---|
| **httr2** | Functional request transformation; explicit request construction and `req_perform()` execution boundary; R-native condition style | https://httr2.r-lib.org/reference/request.html and https://httr2.r-lib.org/reference/req_perform.html |
| **Python Requests** | Obvious one-shot method helpers; semantic `json=` body parameter; simple response access | https://requests.readthedocs.io/en/latest/user/quickstart/ |
| **HTTPX** | Reusable client; connection pooling; client/request configuration sharing and deterministic merging; explicit request instances; custom/mock transports; phase-specific timeout model | https://www.python-httpx.org/advanced/clients/ , https://www.python-httpx.org/advanced/transports/ , https://www.python-httpx.org/advanced/timeouts/ |
| **Fetch API** | `Request -> fetch -> Response` mental model; response headers/status separated from subsequent body consumption | https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API |
| **Ky** | Compact retry/timeout/hook policy configuration; derived configured clients layered on Fetch | https://github.com/sindresorhus/ky |
| **reqwest** | Reusable client with connection pool; client builder; request builder with query, headers, auth, body, JSON, timeout, and explicit send | https://docs.rs/reqwest/latest/reqwest/blocking/struct.Client.html and https://docs.rs/reqwest/latest/reqwest/blocking/struct.RequestBuilder.html |

The intended synthesis is:

```text
Requests-level simplicity
        +
httr2-level functional composition
        +
HTTPX client/transport architecture
        +
Fetch response/body model
        +
Ky policy ergonomics
        +
reqwest client/request layering
        =
zuhttp public API
```

The API should be judged by a practical rule:

> A new R user should be able to guess how to make a GET or JSON POST, while a package author should be able to construct, inspect, transform, mock, retry, and execute a request without bypassing the public abstraction.

---

#### 31.16 Initial API sketch

A minimal coherent first API could be:

```r
# one-shot  (client is always a named argument, never positional)
zu_get(url, ..., client = zu_default_client())
zu_post(url, ..., client = zu_default_client())

# reusable configuration/resources
zu_client(...)
zu_client_update(client, ...)

# explicit construction
zu_request(method, url)
zu_query(req, ...)
zu_headers(req, ...)
zu_body_json(req, x)
zu_body_raw(req, x)
zu_req_timeout(req, ...)
zu_req_retry(req, ...)

# execution
zu_perform(req, client = zu_default_client())

# response
zu_resp_status(res)
zu_resp_ok(res)
zu_resp_headers(res)
zu_resp_header(res, name)
zu_resp_raw(res)
zu_resp_text(res)
zu_resp_json(res)
zu_resp_timings(res)
zu_resp_check(res)
```

Before the API is frozen, prototype it against at least these workflows:

1. One-line GET.
2. JSON POST.
3. API client with bearer token and base URL.
4. Package function that builds but does not immediately execute a request.
5. Retried idempotent request.
6. Streaming download.
7. Mocked package test.
8. Custom timeout on one request overriding client defaults.
9. Redirect/error inspection.
10. Multiple requests reusing one connection pool.
11. A client used inside `parallel::mclapply()` (§26.4).
12. A client serialized with `saveRDS()` and restored in a new session (§26.5).
13. A response body decoded as text from a server that sends no `charset` (§31.7).

### 32. Middleware

Middleware should live primarily at the R level.

Conceptual pipeline:

```text
request
   |
retry
   |
authentication
   |
logging
   |
tracing
   |
transport
```

Possible API:

```r
client <- zu_client(
  middleware = list(
    zu_retry(),
    zu_bearer_token(token),
    zu_trace()
  )
)
```

Middleware should receive:

- immutable-ish request representation.
- next handler.
- request context.

This avoids adding many unrelated behaviors to the C core.

### 33. Retry Model

Retry must be safe by default. An HTTP client that silently replays a POST is a data-integrity bug waiting to happen.

```r
zu_retry(
  attempts        = 3,
  backoff         = "exponential",
  jitter          = TRUE,
  retry_after     = TRUE,
  attempt_timeout = NULL
)
```

The argument is `attempts` — the **total** number of attempts including the first, not the number of retries after it. (An earlier draft used `attempts` in one place and `max_attempts` in another, with the two meanings differing by one; `attempts = 1` means no retrying.)

#### 33.1 When a retry is permitted

All three must hold:

1. **The failure is retryable** — see §33.2.
2. **The request is replay-safe**: the method is idempotent per RFC 7231 (GET, HEAD, PUT, DELETE, OPTIONS, TRACE), *or* the caller set `zu_req_retry(req, replay_safe = TRUE)`, *or* the request carries an `Idempotency-Key` header.
3. **The body is rewindable** — `zu_body_rewindable(req)` is `TRUE` (§28.2). Otherwise the attempt fails with `zu_body_not_replayable`.

POST is not idempotent and is never retried automatically. `Idempotency-Key` is honoured because it is the mechanism the payment and API ecosystem has standardised on; `zuhttp` generates one on request when asked:

```r
zu_req_retry(req, attempts = 3, idempotency_key = TRUE)
```

#### 33.2 Retryable conditions

| Condition | Retryable |
|---|---|
| Connection reset **before** any response byte | yes |
| Stale pooled connection failing on first write | yes, and does not count against `attempts` |
| DNS or connect failure | yes |
| TLS handshake failure | no — a trust failure will not fix itself |
| Timeout | only if `total` budget remains (§24.3) |
| 408, 429 | yes |
| 500, 502, 503, 504 | yes |
| Other 5xx | no by default |
| Any 4xx other than 408/429 | no |
| Connection reset **after** partial response | no — the request may have been applied |

The stale-connection case is important and is why it is exempt from the attempt count: a connection that the server closed while idle is a pool artifact, not a real failure, and retrying it on a fresh connection is transparent.

#### 33.3 Backoff and `Retry-After`

- Exponential with full jitter by default; jitter is on because synchronised retries from many R sessions are a real thundering-herd source.
- `Retry-After` is honoured when `retry_after = TRUE`, in both its delta-seconds and HTTP-date forms, and is **clamped** to `max_retry_after` (default 60s) so that a hostile or misconfigured server cannot pin an R session for hours.
- Before sleeping, the retry layer checks the remaining `total` budget (§24.3) and fails immediately rather than sleeping past the deadline.
- Backoff sleeps must be interruptible — they participate in the §25 checkpoint loop, not `Sys.sleep()` in a tight block.

#### 33.4 Observability

Every retry emits a `before_retry` hook event (§35) carrying attempt number, the triggering condition, and the computed delay. A retry that is never surfaced is a latency mystery for whoever debugs it later.

### 34. Error Model

Avoid exposing raw platform or TLS codes as the primary API.

#### 34.1 Condition hierarchy

```text
zu_error  (inherits: error, condition)
├── zu_dns_error
├── zu_connect_error
├── zu_timeout_error
├── zu_tls_error
│   ├── zu_tls_certificate_error
│   ├── zu_tls_hostname_error
│   ├── zu_tls_handshake_error
│   └── zu_tls_pin_error
├── zu_http_parse_error
├── zu_url_error                  (the URL itself does not parse or is unusable)
├── zu_proxy_error
│   └── zu_proxy_auth_error
├── zu_redirect_error
│   └── zu_too_many_redirects
├── zu_body_limit_error
├── zu_body_decode_error
├── zu_body_not_replayable
├── zu_http_status_error          (a valid response with an error status)
│   ├── zu_http_client_error      (4xx)
│   └── zu_http_server_error      (5xx)
└── zu_cancelled_error
    └── zu_interrupted_error      (user interrupt specifically)
```

Every class inherits from `error` and `condition` so that base R `tryCatch()` works without any additional package.

`zu_interrupted_error` is distinct from `zu_cancelled_error` because a user pressing Ctrl-C and a programmatic cancellation (§25.5) call for different handling in package code.

#### 34.2 Payload

Each condition carries:

- a stable project error code (`zu_code`), which is part of the public API and does not change with message wording,
- a human-readable message,
- the URL, **credential-redacted** per §42,
- the phase (`dns`, `connect`, `tls`, `write`, `ttfb`, `read`, `decode`),
- the platform backend and its native error code, where useful,
- a retryability hint,
- the request and response objects where they exist.

```r
tryCatch(
  zu_get(url),
  zu_tls_certificate_error = function(e) {
    ...
  }
)
```

#### 34.3 No rlang dependency

Conditions are built with base R (`structure(class = c(...), ...)`, `stop()`), not `rlang::abort()`. This keeps the hard-dependency count at zero (§1). Where `rlang` is available, the conditions are still well-formed for `rlang::catch_cnd()` and friends, because the class vector and `message`/`call` fields follow the standard layout.

#### 34.4 Messages

Success criterion §61.9 requires that messages be substantially more actionable than raw backend errors. Concretely, every message states what was attempted, what failed, and the most likely fix:

```text
Error: TLS certificate verification failed for `api.example.com`.
  The certificate is signed by an issuer not in the system trust store.
  Issuer: CN=Corp Proxy CA
  * If your organisation intercepts TLS, add its root:
      zu_tls(ca_extra = "corporate-root.pem")
  * Backend: OpenSSL 3.0.13, error 20 (unable to get local issuer certificate)
```

The backend code is present but last, not first.

### 35. Observability

#### 35.1 Timings

Timing data is reached through the accessor, consistent with §31.7 — **not** through `res$timings`:

```r
zu_resp_timings(res)
```

Fields:

```text
dns
connect
tls
request_write
ttfb
response_read
total
body_bytes_wire
body_bytes_decoded
```

All durations are from the monotonic clock (§24.4).

#### 35.2 Connection metadata

```r
zu_resp_connection(res)
```

```text
reused_connection
remote_ip
tls_protocol
tls_cipher
trust_backend
http_version
proxy_used
retries_performed
redirect_count
```

`trust_backend` is reported separately from the TLS engine because §13.1 splits them, and "which store decided to trust this certificate" is a question users genuinely ask.

#### 35.3 Event hooks

```text
request.start
dns.start / dns.done
connect.start / connect.done
tls.start / tls.done
headers.received
body.chunk
retry.scheduled
redirect.followed
request.done
```

Hooks are observability, and are kept separate from policy middleware (§31.13). They must not be able to modify the request — a hook that mutates is middleware wearing a disguise.

**All hook payloads pass through the redaction filter in §42 before the handler sees them.** A trace handler that logs request headers must not be the mechanism by which a bearer token reaches a log file.

This can later support OpenTelemetry without coupling the C core to an observability framework.

#### 35.4 Cost

Hooks are off by default and compile to a NULL check when unregistered. §51 must measure the overhead of an enabled `body.chunk` hook on a large download, since that is the one event that fires per-chunk rather than per-request.

### 36. Pluggable Transport

Transport substitution is a supported architectural mechanism, not a testing hack. Note that this is the **upper** of the two substitution points; §50.1 explains why `zuhttp`'s own tests use the lower one.

Default:

```r
client <- zu_client(transport = zu_native_transport())
```

Testing:

```r
client <- zu_client(
  transport = zu_mock_transport(function(req) {
    zu_response(
      status  = 200L,
      headers = c("Content-Type" = "application/json"),
      body    = charToRaw('{"ok":true}')
    )
  })
)
```

`zu_response()` takes `body` as a raw vector. A character scalar is accepted and encoded as UTF-8 for convenience, but the canonical form is raw — a response body is bytes, and letting the constructor guess an encoding would contradict §31.7.

#### 36.1 The transport contract

A transport is a function of one request returning one response, or signalling a `zu_error`. It is responsible for network semantics only: it does **not** implement redirects, retries, or policy merging, all of which sit above it (§31.13). This is what makes a mock transport a faithful stand-in — a mock that had to reimplement redirect handling would not be testing the same code path.

Potential transports:

```text
native            §13, the real thing
mock              in-memory, deterministic
record/replay     §37
Unix-domain       §59
custom            package-provided
```

### 37. Mocking and Record/Replay

Testing should not require real HTTP.

Mock transport should support matching:

- method.
- URL.
- headers.
- body.

Record/replay may serialize:

```text
request metadata
response status
response headers
response body
timing metadata optionally
```

Sensitive headers must be redacted:

- Authorization.
- Cookie.
- Proxy-Authorization.
- API-key patterns where configurable.

### 38. Authentication Scope

Initial:

- Basic.
- Bearer.
- arbitrary headers.

Later:

- client TLS certificates.

Not in transport core:

- OAuth flows.
- cloud-provider signing.
- NTLM.
- Kerberos.

Those belong in middleware or higher-level packages.

### 39. Information API

Expose:

```r
zu_info()
```

Example:

```text
zuhttp 0.1.0
HTTP: HTTP/1.1
TLS backend: Schannel
Trust: Windows Certificate Store
Compression: gzip, deflate
IPv6: yes
Proxy: yes
```

Unix:

```text
TLS backend: OpenSSL 3.x
Trust: system defaults
```

This should make networking diagnostics understandable.


---

## Part 7 — Security

### 40. Resource Limits and Security Defaults

Network input must be treated as hostile.

Default configurable limits should include:

```text
max_url_length
max_status_line
max_header_bytes
max_header_count
max_header_name
max_header_value
max_redirects
max_body_bytes
max_chunk_size
max_decompressed_bytes
max_decompression_ratio
```

Important checks:

- Checked integer arithmetic.
- No signed/unsigned overflow.
- No unchecked pointer arithmetic.
- No CRLF injection.
- No unbounded stack allocation based on network input.
- Reject ambiguous body framing.
- Reject malformed chunk encoding.
- Enforce TLS verification by default.
- Strip credentials on cross-origin redirects.
- Prevent accidental proxy credential leakage.

### 41. Memory Management

Prefer simple ownership rules.

Internal allocations should use a project abstraction:

```c
void *zu_alloc(size_t);
void *zu_realloc(void *, size_t);
void  zu_free(void *);
```

This enables:

- overflow checks.
- memory instrumentation.
- fuzz testing.
- optional R allocator integration where appropriate.

Do not retain pointers into R-managed memory across calls unless explicitly protected and documented.

For streaming, copy only when necessary.

### 42. Secret Redaction

Redaction must be **one policy applied at every egress**, not a feature of the record/replay transport alone. §37 redacts recordings, but §35's trace hooks, §31.4's request printing, and §34's error messages can each leak the same credential just as easily.

#### 42.1 What is redacted

By default:

- `Authorization`
- `Proxy-Authorization`
- `Cookie` and `Set-Cookie`
- `X-Api-Key`, `X-Auth-Token`, and a configurable pattern list
- userinfo in any URL (`https://user:pass@host/...`)
- query parameters named in `zu_redact_params()` (default: `access_token`, `api_key`, `signature`, `sig`)
- the request body of any request whose `Content-Type` is a credential-bearing form (`application/x-www-form-urlencoded` containing a redacted parameter name)

Redacted values render as `<redacted>`, never as a truncated prefix — a prefix is enough to confirm a guess.

#### 42.2 Where it applies

| Egress | Redacted |
|---|---|
| `print()` on a request or response | yes |
| `format()` / `as.character()` | yes |
| Condition messages and payloads (§34.2) | yes |
| Trace and hook payloads (§35.3) | yes |
| Record/replay serialization (§37) | yes |
| `zu_resp_url()` | yes — userinfo stripped |
| Verbose/debug transport logging | yes |

The single exception is explicit user retrieval: `zu_req_headers(req)` returns real values, because the user asking for their own header by name is not an accidental disclosure. That asymmetry must be documented.

#### 42.3 Implementation constraint

Redaction is applied by the formatting layer, not by mutating stored objects — a redacted request must still be *executable*. Storing `<redacted>` into the request would produce a client that fails authentication in confusing ways.

#### 42.4 Testing

§50 must include a test that greps the full output of a verbose request, an error condition, a printed request, and a recording for a canary credential string. This is a regression class that reappears every time a new output path is added.

### 43. Fuzzing

Fuzzing is essential.

Primary targets:

- response parser wrapper.
- chunked decoder.
- header normalization.
- URL handling.
- redirect resolution.
- proxy environment parsing.
- decompression limits.

Use:

- libFuzzer.
- AFL++ where practical.

Sanitizers:

- ASan.
- UBSan.
- MSan where feasible.

CI should periodically fuzz using corpus seeds.

### 44. Static Analysis

Recommended:

- clang-tidy.
- compiler warnings at high levels.
- `-Wall -Wextra -Wpedantic` where compatible.
- MSVC `/W4`.
- Coverity or equivalent if available.
- CodeQL if useful for C paths.

Treat warnings in project-owned code as errors in CI.

Vendored code may use separate warning policy.

### 45. Security Review Requirements

Before first stable release:

- external or independent code review of TLS glue.
- fuzz parser interfaces.
- fuzz URL handling.
- test CRLF/header injection.
- verify redirect credential stripping.
- test certificate failures.
- test malformed proxy responses.
- test timeout and cancellation cleanup.
- test decompression bombs.
- run ASan/UBSan.
- run valgrind where useful.
- verify no R API calls from non-main threads.
- verify all allocation overflow checks.

### 46. Ongoing Security Policy

§45 covers the audit before first release. This section covers the obligation that begins the day after.

**A package that implements its own TLS glue and HTTP framing takes on CVE-response duty that `curl` users currently receive from the libcurl team.** That is the real, ongoing cost of the architecture in §12, and it must be accepted deliberately rather than discovered.

#### 46.1 Required artifacts

- **`SECURITY.md`** in the repository, stating the disclosure address, expected acknowledgement time, and supported versions.
- A monitored contact address that is not solely the maintainer's personal inbox.
- A documented patch SLA. Proposed: acknowledge within 72 hours; fix or mitigation for a remotely triggerable memory-safety issue within 14 days; CRAN submission immediately on fix.

#### 46.2 Dependency watch

Vendored components (§48) must be watched upstream, because they will not be updated by the system package manager the way system OpenSSL and zlib are:

- Subscribe to upstream security channels for every vendored library.
- Record upstream version and commit (§48) so exposure can be assessed in minutes rather than hours.
- The `tools/update-*` scripts exist so that a security update is a mechanical, same-day operation.

#### 46.3 The maintainer-count risk

A single-maintainer, security-critical CRAN package is a bus-factor problem for its dependents. Mitigations, in order of preference: recruit a second maintainer with commit and CRAN-submission rights before 1.0; failing that, document the risk prominently in the README so that prospective dependents can make an informed choice.

This is tracked as Appendix B, R-6, and it is a legitimate reason for a package author to choose `curl` instead. §6 must not claim otherwise.

## Part 8 — Build, Test, Release

### 47. CRAN Build Strategy

#### 47.1 Per-platform dependencies

| Platform | TLS engine | Trust | Other |
|---|---|---|---|
| Windows | Schannel (`secur32`, `crypt32`) | Windows cert store | Winsock2, zlib from Rtools |
| macOS | see §13.2 | `Security.framework` | system zlib |
| Linux/Unix | system OpenSSL | OpenSSL default paths | system zlib |

Link flags:

```text
Windows : -lws2_32 -lsecur32 -lcrypt32 -lz
macOS   : -framework Security -framework CoreFoundation -lz  (+ engine)
Unix    : -lssl -lcrypto -lz
```

No OpenSSL installation is required on Windows.

#### 47.2 DESCRIPTION requirements

```text
SystemRequirements: OpenSSL >= 1.1.1 (Linux/Unix only), zlib
```

CRAN reviewers check that a system dependency is declared here; omitting it is a common first-submission rejection.

#### 47.3 configure

`configure` must be POSIX `sh` — not bash — and must:

- probe headers and library version, not just presence,
- work when `pkg-config` is absent, falling back to a direct compile-and-link probe,
- respect `PKG_CPPFLAGS` / `PKG_LIBS` from the environment and from `~/.R/Makevars`,
- honour `R_HOME`'s compiler settings rather than hard-coding `cc`,
- not write outside the package directory,
- emit a failure message naming the exact missing package for the common distros:

```text
zuhttp: could not find OpenSSL headers (openssl/ssl.h).
  Debian/Ubuntu : apt-get install libssl-dev
  Fedora/RHEL   : dnf install openssl-devel
  Alpine        : apk add openssl-dev
  macOS         : not required (system TLS is used)
```

A matching `cleanup` script removes generated files. If autoconf is used, `configure.ac` ships in the tarball and the generated `configure` is committed.

#### 47.4 Windows toolchain: TLS 1.3 structures are missing from Rtools

**Measured, not assumed.** The S1 probe (`spike/windows-schannel/`, run on GitHub Actions with the compiler from `R CMD config CC`) found:

| Symbol | Kind | Present under Rtools mingw-w64 11.0 |
|---|---|---|
| `SCH_CREDENTIALS_VERSION`, `SCH_USE_STRONG_CRYPTO`, `SP_PROT_TLS1_3_CLIENT` | macros | **yes** |
| `SCH_CREDENTIALS`, `TLS_PARAMETERS` | **typedefs** | **no** |
| `SCHANNEL_CRED_VERSION`, `SP_PROT_TLS1_2_CLIENT`, `UNISP_NAME_A` | TLS 1.2 path | yes |
| `CERT_CHAIN_POLICY_SSL`, `CERT_STORE_PROV_MEMORY` | chain validation | yes |

`InitSecurityInterfaceA()` returns non-NULL and `CertOpenStore(CERT_STORE_PROV_MEMORY, ...)` succeeds, so SSPI and CryptoAPI genuinely link and run — the Windows plan in §13.4 and §14.3 is otherwise sound.

The split result is the important part. **It is not a version gate**: `-D_WIN32_WINNT=0x0A00 -DNTDDI_VERSION=0x0A000000` does not make the typedefs appear. mingw-w64 11.0's `schannel.h` was partially updated for TLS 1.3 — the manifest constants landed, the structure definitions did not.

Options, in preference order:

1. **Declare `SCH_CREDENTIALS` and `TLS_PARAMETERS` locally**, guarded so they compile away if a future Rtools ships them. Roughly 30 lines, and because the constants already exist there is no constant table to keep in sync. **Requires ABI verification against a real Windows 10+ target before it can be trusted** — a wrong structure layout passed to `AcquireCredentialsHandle` is a memory-safety bug, not a compile error.
2. **Ship Windows TLS 1.2-only for v1.** Safe, cheap, and leaves Windows one protocol version behind the other platforms.
3. Require a newer mingw-w64 than Rtools ships — not viable, since CRAN builds with Rtools.

Take option 1, falling back to option 2 if the ABI cannot be verified confidently. Either way this is bounded work on the TLS 1.3 path only; nothing else about the Windows backend is blocked.

`src/Makevars.win` handles Windows; `configure` plus `src/Makevars.in` handles Unix.

#### 47.5 CRAN policy constraints

- **No internet access in examples, tests, or vignettes** by default. All network tests are skipped on CRAN and run against the local test server (§50.3) elsewhere.
- **No writes outside `tempdir()`**. The record/replay transport (§37) defaults its cassette directory to `tempdir()`, and requires an explicit path otherwise.
- Examples must run in reasonable time; anything network-shaped is wrapped in `\donttest{}` *and* guarded at runtime.
- Compiled code must not write to `stdout`/`stderr` outside of R's own facilities.

### 48. Vendoring Policy

Vendored libraries should satisfy:

1. Permissive compatible license.
2. Small source footprint.
3. Narrow purpose.
4. Active maintenance.
5. No hidden runtime.
6. Easy security update process.

Each vendored dependency should live in a clearly isolated directory.

Maintain:

```text
tools/update-<http-parser>
tools/update-<uri-parser>
```

Record:

- upstream version.
- commit.
- license.
- modifications.

Avoid modifying vendored source unless absolutely necessary.

### 49. Licensing

#### 49.1 Package license

`zuhttp` uses a permissive license compatible with all vendored components and with CRAN requirements. MIT is the recommended default; BSD-2-Clause, BSD-3-Clause and Apache-2.0 are acceptable alternatives.

CRAN mechanics that are easy to get wrong on a first submission:

- `License: MIT + file LICENSE`, with a `LICENSE` file containing exactly the two lines `YEAR:` and `COPYRIGHT HOLDER:`. The full MIT text does **not** go in that file.
- Apache-2.0 instead requires `License: Apache License (>= 2)` and the full text in `LICENSE`.

#### 49.2 Third-party attribution

This is a CRAN requirement, not a courtesy, and it is a frequent cause of resubmission:

- Every vendored component's copyright holder is listed in `Authors@R` with role `cph`, or in an `inst/COPYRIGHTS` file, or both.
- `inst/COPYRIGHTS` records, per component: name, upstream URL, version/commit, license identifier, and the full license text.
- `LICENSE.note` summarises the aggregate licensing situation for a human reader.

Current candidates and their licenses:

| Component | License | Vendored? |
|---|---|---|
| picohttpparser | MIT | if chosen (A.3) |
| llhttp | MIT | if chosen (A.3) |
| uriparser (subset) | BSD-3-Clause | yes — §8.2, inst/COPYRIGHTS |
| zlib | zlib license | **no** — system-linked |
| miniz | MIT | only under `--with-bundled-zlib` |

#### 49.3 System TLS

Native system TLS is dynamically linked and does not require vendoring TLS licenses into the package beyond any required notices. OpenSSL 3.x is Apache-2.0; OpenSSL 1.1.1 is the older dual OpenSSL/SSLeay license. Since neither is distributed in the tarball, neither constrains the package license — but `inst/COPYRIGHTS` should still name them as system dependencies for the reader's benefit.

All vendored third-party licenses must be retained verbatim, in their original files, inside the vendored directory.

### 50. Testing Strategy

#### 50.1 Test the engine, not just the seam

The mock transport in §36 substitutes at the **R level**, which means a package test using it exercises none of the C parsing, framing, or TLS code. That is the right tool for testing *someone else's package that depends on zuhttp*, and the wrong tool for testing `zuhttp` itself. Using it as the primary test mechanism would leave the code most in need of testing as the code least covered.

`zuhttp`'s own tests therefore use **three** substitution points, at descending levels:

| Level | Substitutes | Exercises | Used for |
|---|---|---|---|
| R transport (§36) | everything below the R API | R API, merging, middleware | API ergonomics; downstream packages' tests |
| **`zu_stream` mock (§9)** | the socket/TLS layer | **parser, framing, pool, redirects, decompression** | the majority of `zuhttp`'s own unit tests |
| local test server (§50.3) | nothing | the whole stack including real sockets | integration |

The `zu_stream` mock is the important one: it feeds a canned byte sequence — including every malformed input in §50.2 — through the *real* engine and asserts on the resulting response or condition. It is fully deterministic, needs no network, and runs on CRAN.

#### 50.2 Unit tests

- URI parsing and relative resolution.
- Header parsing and validation.
- Status-line parsing.
- Body framing precedence (§18.1) — every row of that table is a test.
- Chunked decoding, including trailers (§18.2).
- Duplicate header accessor semantics (§18.3).
- Redirect method/body rewriting (§19.1) — every row of that table is a test.
- Header-stripping on cross-origin redirect (§19.2).
- `NO_PROXY` matching (§20.2).
- Timeout composition arithmetic (§24.2) and budget-across-retries (§24.3).
- Retry admissibility (§33.1) and the rewindability matrix (§28.2).
- Text decoding and charset fallback (§31.7).
- Redaction canary tests (§42.4).

#### 50.3 Parser corpus

Maintain malformed inputs as fixture files, shared with the fuzzer (§43) as seed corpus:

- broken status lines,
- duplicate and conflicting `Content-Length`,
- `Content-Length` together with `Transfer-Encoding`,
- invalid chunk sizes, chunk-size overflow, chunk extensions,
- oversized headers, too many headers,
- invalid header characters, `obs-fold`,
- truncated messages at every boundary,
- decompression bombs (§21.4),
- CONNECT responses that are malformed or non-2xx.

#### 50.4 Integration server

A deterministic local test server supporting: redirects (all five statuses), chunked responses, gzip and deflate (both wrappings), slow headers, slow body, truncated body, connection close mid-body, keep-alive, malformed responses, proxy CONNECT, and `100-continue`.

Prefer a helper written in R, or a tiny vendored executable, over requiring Python or Node during CRAN checks.

#### 50.5 TLS integration tests

Against locally generated certificates: trusted, untrusted, wrong hostname, expired, not-yet-valid, custom CA, custom CA via `ca_extra`, and pin match/mismatch.

**These negative tests are mandatory from the first commit of any TLS backend, on every platform, in CI.** S0 finding F-3 is the reason: the spike's first working build accepted *every* invalid certificate, because OpenSSL clients default to `SSL_VERIFY_NONE` and under it a `cert_verify_callback` returning 0 records the failure without aborting the handshake. The bug produced a perfectly working HTTPS connection and would have passed any happy-path test. A verification bypass is only visible to a test that expects rejection.

Reproducing a *system* trust store in CI is the hard part (§62): a test that installs a root into the OS store is intrusive and platform-specific. The practical approach is to test the trust *evaluator* against a store the test controls, and to verify only that the production path selects the system store — not to test the system store's contents.

External internet tests must never be required for CRAN checks.

#### 50.6 Concurrency and lifecycle tests

Easy to forget, and each corresponds to a §26/§29 hazard:

- A request interrupted at every phase, asserting no leaked descriptors (run under ASan and valgrind, §45).
- A pooled client used across `parallel::mclapply()` (§26.4) — **both hazards**: inherited connections, and on macOS a forked child raising a named condition rather than segfaulting (§26.4 hazard 2).
- A client `saveRDS()`-ed and restored in a fresh session (§26.5).
- A streaming callback that raises an R error (§27.3).
- A streaming callback that issues a nested request (§27.4).

### 51. Performance Targets

Performance should be competitive for ordinary HTTP/1.1 use. **"Competitive" is defined numerically here so that the prototype can pass or fail against it**, rather than being assessed impressionistically.

#### 51.1 Architectural targets

- Minimal request setup overhead.
- Connection reuse (§26).
- Zero-copy header parsing.
- Streaming body handling with no whole-body copy.
- Bounded allocation count per request.
- TLS session resumption across new connections to the same origin — pooling alone does not cover the cost of a fresh handshake, and on Schannel and OpenSSL alike, resumption is the single largest win for repeated HTTPS requests.

#### 51.2 Benchmarks

| Benchmark | Measures |
|---|---|
| 1,000 sequential GETs, local keep-alive HTTP server | per-request overhead |
| 1,000 sequential GETs, local keep-alive HTTPS server | overhead including TLS record layer |
| 100 HTTPS requests to a fresh connection each time | handshake + resumption |
| 1 MB download to memory | throughput, copies |
| 100 MB streaming download to file | throughput, peak RSS |
| gzip response, 10 MB decompressed | decompression path |
| the same with a `body.chunk` hook registered | hook overhead (§35.4) |

Compared against the `curl` package on each platform.

#### 51.3 Pass/fail thresholds

These are the numbers the §63 prototype is judged against:

| Metric | Target | Abort threshold |
|---|---|---|
| p50 latency, local keep-alive GET | within 1.5× of `curl` | worse than 2× |
| Throughput, 100 MB streaming download | within 1.2× of `curl` | worse than 1.5× |
| Peak RSS, 100 MB streaming download | < 16 MB above baseline | any full-body allocation |
| Allocations per simple request | < 50 | > 200 |
| Project-owned C | ≤ 8,000 LOC | > 12,000 LOC |
| Total C, vendored + owned | ≤ 25,000 LOC | > 40,000 LOC |
| Source tarball | ≤ 2 MB | > 5 MB |
| Cold compile time, one core | ≤ 90 s | > 180 s |

**Measured 2026-09-07, after S7 and D-11** (code lines, excluding blank and
comment-only lines; the LOC rows only — the runtime rows need the §63
prototype, which does not exist yet):

| Metric | Measured | Target | Status |
|---|---|---|---|
| Project-owned C | 2,601 | ≤ 8,000 | 33% of budget |
| Vendored: picohttpparser | 598 | — | |
| Vendored: uriparser subset | 3,869 | — | |
| **Total C** | **7,068** | ≤ 25,000 | 28% of budget |

Counting raw lines instead — which is what a reviewer actually reads, license
headers and doxygen included — gives 11,459, still under the *code-line*
budget. The two vendored components together are 63% of the total C, which is
the number to watch: it is the code this project does not own but must still
security-track (§46.2, §48). Both remaining backends (Schannel S8, macOS S9)
add project-owned lines only.

Exceeding an abort threshold is not a bug to be fixed later; it is a signal that the architecture is not delivering the advantage the project exists to provide, and it should trigger the reconsideration in Appendix B.

The goal is not to beat libcurl everywhere, but to avoid regressions caused by architecture — and to be honest, in public, when a number is worse.

### 52. Compatibility Targets

Primary:

- Windows x86_64.
- Windows ARM64 when R tooling permits.
- macOS arm64.
- macOS x86_64 while supported by R.
- Linux x86_64.
- Linux arm64.

Source code should remain portable across additional Unix platforms where OpenSSL and POSIX sockets are available.

Use C99-compatible code unless CRAN platform constraints dictate a stricter subset.

Avoid compiler-specific extensions in project-owned code.

### 53. API Stability

C internals are not public initially.

Only R-level API is stable.

Internal headers should live under:

```text
src/
```

not:

```text
inst/include/
```

until there is a deliberate decision to expose a C API.

This avoids prematurely freezing internal representations.

### 54. Potential Public C API

If ecosystem demand emerges, expose a small stable C API:

```c
zu_client *
zu_request *
zu_response *
```

But only after the core architecture is stable.

Do not expose vendored library types.

### 55. Documentation Requirements

User documentation should explain:

- Native TLS backend on each OS.
- System trust behavior.
- Proxy behavior.
- Timeout semantics.
- Redirect policy.
- Retry safety.
- Streaming.
- Error classes.
- Differences from `curl`.
- Unsupported libcurl features.

Developer documentation should explain:

- stream abstraction.
- parser ownership.
- TLS backend contract.
- cancellation model.
- allocation ownership.
- platform porting requirements.


---

## Part 9 — Plan

### 56. Design Constraints

The following constraints should guide implementation decisions.

#### Constraint 1: HTTP-only

Do not add unrelated protocols.

#### Constraint 2: Native TLS

Avoid vendoring cryptography.

#### Constraint 3: Small core

Prefer narrow dependencies and project-owned glue.

#### Constraint 4: Bounded behavior

Every parser and operation should have explicit limits.

#### Constraint 5: R-first cancellation

Never allow indefinitely blocking native calls.

#### Constraint 6: Testability

Every networking layer should be mockable.

#### Constraint 7: System-native trust

Default behavior should follow host certificate policy.

#### Constraint 8: Portability

Project-owned C should use portable C99 and isolated platform shims.

#### Constraint 9: No hidden runtime

Do not introduce another managed runtime unless strongly justified.

#### Constraint 10: Reject feature creep

Do not evolve into libcurl.

### 57. Initial MVP

The MVP implements only:

```text
HTTP/1.1
HTTP + HTTPS
GET, HEAD, POST
custom headers
raw/string bodies
Content-Length
chunked responses  (incl. strict framing, §18.1)
redirects          (incl. the §19.1 rewrite table and §19.2 stripping)
gzip/deflate       (incl. the §21.4 limits)
IPv4 + IPv6
timeouts           (full §24 model, including total-across-chain)
Ctrl-C cancellation
certificate verification, system trust
memory responses
file downloads
Connection: close
basic proxy support
structured conditions (§34)
redaction (§42)
```

#### 57.1 Not optional in the MVP

Three items are sometimes treated as polish and must not be, because retrofitting them is a breaking change or a security fix rather than a feature:

- **Strict framing (§18.1).** Loosening a parser later is easy; tightening one after users depend on the permissive behavior is not.
- **Redaction (§42).** Every output path added before redaction exists is a leak that must be found later.
- **The fork guard (§26.4).** It is three lines in the right place and a corrupted-TLS bug report in the wrong one.

Connection reuse follows immediately after correctness is established, but the pool key (§26.1) and the no-reuse rules (§26.3) are designed in from the start so that enabling reuse does not change observable behavior.

### 58. Phase 2

Add:

- Keep-alive.
- Connection pool.
- PUT/PATCH/DELETE helpers.
- Streaming callbacks.
- R connection sinks.
- Structured retry policies.
- middleware.
- mock transport.
- richer diagnostics.
- custom CA.
- client certificate support.

### 59. Phase 3

Add only if justified:

- concurrent HTTP/1.1 state machine.
- record/replay transport.
- native system proxy settings.
- Unix-domain sockets.
- OpenTelemetry hooks.
- optional Brotli.
- optional zstd.

HTTP/2 should require a separate design decision.

### 60. HTTP/2 Policy

HTTP/2 should not be implemented merely for feature parity.

Before adding HTTP/2, determine whether:

- real R workloads materially benefit.
- connection concurrency is insufficient.
- a small reusable HTTP/2 library is acceptable.
- source size remains within project goals.

If HTTP/2 materially changes the project's character, it should remain outside `zuhttp`.

### 61. Success Criteria

Qualitative criteria cannot be failed, and a criterion that cannot be failed is not a criterion. Each of the following has a measurement and a threshold.

| # | Criterion | Measurement | Threshold |
|---|---|---|---|
| 1 | Source installs reliably on CRAN toolchains | R-hub / win-builder / macOS builder | 0 errors, 0 warnings on all platforms in §52 |
| 2 | HTTPS works on native trust with no bundled CA bundle | integration suite | passes on all three platforms; no CA file in the tarball |
| 3 | Common REST workloads need no libcurl | the 13 workflows in §31.16 | all pass with `curl` not installed |
| 4 | Ctrl-C reliably cancels stalled requests | §50.6 interrupt tests | cancels within 200 ms in every phase except DNS (§25.4), on all three R front-ends |
| 5 | Connection reuse gives competitive latency | §51.2 keep-alive benchmark | within 1.5× of `curl` |
| 6 | Streaming needs no full-body allocation | §51.2, 100 MB download | peak RSS < 16 MB over baseline |
| 7 | Native source is small enough to audit | `cloc` on `src/`, excluding vendored | ≤ 8,000 LOC project-owned |
| 8 | Fuzzing finds no persistent memory-safety issues | §43 | 24 h libFuzzer per target, 0 crashes, 0 ASan/UBSan reports |
| 9 | Errors are substantially more actionable than backend errors | review of the §34.4 catalogue | every `zu_error` class has a message naming cause and likely fix; 0 messages that are only a numeric code |
| 10 | The design stays HTTP-focused | §4 review at each release | no protocol added outside HTTP/1.1 |
| 11 | New users need no builder API for GET/JSON POST | usability check with 3 R users unfamiliar with the package | each writes a working GET and JSON POST within 5 minutes using only the reference index |
| 12 | Package authors get one coherent request model | §31.16 workflows 4, 7, 12 | build, inspect, transform, mock, and execute without reaching past the public API |
| 13 | No masking of httr2 | `library(httr2); library(zuhttp)` | 0 masking warnings |
| 14 | Fork- and session-safe | §50.6 | pooled client survives `mclapply()` and a `saveRDS()` round-trip |

Criteria 1–8 and 13–14 are automatable and belong in CI. Criteria 9 and 11 require human review and are gates on the 1.0 release, not on every commit.

### 62. Open Questions

Questions that the drafting process has already answered are recorded in the Decision Register at the top of this document and removed from this list. What remains genuinely requires a prototype, a benchmark, or a platform experiment.

#### 62.1 Blocking — must be answered before substantial implementation

| # | Question | Resolved by |
|---|---|---|
| ~~1~~ | ~~Can the §13.1 engine/trust split work on macOS from a synchronous poll loop?~~ **ANSWERED: yes.** S0, 2026-09-07. | — |
| 1a | **Which portable TLS engine on macOS is viable for CRAN binary builds?** S0 used Homebrew OpenSSL; CRAN needs a static engine from the recipes toolchain or an alternative. Now the top macOS unknown. | S4 |
| ~~2~~ | ~~Does the Rtools mingw-w64 SDK expose `SCH_CREDENTIALS`?~~ **ANSWERED: no.** S1, 2026-09-07. Must be declared locally (§47.4). | — |
| 2a | **Is a locally declared `SCH_CREDENTIALS` ABI-correct against a real Windows 10+ target?** Until verified, Windows TLS 1.3 is not safe to ship. | S3 |
| 3 | What is the realistic line count of the Schannel backend, and does it fit the §51.3 budget? | Windows spike, §63.1 |
| ~~4~~ | ~~picohttpparser or llhttp?~~ **ANSWERED: picohttpparser**, 2026-09-07, after the strictness layer was built and tested independently. | — |
| ~~5~~ | ~~Vendor `uriparser` (~15k LOC) or write a ~600-line parser?~~ **ANSWERED: a 3.9k-line subset**, 2026-09-07. The 15k figure measured the whole distribution; six of eight historical CVEs are in the excluded files (§8.2). | — |

#### 62.2 Important — answer before 1.0

| # | Question |
|---|---|
| 6 | Minimum Unix TLS baseline: OpenSSL 1.1.1 or 3.x? What does this cost in supported distributions? |
| 7 | Is LibreSSL explicitly supported, or best-effort? |
| 8 | Does connection pooling belong entirely in C, or partly in R? |
| 9 | Are R connections performant enough to serve as streaming sinks (§27.5)? |
| 10 | How is `R_CheckUserInterrupt()` integrated without measurable throughput cost? What poll interval is the right trade? |
| 11 | How are system certificate stores tested reproducibly in CI (§50.5)? |
| 12 | Is a cancellable DNS path worth a scoped exception to the no-threads rule (§8.4)? |
| 13 | Should middleware operate on immutable request objects, and what is the cost of copying? |

#### 62.3 Open — may remain open past 1.0

| # | Question |
|---|---|
| 14 | Should `zuhttp` expose a stable C API (§54)? |
| 15 | Does asynchronous concurrency belong in this package at all, or in a layer above it (§30)? |
| 16 | Is an httr2 backend practical, and are the httr2 maintainers interested (§5)? |
| 17 | Is there real demand for a lightweight in-memory cookie store (§22)? |
| 18 | Should derived clients share a connection pool when transport, TLS and proxy configuration are identical (§31.10)? |

### 63. Recommended First Prototype

The prototype's job is not to demonstrate that a GET works — that is not in doubt. **Its job is to falsify the four blocking risks in Appendix B as fast as possible**, because those determine whether the architecture in §12 is viable at all.

#### 63.1 Order of work: spikes before slices

The earlier phasing (Linux, then Windows, then macOS) postpones both low-confidence items to the end, which is exactly backwards. Reordered:

| Stage | Work | Gate |
|---|---|---|
| ~~**S0**~~ | ~~macOS TLS spike~~ — **COMPLETE 2026-09-07, verdict GO.** `spike/macos-tls/`, 16/16 assertions. Retired R-1; raised R-12 and R-13; corrected §14.5; hardened §26.4 and §50.5. | ✅ |
| **S1** | Rtools/Schannel header probe (§47.4): does mingw-w64 expose `SCH_CREDENTIALS`? | **R-3.** Determines whether Windows gets TLS 1.3 in v1 |
| **S2** | Linux vertical slice (below) | Baseline; proves the engine shape |
| **S3** | Windows/Schannel backend, measured against the §51.3 LOC budget as it is written | **R-2.** Stop at 3,500 LOC and reconsider |
| **S4** | macOS backend per the S0 outcome | — |

S0 and S1 are days of work each and can be done before any engine code exists. Doing them first is the single highest-value change to the plan.

#### 63.2 Vertical slice

```text
R
 |
zu_get()
 |
C request builder
 |
URI handling (§8.2 subset + policy layer)
 |
TCP
 |
TLS engine + trust evaluator (§13.1)
 |
HTTP parser (picohttpparser, D-10)
 |
memory body
 |
R raw vector
```

Capabilities: GET only, HTTPS, certificate verification, one redirect, `Content-Length`, chunked decoding, total timeout, Ctrl-C, memory response.

#### 63.3 Build both open options — DONE

D-10 (parser) and D-11 (URI) are both decided: picohttpparser, and a
parse/resolve/recompose subset of uriparser. Both were settled the way this
section prescribes — build the decision-independent part first, then measure.
For D-10 that meant writing `zu_framing.c` before choosing a parser, which
removed the main objection to picohttpparser (that it makes no framing
decisions — it does not, and framing is ours regardless). For D-11 it meant
writing `zu_uri.h` and `zu_redirect.c` against the flat struct first, so only
§19.6 was ever blocked, and then deriving the vendor subset by linking rather
than by argument. The LOC figure that had been carried in §8.2 for two drafts
(15k) turned out to be measuring the wrong thing by a factor of four.

#### 63.4 Measure, then decide

Against the thresholds in §51.3:

- project-owned and total LOC,
- source tarball and compiled binary size,
- install time and complexity on a clean CRAN-like machine,
- p50 and p99 latency versus `curl`,
- TLS compatibility across a spread of real hosts, including one behind a corporate MITM proxy,
- quality of failure diagnostics for the §14.6 catalogue.

**Publish the numbers even if they are unfavourable.** §1.2 lists three claims this document makes that only the prototype can substantiate; the prototype's real deliverable is the answer to those, not the working GET.

Only then implement connection pooling and the broader API.

### 64. Effort Estimate

An architecture document that proposes writing TLS glue and HTTP framing from scratch is not honest without a cost estimate. These are rough, single-experienced-developer figures, in person-weeks, assuming familiarity with C and with R's C API.

| Work item | Estimate | Confidence |
|---|---|---|
| Stream abstraction, sockets, poll loop, deadlines | 2 | high |
| R interrupt/unwind integration (§25.2), done correctly | 2 | medium — this is subtle |
| HTTP request builder, response parser wrapper, framing (§18) | 3 | high |
| URI handling (either option, §8.2) | 1–2 | high |
| Redirects, proxy, CONNECT (§19, §20) | 2 | high |
| Compression + limits (§21) | 1 | high |
| **OpenSSL backend + trust** | 2 | high |
| **Schannel backend + trust** (§13.4) | 4–6 | **low** — the dominant unknown |
| **macOS engine + Keychain trust** (§13.2) | 3–5 | **low** — blocked on §63.1 |
| Connection pool, incl. fork and session safety (§26) | 2 | medium |
| R API: client/request/response, merging, printing (§31) | 3 | high |
| Retry, middleware, hooks, errors, redaction (§33–§35, §42) | 3 | high |
| Test server, corpus, unit and integration suites (§50) | 3 | medium |
| Fuzzing harnesses and CI (§43, §44) | 2 | medium |
| CRAN packaging, configure, three-platform builds (§47) | 2 | medium |
| Documentation (§55) | 2 | high |
| External security review and remediation (§45) | 2 | low |
| **Total** | **39–46 person-weeks** | |

That is roughly **9–11 person-months to a trustworthy 1.0**, of which **7–11 weeks — about a quarter — is TLS backend work on Windows and macOS**, the two items with the lowest confidence.

Two consequences follow:

1. The §63 prototype must attack the low-confidence items **first**, not last. The current phasing (Linux → Windows → macOS) does exactly this only if the Windows and macOS spikes are treated as gates rather than as follow-on work.
2. If the macOS spike fails and the fallback in §13.2 is also unacceptable, the honest options are to ship Linux and Windows only, or to stop. Both are better than shipping a macOS backend nobody has validated.

## Appendix A — Rejected Alternatives

### A.1 Gambit Scheme

A prior design considered:

```text
Scheme source
   |
 Gambit gsc
   |
portable generated C
   |
LinkingTo: rgambit
   |
R package
```

Potential benefits:

- Full Scheme.
- Mature portable-C compiler.
- Stronger memory-safety properties than raw C in ordinary Scheme code.
- Good parser/state-machine language.

Rejected for `zuhttp` because embedding Gambit introduces:

- Second garbage collector.
- Second exception model.
- Runtime initialization.
- Continuation semantics.
- Runtime ABI/version coupling.
- Error-unwinding complexity with R.
- Potential multiple embedded Gambit runtimes across R packages.
- Greater operational complexity than justified for a small HTTP client.

The `rgambit` idea remains potentially interesting as an independent R infrastructure project.

### A.2 CRUNCH

CRUNCH is a CHICKEN extension implementing a restricted, statically typed Scheme subset that emits C with a small runtime.

Potential benefits:

- Scheme-like implementation language.
- Small generated runtime.
- No full Scheme VM required at runtime.
- Direct C-oriented code generation.

Reasons not to use it initially:

- Young/maturing toolchain.
- Restricted language.
- Existing HTTP code would require porting.
- Once picohttpparser is used, the remaining HTTP state-machine logic is small enough that C may be simpler.
- Adds a development compiler dependency without a clear runtime advantage for this specific project.

CRUNCH may be reconsidered for isolated subsystems if it becomes more mature.

### A.3 llhttp

`llhttp` is a strong alternative to picohttpparser, and the earlier draft's comparison was not made on fair terms.

#### The unfair comparison

The original framing was:

| | picohttpparser | llhttp |
|---|---|---|
| Size | tiny (~700 LOC) | larger |
| API | minimal | callbacks and state |
| Style | zero-copy, allocation-free | incremental state machine |

On those axes picohttpparser wins easily. But it compares picohttpparser *alone* against llhttp *alone*, and picohttpparser alone is not a substitute for llhttp. **picohttpparser makes no framing decisions.** Every rule in §18.1 — `Content-Length`/`Transfer-Encoding` conflict, duplicate `Content-Length`, chunk-size overflow, `obs-fold` rejection, status-line validation — is code this project writes, tests, and fuzzes itself. llhttp enforces them.

#### The fair comparison

| | picohttpparser + own strictness layer | llhttp |
|---|---|---|
| Vendored LOC | ~700 | ~7,000 generated + ~1,000 runtime |
| Project-owned framing LOC | ~800–1,200, security-critical | ~200 glue |
| Total LOC this project is responsible for auditing | ~1,500–1,900 | ~200 |
| Smuggling rules | **written here, fuzzed here** | enforced upstream |
| Battle-testing of those rules | this project's corpus | the Node.js ecosystem, continuously |
| Upstream maintenance | h2o repo, effectively frozen | active |
| Buffering constraint | whole header block contiguous; re-parse from offset 0 | true incremental, no contiguity requirement |
| Performance | zero-copy, very fast | fast; extra callback indirection |

The LOC gap narrows to roughly 6,000 vendored lines, in exchange for moving the most security-sensitive logic in the project from code this project must get right to code that a large ecosystem has already stress-tested. §18's emphasis on smuggling defenses, and §46's acknowledgement that this project owns its CVE response, both argue in llhttp's favour.

The counter-arguments for picohttpparser remain real: 6,000 vendored lines is 6,000 lines against the §51.3 budget; zero-copy parsing genuinely is faster; and llhttp's callback model interacts less cleanly with a poll loop that may deliver partial reads.

#### Decision: picohttpparser (2026-09-07)

**Resolved, and on a basis the comparison above did not anticipate.** The strictness layer was built *before* the parser was chosen: `zu_framing.c` implements every §18.1 rule with a test per row, and the header store re-validates every field regardless of what the parser accepted. The 800–1,200 lines this table treats as picohttpparser's hidden cost are written, tested under ASan/UBSan, and will be fuzzed at S18.

With that cost already paid and verified, the remaining comparison is 803 vendored LOC against roughly 8,000, for a parser whose only remaining job is splitting a status line and a header block. picohttpparser wins on the §51.3 budget.

What this project gives up, and must keep visible:

- No upstream fuzzing of the framing rules. Ours are the only ones. §43 must treat `zu_framing.c` as the primary target, not a secondary one.
- h2o's repository is effectively frozen, so no upstream security response should be expected. §46.2's dependency watch applies with full force.
- The contiguous-header-block requirement stands: `max_header_bytes` bounds both the allocation and the repeated scan.

Revisit only if the framing layer proves harder to keep correct than this decision assumed.

### A.4 Vendored Mbed TLS

Considered:

```text
Mbed TLS everywhere
```

Advantages:

- One TLS implementation.
- Portable.
- Permissive licensing.
- No system OpenSSL dependency.

Rejected as default because:

- Duplicates cryptography already supplied by platforms.
- Requires explicit trust-store integration.
- Increases vendored source.
- Security updates become package-maintainer responsibility.
- Native system trust behavior is desirable.

Native/system TLS remains preferred.


---

## Appendix B — Risk Register

Ordered by expected impact. Each risk has an owner-facing mitigation and an explicit trigger for abandoning or rescoping the approach.

| ID | Risk | L | I | Mitigation | Kill / rescope trigger |
|---|---|---|---|---|---|
| ~~R-1~~ | ~~**macOS TLS dead end.**~~ **RETIRED 2026-09-07** by the S0 spike: OpenSSL engine + `SecTrustEvaluateWithError` works with TLS 1.3, Keychain trust, and a caller-owned poll loop. | — | — | — | — |
| **R-12** | **macOS forked HTTPS crashes.** Security.framework's `trustd` XPC connection does not survive `fork()`; a child calling it after the parent segfaults (S0 F-5). `mclapply` + HTTPS is a very common R pattern. | **High** | **High** | PID guard on the trust evaluator raising a named condition instead of dying (§26.4); document `PSOCK`/`multisession` as the supported path | Cannot reliably detect the forked state before the crash → macOS HTTPS must be documented as unsupported under forked parallelism |
| **R-13** | **No CRAN-viable macOS TLS engine.** S0 linked Homebrew OpenSSL; CRAN macOS binaries need a static engine from the recipes toolchain or an alternative (§62.1). | Medium | High | Resolve during S4 before committing to the macOS backend | No acceptable engine → fall back to TLS 1.2-only Secure Transport, or drop macOS |
| **R-2** | **Schannel overrun.** 1,500–2,500 lines of security-critical code, low-confidence estimate (§13.4, §64). | High | High | Time-box the spike; measure LOC against §51.3 early | Schannel backend exceeds 3,500 LOC or 8 weeks → reconsider a portable engine + `CertGetCertificateChain` trust on Windows too |
| **R-3** | **CONFIRMED 2026-09-07 (S1).** Rtools mingw-w64 11.0 lacks the `SCH_CREDENTIALS` / `TLS_PARAMETERS` typedefs; not a version gate (§47.4). Blocks TLS 1.3 on Windows only. | **Certain** | Medium | Declare the two structures locally behind a feature guard; the constants already exist. **ABI must be verified on a real Win10+ target** — a wrong layout into `AcquireCredentialsHandle` is a memory-safety bug, not a compile error | ABI cannot be verified confidently → ship Windows TLS 1.2-only for v1, documented |
| **R-4** | **Size budget blown.** Vendored dependencies plus three backends exceed the auditability claim that justifies the project (§51.3). | Medium | High | Hard thresholds in §51.3; parser and URI decisions made against them | > 40k total LOC or > 12k project-owned → the "small and auditable" positioning is false; revise §1 and §6 publicly or stop |
| **R-5** | **Security defect in own TLS glue or framing.** A memory-safety or verification bug in code with no upstream to inherit fixes from. | Medium | **Very high** | §43 fuzzing, §44 static analysis, §45 external review, strict §18.1 | A verification-bypass class bug found post-release → mandatory external audit before any further release |
| **R-6** | **Bus factor.** Single maintainer for a security-critical package that other packages depend on (§46.3). | High | High | Recruit a second maintainer with CRAN rights before 1.0; document the risk in README | No second maintainer at 1.0 → ship 1.0 labelled experimental, or do not encourage dependents |
| **R-7** | **Performance regression from architecture.** Non-blocking poll loop with frequent interrupt checks is slower than libcurl's tuned path (§51). | Medium | Medium | Benchmark from the first prototype, not at the end | Worse than 2× `curl` on keep-alive p50 after tuning → the performance premise fails |
| **R-8** | **Cancellation correctness.** Longjmp past C frames leaks descriptors or corrupts pooled connections (§25.2, §26.3). | Medium | High | `R_UnwindProtect` + external-pointer ownership; ASan/valgrind interrupt tests in §50.6 | Leaks persist under test → interrupt handling redesigned before any release |
| **R-9** | **Fork corruption.** Inherited TLS connections used concurrently by parent and child (§26.4). | High (if unhandled) | High | PID guard on every pool acquisition and in every finalizer; §50.6 test | — mitigated by design; the risk is forgetting it |
| **R-10** | **CRAN friction.** System dependency declaration, third-party attribution, configure portability (§47, §49). | Medium | Low | Follow §47.3 and §49.2 precisely; submit early with a minimal version | — cost is delay, not failure |
| **R-11** | **No adopter.** The package works and nobody uses it, because `curl` is adequate and trusted. | Medium | Medium | Validate demand against the §31.16 workflows with real package authors before 1.0 | No adopter interest after the prototype → finish it as a learning exercise, do not take on §46's ongoing obligations |

#### Reading this table

R-1 through R-4 are resolved or falsified by the prototype in §63 and should be attacked in that order. R-5 and R-6 are permanent conditions of the architecture rather than problems to be solved — they are the ongoing price of not depending on libcurl, and §6 must not pretend otherwise.

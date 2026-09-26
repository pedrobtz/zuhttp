# zuhttp Design

**Edition:** 2 — normative specification, rewritten 2026-09-25 after v0.1.0
**Target:** R package, CRAN-compatible source package, C core
**Scope:** HTTP/1.1 over HTTP and HTTPS, on each platform's own TLS stack and trust store
**Companion:** [roadmap.md](roadmap.md) — milestones M0–M3 and work packages W1–W19
**History:** [history/zuhttp-design-v1.md](history/zuhttp-design-v1.md) — edition 1 verbatim (4,330 lines), with every spike measurement and "how this landed" narrative

---

## How to read this document

**This edition is a specification, not a log.** Edition 1 grew by accretion —
"an earlier draft…", "how this landed…" — until prose and code disagreed in
places the 2026-09-22 review had to correct one by one (#20). Edition 2 states
what zuhttp *is* and what it *will be*, in the present tense, and moves the
narrative to `history/`. Findings that change the plan go in the roadmap's
findings log; a finding that changes the *specification* changes this file,
in the same commit as the code.

Five rules keep it that way:

1. **Section numbers are stable anchors.** The code cites this document
   ~1,100 times by `§n.m`. No section is ever renumbered or deleted; a section
   whose content is retired keeps its heading and says so in one line.
2. **Every section has a status**, one of **Built**, **Partial**,
   **Planned (Wn)** or **Out of scope**, on its first line. Status never goes
   in a heading (roadmap rule 4).
3. **MUST / SHOULD / MAY** are RFC 2119. A MUST that the code does not meet is
   either a defect with an issue number or a **Partial** status that names the
   gap. It is never silent.
4. **Every decision is a register row.** Prose argues; the register decides.
   A row is **Accepted**, **Proposed** (accepted when the PR that implements
   it merges), **Open** (a question with a named way to answer it) or
   **Rejected**.
5. **Measured beats estimated.** Where a number exists it is quoted with its
   date; where it does not, the section says "unmeasured".

---

## Decision Register

### Accepted (edition 1, carried forward)

| # | Decision | Status | § |
|---|---|---|---|
| D-1 | R prefix `zu_`, response accessors `zu_resp_`; C macros `ZUHTTP_` (internal C prefix: D-66) | Accepted | 1.1 |
| D-2 | No `zuhttp` export may collide with an httr2 export | Accepted | 1.1, 5 |
| D-3 | Separate the TLS protocol engine from trust evaluation | Accepted | 13.1 |
| D-4 | macOS: Secure Transport engine + `SecTrustEvaluateWithError` trust — **superseded by D-63 when W13 lands** | Accepted | 13.2 |
| D-5 | Windows: Schannel for engine and trust — required, not preferred | Accepted | 13.4 |
| D-6 | Unix: system OpenSSL for engine and trust | Accepted | 13.5 |
| D-7 | Link system zlib; do not vendor miniz | Accepted | 21.1 |
| D-8 | Send `Accept-Encoding: gzip` by default; decode transparently | Accepted | 21.2 |
| D-9 | `zu_resp_raw()` returns decoded bytes | Accepted | 21.2, 31.7 |
| D-10 | HTTP parser: picohttpparser, vendored | Accepted | 8.1 |
| D-11 | URI: vendored subset of uriparser (parse / resolve / recompose) | Accepted | 8.2 |
| D-12 | `ca_file` REPLACES system trust; `ca_extra` ADDS to it | Accepted | 14.2 |
| D-13 | Public-key pinning supported; no custom OCSP/CRL fetching | Accepted | 14.4, 14.5 |
| D-14 | Reject non-ASCII (IDN) hostnames | Accepted | 4 |
| D-15 | Strict framing: reject CL+TE, duplicate CL, non-chunked TE | Accepted | 18.1 |
| D-16 | `zu_resp_header()` returns a character vector, never comma-joined | Accepted | 18.3 |
| D-17 | Redirect method/body rewriting per the §19.1 table | Accepted | 19.1 |
| D-18 | `total` timeout spans all retries and redirects | Accepted | 24.3 |
| D-19 | The client is always a named `client =` argument | Accepted | 31.3 |
| D-20 | Policy objects (`retry =`) are distinct from `middleware =` | Accepted | 31.13 |
| D-21 | Interrupt safety: external-pointer ownership + `R_UnwindProtect` | Accepted | 25.2 |
| D-22 | The PID guard covers the pool **and** the trust evaluator | Accepted | 26.4 |
| D-23 | Clients lazily re-create pools after serialization | Accepted | 26.5 |
| D-24 | Body rewindability is a checked property | Accepted | 28.2 |
| D-25 | `jsonlite` in Suggests; pluggable JSON backend | Accepted | 31.7 |
| D-26 | Conditions built with base R; no rlang | Accepted | 34.3 |
| D-27 | Redaction is one policy applied at every egress | Accepted | 42 |
| D-28 | zuhttp's own tests use the `zu_stream` mock, not the R transport mock | Accepted | 50.1 |
| D-29 | Concurrency, if ever built, integrates with `later` — **not before 1.0 (D-67)** | Proposed | 30.2 |
| D-30 | DNS is not interruptible in 0.x; documented — **superseded by D-59 when W14 lands** | Accepted | 8.4, 25.4 |
| D-31 | Revocation checking off by default, opt-in | Accepted | 14.5 |
| D-32 | HTTPS in a forked child raises an actionable error, never a segfault | Accepted | 26.4 |
| D-33 | `check = TRUE` by default: 4xx/5xx raise | Accepted | 31.14 |
| D-34 | `base_url` is joined textually, not resolved per RFC 3986 | Accepted | 31.3 |
| D-35 | Three-state policy merge: absent inherits, `NULL` resets, value overrides | Accepted | 31.9 |
| D-36 | The live pool hangs off the client as an attribute environment | Accepted | 26.5 |
| D-37 | Pooling is on by default; `zu_client(pool = NULL)` opts out | Accepted | 26.2 |
| D-38 | `zu_pool_stats()` is exported, so reuse is observable | Accepted | 26.2 |
| D-39 | The §42.1 secret-parameter list is extended for the cassette egress | Accepted | 42.1, 37 |
| D-40 | A cassette's match key is computed from the redacted request | Accepted | 37 |
| D-41 | Cassettes are written uncompressed, so a byte-level canary means something | Accepted | 37, 42.4 |
| D-42 | Retrying is off by default (`attempts = 1`) | Accepted | 33 |
| D-43 | Retry admissibility is decided once, before the first attempt | Accepted | 33.1 |
| D-44 | The retry loop sits inside middleware | Accepted | 31.13 |
| D-45 | The response sink argument is `path =`; `file =` is a request body | Accepted | 27, 31.6 |
| D-46 | The body path lives in `zu_body.c`, so it is mock-testable | Accepted | 27, 50.1 |
| D-47 | A callback is caught on error and interrupt only | Accepted | 27.3 |
| D-48 | Proxying is disabled with `proxy = FALSE`, not `NULL` | Accepted | 20.1, 31.9 |
| D-49 | `verify` is a merged policy argument; `zu_tls()` carries `ca_file`, `ca_extra`, `pins`, `revocation`, `min_version` | Accepted | 14.1, 31.9 |
| D-50 | `redirect.followed` carries the resolved target, built like `final_url` | Accepted | 35.3 |
| D-51 | A URL enters the trace only through `zu_trace_add_url()`, which redacts in C | Accepted | 35.3, 42.2 |
| D-52 | `final_url` is redacted in the engine | Accepted | 42.1, 42.2 |
| D-53 | One response sink: `path` and `callback` are mutually exclusive | Accepted | 27.1 |
| D-54 | zuhttp consumes no `zu*` sibling in 0.x; internal C moves off `zu_` | Accepted 2026-09-25 | 5.1 |
| D-55 | Features deferred from 0.1.0 target 0.2.0; 0.1.x is fixes only | Accepted 2026-09-25 | 57 |
| D-56 | An unhonourable `zu_tls()` setting raises `zu_tls_unsupported_error` before any I/O, from a per-backend capability mask in C | Accepted 2026-09-25 | 14, 34.1, 39 |

### New in edition 2

Each row is decided here and implemented by the named work package; it is
accepted when that work package's PR merges.

| # | Decision | Status | § | Work |
|---|---|---|---|---|
| D-57 | Timeout phases are **`connect`**, **`read`**, **`write`** and **`total`**. `connect` covers TCP and the TLS handshake (per hop, elapsed); `read`/`write` are inactivity timers; `tls` and `pool` are dropped | Proposed | 24.1 | W7 |
| D-58 | Defaults: `total = 30` s, `connect = 10` s, `read`/`write` unset (bounded by `total`). §24.5's 300 s is rejected: 30 s is what shipped and what an API client wants | Proposed | 24.5 | W7 |
| D-59 | DNS becomes cancellable: `getaddrinfo()` on a **detached helper thread** that never touches R, handing its result back through a pipe the poll loop watches. A scoped exception to §29.1, the same model as libcurl's threaded resolver | Proposed | 8.4, 25.4, 29.1 | W14 |
| D-60 | SubjectPublicKeyInfo is extracted by **one project-owned, bounded DER walker** shared by Secure Transport and Schannel; the digest comes from the platform (CommonCrypto, CNG). The walker is fuzz target 11 | Proposed | 14.4 | W9 |
| D-61 | Windows custom trust: `ca_file` builds a chain engine with an exclusive root store; `ca_extra` evaluates against the system engine first and, on an untrusted-root result only, against an exclusive-root engine over the extra store | Proposed | 14.3 | W8 |
| D-62 | Revocation stays **platform-provided**. OpenSSL refuses `revocation = TRUE` unless `zu_tls(crl_file = )` supplies CRLs; zuhttp never fetches OCSP or CRLs, and offers no soft-fail mode | Proposed | 14.5 | W10 |
| D-63 | macOS uses **Network.framework**, Apple's native, non-deprecated TLS, with trust still from our `SecTrustEvaluateWithError`. Direct HTTPS works on every macOS that R supports; HTTPS **through a proxy requires macOS 14**. Secure Transport is removed rather than kept as a fallback, because keeping it would keep the `--as-cran` NOTE. zuhttp vendors no TLS library; a bundled engine, if ever needed, comes from **`zucrypt`** | Accepted 2026-09-26 (maintainer; measured in `spike/network-framework/`) | 13.2, 5.1, 56 | W13 |
| D-71 | On macOS an HTTPS stream is **dialled** by the TLS backend (`zu_tls_dial()`, `ZU_TLS_CAP_DIALS`), which does TCP, DNS and CONNECT itself; everywhere else, and for plain HTTP, the engine still opens the socket and the backend wraps it | Proposed | 9, 13.2, 20.3 | W13 |
| D-64 | Windows TLS 1.3 ships only behind a CI job that proves the local `SCH_CREDENTIALS` / `TLS_PARAMETERS` layout equals MSVC's; otherwise Windows stays TLS 1.2 and scope cut 4 is recorded as taken | Proposed | 13.4, 47.4 | W15 |
| D-65 | Export surface: exactly the **17** removals in §53, leaving **58** functions at 0.2.0 (75 today); every condition also inherits **`zuhttp_error`**, directly above `error` | Proposed | 34.1, 53 | W3 |
| D-66 | Internal C identifiers become `zuh_` / `ZUH_`; only `R_init_zuhttp` is exported from the shared object | Proposed | 1.1, 11 | W2 |
| D-67 | No asynchronous or concurrent requests before 1.0 (answers §62 Q15 for 0.x). R connection sinks (§27.5) are **rejected** — `callback` covers them. Client certificates are post-1.0, on demand | Proposed | 27.5, 30, 38 | — |
| D-68 | Default `redirects` is **10**, as §19.4 always said; the shipped default of 1 was a leftover of the §63.2 slice. An exhausted chain raises `zu_too_many_redirects`; `redirects = 0` returns the 3xx | Accepted 2026-09-26 (#55) | 19.4, 31.9 | — |
| D-69 | The decompression-ratio limit is enforced by default (`max_decompression_ratio = 1000`), as §21.4 requires; today it is implemented in `zu_inflate.c` and switched off at `zu_body.c:35` | Proposed | 21.4, 40 | W6 |
| D-70 | Process: CI runs on every pull request; one PR per work package; a work package's test lands before or with it, `skip()`ped with the package named until then | Proposed | 50 | W1 |
| D-72 | A **connection seam**, `zu_get_opts.dial`: NULL opens real TCP (always, in the package); set, it supplies every connection while everything above it runs for real. It is how the offline suite and fuzz target 10 drive the whole engine | Accepted 2026-09-26 (#58) | 50.1 | — |
| D-73 | Bytes received **past a response's framing** — after `Content-Length`, after a chunked body's trailers, or on a bodiless response — keep that connection out of the pool | Accepted 2026-09-26 (#58) | 26.3 | — |
| D-74 | The interrupt checkpoint runs `R_CheckUserInterrupt()` under `R_tryCatch` and keeps the condition: a user interrupt becomes `zu_interrupted_error`; any other error raised there (a time limit) is re-raised unchanged after the engine unwinds. Its context lives in a per-call slot, never in a pooled stream | Accepted 2026-09-26 (#57) | 25.2 | — |

---

## Part 1 — Scope and Positioning

### 1. Executive Summary

**Status:** Built (0.1.0).

zuhttp is a small HTTP/1.1 client for R that uses the platform's own TLS stack
and trust store instead of bundling cryptography or a CA bundle, and has no
hard R dependencies. It competes with the `curl` package at the transport
layer for the common case — HTTPS requests with system trust, redirects,
streaming, timeouts, proxies, cancellation, structured errors — and does not
try to be libcurl.

It is built from: project-owned C (framing, pool, redirects, proxy, sinks,
three TLS backends, R glue), vendored picohttpparser (D-10) and a uriparser
subset (D-11), system zlib (D-7), and the platform TLS stack (§13).

Measured 2026-09-25: 6.4k code lines of project-owned C (9.3k raw), 7.9k raw
lines vendored, 3.4k lines of R, 75 exports, 1,630 offline C checks (the
engine included), 247 `test_that()` blocks before the local-server suites of
2026-09-26, ten fuzz targets. Combined line coverage of project-owned C: 91.9%
on macOS, 89.4% on Linux (`tools/coverage/`, floors enforced in CI).

#### 1.1 Naming conventions

| Surface | Prefix | Example |
|---|---|---|
| R functions | `zu_` | `zu_get()`, `zu_client()` |
| R response accessors | `zu_resp_` | `zu_resp_status()` |
| R condition classes | `zu_`, root `zuhttp_error` (D-65) | `zu_tls_certificate_error` |
| C identifiers, internal | `zu_` today; `zuh_` after W2 (D-66) | `zu_stream` → `zuh_stream` |
| C macros | `ZUHTTP_` | `ZUHTTP_NO_COMPRESSION` |

`zu_resp_` exists because httr2 exports `resp_status()` and friends and the
two packages are attached together (D-2). The C prefix moves because `zu_` /
`ZU_` is `zukomp`'s public ABI, and `ZU_OK` and `zu_buffer` already collide
with `zukomp.h` (D-54, #15).

#### 1.2 Honest claims

Three claims remain unsubstantiated and MUST be measured or withdrawn before
1.0 (W18): "smaller native code than the alternative" (false on Linux, where
`curl` links system libcurl), "competitive performance" (unmeasured, §51), and
"a possible httr2 backend" (outside this project's control, §5).

### 2. Motivation

**Status:** Accepted rationale.

Most R packages need less than libcurl: reliable HTTPS with system trust,
redirects, streaming, timeouts, proxies, cancellation and useful diagnostics.
zuhttp serves that narrower need with a smaller, auditable architecture,
R-native conditions, first-class cancellation, mockable transports and
built-in observability.

### 3. Goals

**Status:** Partial — see the MUST list for the three open items.

#### 3.1 Primary goals

zuhttp MUST support HTTP/1.1 over HTTP and HTTPS; any method; request headers;
request bodies from memory and files; response bodies to memory, files and
callbacks; `Content-Length` and chunked framing; redirects; gzip and deflate;
IPv4 and IPv6; HTTP proxies and HTTPS over CONNECT with the §20.1 environment
variables; system TLS and system trust on every platform; custom CAs;
configurable verification; connection reuse; bounded resources; structured
timings and error classes; a pluggable transport; R-level middleware; CRAN
source builds; safety across `fork()` and serialization; and no httr2 masking.

**Open against this list:** phase-specific timeouts (§24, W7); custom CAs on
Windows (§14.3, W8); cancellation during DNS (§8.4, W14). R connection sinks
were in this list in edition 1 and are removed (D-67).

#### 3.2 Secondary goals

Built: safe retries with idempotency and `Retry-After` (§33), record/replay
(§37), tracing hooks (§35), pool metrics (§26.2), Basic and Bearer via headers
(§38). Not yet: client certificates (post-1.0, D-67), OpenTelemetry (§59),
Unix-domain sockets (§59).

### 4. Non-Goals

**Status:** Accepted.

| Not supported | Why, and what to do instead |
|---|---|
| HTTP/2, HTTP/3 | §60. Parallel HTTP/1.1 connections cover the in-scope workloads. |
| WebSockets | Different lifecycle; a separate package could reuse the stream layer. |
| Persistent cookie jars | §22. |
| HSTS persistence, Alt-Svc, DNS-over-HTTPS | Durable client state; system resolvers are the predictable default. |
| Multipart, full MIME | §23. A body encoder if ever, not networking. |
| OAuth, cloud signing, NTLM, Kerberos | §38. Middleware or higher-level packages. |
| IDN / punycode | Non-ASCII hostnames are rejected (D-14); pre-encode instead. |
| An event-loop framework | §30. |
| Asynchronous requests before 1.0 | D-67. |

### 5. Positioning in the R Ecosystem

**Status:** Accepted.

zuhttp competes with `curl` at the transport layer and treats httr2 as the
ergonomic baseline for request composition. An httr2 backend is a hypothesis
that needs httr2's maintainers; nothing in the roadmap depends on it. What
zuhttp controls is being a good candidate: one request model, deterministic
merging, and a transport seam (§36). It MUST NOT mask an httr2 export (D-2).

#### 5.1 Relationship to the `zu*` family (D-54)

**Status:** Accepted 2026-09-25.

zuhttp consumes no sibling in 0.x. Compression is system zlib; pin digests
come from each TLS backend; `zuxml` is at most a `Suggests` for a future
`zu_resp_xml()`. `zucrypt` is the named route for a bundled TLS engine on
macOS if native TLS ever stops being enough (D-63, §13.2); taking it would be
zuhttp's first sibling dependency. The shared five-repository family table is in edition 1
§5.1 and changes only in all five repositories at once; its zuhttp licence
cell is stale since #52 closed.

### 6. Comparison with R curl

**Status:** Accepted.

`curl` is mature, broad, fast and battle-tested. zuhttp offers a smaller
scope, system trust on every platform, structured conditions, deadlines and
cancellation, pluggable transports and middleware, safe retries, built-in
observability, two-level mocking and explicit limits.

#### 6.1 Where `curl` is the better choice

HTTP/2 or HTTP/3; NTLM, Kerberos or cloud signing; libcurl's accumulated
interoperability workarounds; any project that cannot accept a
single-maintainer dependency for security-critical code (§46.3, R-6); and
forked parallelism with HTTPS on macOS, where zuhttp raises `zu_fork_error`
(§26.4). A user who picks `curl` after reading this list has chosen well.

---

## Part 2 — Architecture

### 7. High-Level Architecture

**Status:** Built.

```text
R API: verbs, zu_request() |> ..., zu_client()        (§31)
  └─ policy merge, middleware, retry                   (§31.9, §31.13, §33)
      └─ transport: native | mock | cassette           (§36, §37)
          └─ init.c — the only file that includes R headers
              └─ engine: request → framing → body      (§17, §18, §27)
                  ├─ URI + redirects                   (§8.2, §19)
                  ├─ proxy + CONNECT                   (§20)
                  ├─ pool + PID guard                  (§26)
                  └─ zu_stream vtable                  (§9)
                      ├─ TCP (poll, non-blocking)      (§8.5)
                      ├─ TLS engine │ trust evaluator  (§13)
                      └─ mock stream                   (§50.1)
```

Two properties carry the design: the engine and trust evaluator are separate
(§13.1), and the mock stream sits at the same seam as the real transports,
so the whole HTTP engine is testable with no network (§50.1). Decompression
sits between framing and the sink (§21, §27).

### 8. Component Selection

**Status:** Built.

| Component | Role | Size | Decision |
|---|---|---|---|
| picohttpparser | status line + header block | 0.8k raw | D-10 |
| uriparser subset | RFC 3986 parse / resolve / recompose | 7.0k raw, 3.9k code | D-11 |
| zlib | inflate | system | D-7 |
| TLS | engine + trust | system | §13 |
| project-owned | everything else | 6.4k code | §51.3 |

#### 8.1 HTTP parser — picohttpparser (D-10)

picohttpparser splits the status line and header block and makes **no framing
decisions**. Every §18.1 rule lives in `zu_framing.c` and every header is
re-validated by `zu_headers`, so anything §18.1 does not reject, nothing
does. The parser type never crosses `zu_response.c`. It needs the whole header
block contiguous and re-scans from offset 0, so `max_header_bytes` (§40)
bounds both the allocation and the quadratic re-scan.

#### 8.2 URI parser

The uriparser 0.9.8 parse/resolve/recompose closure (eight `.c` files) plus
the policy layer in `zu_uri.c`. Six of uriparser's eight CVEs are in the
excluded modules. Allocations route through `zu_alloc`, so OOM injection
covers the parser. `src/zu_uriparser.h` is the only includer of uriparser.

The policy layer rejects what RFC 3986 accepts but a client must not:
ports above 65535, empty DNS labels, IPvFuture hosts, non-HTTP schemes and
embedded NUL; it strips a root dot, drops fragments and moves userinfo out of
the URL (§20.4). Supplied paths are preserved verbatim, never normalised.
`zu_query()` encodes values from UTF-8, space as `%20`, everything outside
`unreserved` percent-encoded. The boundary is the flat `zu_uri` struct.

#### 8.3 Compression

System zlib (D-7); §21.

#### 8.4 DNS

**Status:** Partial — resolution is synchronous and ignores `timeout` and
Ctrl-C (D-30). On macOS, W13 makes it cancellable through Network.framework;
on Linux and Windows, W14 does (D-59).

`getaddrinfo()` with `AF_UNSPEC`. Until W14 this is the one phase outside
both the deadline and the interrupt guarantee, and it is documented as such in
`?zuhttp_tls`, on every `timeout` parameter and in the README.

**D-59 design.** A request resolves on a detached thread that owns a copy of
the host and port and never calls the R API. It writes the `addrinfo` result
into a heap block and signals a pipe (a socketpair or an event on Windows);
the request's poll loop waits on that pipe with the ordinary deadline and
interrupt checkpoints. On timeout or interrupt the request abandons the
lookup: the thread keeps running until the resolver returns, then frees its
own block. Abandoned lookups are capped at 8 in flight; beyond that a request
raises `zu_dns_error` immediately rather than spawning more. `getaddrinfo_a`
is not used because it is glibc-only; one mechanism on all three platforms.

#### 8.5 TCP

Non-blocking sockets throughout (POSIX sockets, Winsock), `poll()` /
`WSAPoll()`, so deadlines (§24) and interrupts (§25) are enforced by the loop
rather than the kernel.

### 9. Generic Stream Interface

**Status:** Built — `src/zu_stream.h`. On macOS after W13, HTTPS streams are
dialled rather than wrapped (D-71); the vtable is the same.

The HTTP engine depends only on the `zu_stream` vtable: `read`, `write`,
`close`, `destroy`, and `readable(timeout_ms)`, the non-consuming liveness
probe the pool needs (§26.2). Each call takes a `zu_deadline` and a
`zu_error *`. Implementations: plain TCP, TLS (which wraps another stream, so
the same engine serves a direct connection and a CONNECT tunnel), and the
mock. This is the most important boundary in the codebase.

### 10. Platform Abstraction

**Status:** Built.

Platform differences live in `zu_platform.h`, `zu_net.c`, `zu_time.c` and one
`zu_tls_<backend>.c` per TLS stack selected by `configure`. Generic HTTP
logic contains no `#ifdef _WIN32`.

### 11. Source Tree

**Status:** Built.

```text
src/init.c                    R glue; the only file including R headers
src/zu_{engine,request,response,framing,headers,body,sink,inflate}.c
src/zu_{uri,redirect,proxy,pool,fork,net,time,trace,redact,error,alloc,buffer}.c
src/zu_stream.{c,h}, zu_mock_stream.c
src/zu_tls.c                  backend-neutral policy (defaults, D-56 check)
src/zu_tls_{openssl,sectransport,schannel}.c   one per backend
src/vendor/{picohttpparser,uriparser}/         D-10, D-11
inst/COPYRIGHTS, inst/licenses/                §49.2
ctest/  fuzz/  tools/                          not in the tarball
```

The C core compiles without R headers; that is what makes `ctest/` and
`fuzz/` possible and it MUST stay true. After W2 every non-static symbol
except `R_init_zuhttp` is hidden (D-66), checked by `test-abi.R`.

### 12. Recommended Architectural Decision

**Status:** Built.

A small R API over a small C engine, two vendored parsers, a stream
abstraction, and native TLS with native trust — competing on simplicity,
system trust, cancellation, structured errors, middleware, pluggable
transports, safe retries and observability, not on protocol breadth.

---

## Part 3 — TLS and Trust

### 13. TLS Architecture

**Status:** Built on three backends. On macOS, Network.framework replaces Secure Transport in W13 (D-63).

#### 13.1 Separate the protocol engine from trust evaluation

Two questions, answered separately (D-3): who speaks TLS, and who decides a
chain is trusted. Only the second must be native to deliver "system trust".

| Platform | Engine | Trust |
|---|---|---|
| Windows | Schannel | `CertGetCertificateChain` + `CertVerifyCertificateChainPolicy`, Windows store |
| macOS | Secure Transport (D-4) → Network.framework (D-63, W13) | `SecTrustEvaluateWithError`, Keychain — from the verify block after W13 |
| Unix | system OpenSSL | OpenSSL default verify paths |

Every backend breaks the handshake at the server-authentication step, runs
the trust evaluator, and resumes. Each backend declares which `zu_tls()`
settings it honours (D-56, §14.7).

#### 13.2 macOS engine

**Status:** Decided (D-63, 2026-09-26): **Network.framework**, measured GO in
[`spike/network-framework/FINDINGS.md`](../spike/network-framework/FINDINGS.md).
Secure Transport ships until W13 replaces it, and W13 removes it.

Secure Transport has to go for three reasons: it is deprecated (87 SDK
markers), it caps at TLS 1.2, and its deprecation costs an `--as-cran` NOTE.
Edition 1 rejected Network.framework (F-11) because it owns the socket, so
zuhttp could not run TLS over its own CONNECT tunnel. That was an API reading,
never a run. The 2026-09-26 probe answers the objection instead of refuting
it: for HTTPS, Network.framework no longer needs our socket.

| Measured | Result |
|---|---|
| Trust is decided by our `SecTrustEvaluateWithError`, via `sec_protocol_options_set_verify_block` | yes — an empty anchors-only set rejects a host the system trusts (F-13) |
| TLS 1.3 | yes (F-14) |
| Completions bridged to the §25.1 poll loop through a pipe | yes (F-15) |
| `nw_connection_cancel()` to the cancelled state | 0.4 ms, DNS included (F-16) |
| HTTPS through an HTTP CONNECT proxy | yes, `nw_proxy_config_create_http_connect`, **macOS 14+** (F-17) |
| Warning-free at deployment target 11.0 under `-Werror -Wunguarded-availability` | yes; no deprecated API, so no NOTE (F-18) |
| Fork after use | child killed (SIGILL): the §26.4 hazard as before (F-19) |
| `proxy = FALSE` strictly direct | not guaranteed: `prefer_no_proxy` is a preference (F-20) |

**Consequences for the design.**

- **The §9 seam moves on macOS (D-71).** An HTTPS stream is *dialled* by the
  backend (`zu_tls_dial(host, port, proxy, cfg, deadline)`); it is no longer
  *wrapped* around a TCP stream and CONNECT tunnel the engine opened. The
  engine asks the backend (`ZU_TLS_CAP_DIALS`) and skips its own TCP and
  CONNECT for `https://` when it can. Plain `http://`, and every other
  platform, is unchanged. Above the stream, including framing, the pool,
  redirects and sinks, nothing changes.
- **Proxied HTTPS needs macOS 14.** zuhttp still decides per hop *whether* to
  proxy (§20.1–§20.2) and passes the chosen proxy, with Basic credentials,
  into the connection. On macOS 11–13 a proxied HTTPS hop raises
  `zu_proxy_error` saying it needs macOS 14. Direct HTTPS and all HTTP work on
  every macOS that R supports.
- **DNS becomes cancellable on macOS for free** (F-16). D-59's helper thread
  is for Linux and Windows only.
- **Trust code carries over.** `ca_file`, `ca_extra`, revocation and pinning
  (the leaf from `SecTrustGetCertificateAtIndex`, D-60) run in the verify
  block against the same `SecTrustRef` API as today.
- **Still to settle in W13:**
  - per-phase timings, from `nw_connection_access_establishment_report()`;
  - pool liveness without a descriptor (the state handler plus the idle
    timeout, with the §26.2 probe answering "unknown");
  - F-20 on a machine with a system proxy configured.

**The later option: `zucrypt`.** If a portable engine is ever needed on
macOS, for example because a proxied-HTTPS user cannot move to macOS 14, it
is built on `zucrypt`'s cryptography with trust still from `SecTrust`. That
would be zuhttp's first dependency on a sibling, so it amends D-54 and §56
constraint 2 when taken. It is not planned before 1.0. Vendoring a private
Mbed TLS copy and static OpenSSL (4.64 MB) are both rejected (Appendix A).

##### 13.2.1 Trust evaluation is not fork-safe

Security.framework's XPC connection to `trustd` does not survive `fork()`:
a child that evaluates trust after its parent did is killed by SIGSEGV
(S0 F-5). Network.framework is no better: a child that connects after the
parent did dies with SIGILL, because libdispatch refuses to run after
`fork()` (F-19). The PID guard (§26.4) turns both into `zu_fork_error`. Under
Network.framework it must fire before *any* Network.framework call, not only
before trust evaluation.

#### 13.3 TLS is hidden behind the stream interface

The HTTP layer never knows whether a stream is TCP, TLS, a tunnel or a mock
(§9). `zu_tls_connect()` wraps an inner stream; on failure the inner stream is
left to the caller, so a failed handshake never double-frees a socket.

#### 13.4 Windows / Schannel

**Status:** Partial — TLS 1.2; custom CAs (W8), pinning (W9) and TLS 1.3
(W15) open.

SSPI for the protocol with `SCH_CRED_MANUAL_CRED_VALIDATION`, so trust is
evaluated by the §13.1 evaluator against the Windows store. Schannel is
required, not preferred: OpenSSL on Windows has no trust anchors (measured in
the §63.2 slice). ~590 lines as written, against edition 1's 1,500–2,500
estimate.

**TLS 1.3 (D-64).** It needs `SCH_CREDENTIALS` / `TLS_PARAMETERS`, which
Rtools' mingw-w64 headers do not declare (R-3, §47.4). A local declaration
ships only when a CI job on a Windows runner compiles one probe twice — with
MSVC and the Windows SDK, and with mingw and the local declaration — prints
`sizeof` and every `offsetof`, and fails on any difference. With the check in
place, the backend uses `SCH_CREDENTIALS` on Windows 10 1809+ and falls back
to `SCHANNEL_CRED` below it. Without it, Windows is TLS 1.2 and the README
says so.

#### 13.5 Unix/Linux

System OpenSSL ≥ 1.1.1: default verify paths, `X509_VERIFY_PARAM_set1_host`
for hostnames (never hand-rolled), SNI, TLS 1.2+. LibreSSL is best effort.

### 14. Certificate Trust Model

**Status:** Partial — see §14.3, §14.4, §14.5.

#### 14.1 Defaults

`verify_peer` and `verify_hostname` are on and `trust = "system"`. zuhttp MUST
NOT default to disabling verification. `verify = FALSE` is a merged policy
argument (§31.9, D-49), not a `zu_tls()` field. `zu_tls()` carries `ca_file`,
`ca_extra`, `pins`, `revocation` and `min_version`, and after W10 `crl_file`.

#### 14.2 Custom CA semantics

`ca_file` **replaces** the system trust store; `ca_extra` **adds** to it
(D-12). They are two arguments and never one overloaded `ca =`, and each help
text says "replaces" or "adds to" in its first sentence.

#### 14.3 Custom CAs and native trust stores

| Backend | `ca_file` (replace) | `ca_extra` (add) |
|---|---|---|
| OpenSSL | `SSL_CTX_load_verify_locations` on a fresh store | the same call on the default store |
| macOS | `SecTrustSetAnchorCertificates` + `…AnchorCertificatesOnly(true)` | the same with `false` |
| Windows | **refused today (#5); W8 implements D-61** | **refused today; W8** |

**D-61, the Windows design.** Both modes load the PEM file into a
`CERT_STORE_PROV_MEMORY` store; a certificate that does not parse raises
`zu_tls_error` naming the file.

- `ca_file`: a chain engine built with `CERT_CHAIN_ENGINE_CONFIG.hExclusiveRoot`
  set to the memory store, so only its roots anchor a chain.
- `ca_extra`: evaluate with the default engine first. If — and only if — the
  result is `CERT_TRUST_IS_UNTRUSTED_ROOT` or `CERT_E_UNTRUSTEDROOT`, evaluate
  again with an exclusive-root engine over the extra store and accept if that
  chain is trusted. Any other failure (expiry, name, revocation) is final.
  `hAdditionalStore` alone is not enough: it supplies intermediates, not
  anchors.
- The engine is built per connection and freed with it; building one is
  cheap next to the handshake, and caching it would put the CA file's
  contents in the §26.1 key twice.

Every mode is tested with the same locally generated CA supplied both ways:
`ca_extra` and a public host still validates; `ca_file` and it is rejected.

#### 14.4 Certificate pinning

**Status:** Partial — OpenSSL only; macOS and Windows refuse (#4, #12) until
W9 lands D-60.

`zu_tls(pins = "sha256//<base64>")`. The pin is SHA-256 over the leaf's DER
`SubjectPublicKeyInfo`, checked **in addition to** chain and hostname
verification, never instead of them. A mismatch is `zu_tls_pin_error`; a
backend that cannot pin raises `zu_tls_unsupported_error` before connecting
(D-56). The two MUST stay distinct classes.

**D-60 design.** `zu_spki_locate(der, len, &off, &n)` walks exactly
`Certificate → TBSCertificate → [0] version? → serialNumber → signature →
issuer → validity → subject → subjectPublicKeyInfo` and returns the SPKI's
full TLV. It accepts DER only: definite lengths, no length above the buffer,
at most four length octets, and each element's tag checked. It is ~120 lines,
allocates nothing, and is fuzz target 11 with a corpus of real leaf
certificates plus truncations at every boundary. Input comes from
`SecCertificateCopyData()` on macOS and `CERT_CONTEXT.pbCertEncoded` on
Windows; the digest from CommonCrypto (`CC_SHA256`) and CNG (`BCrypt*`) respectively. The
OpenSSL backend keeps `i2d_X509_PUBKEY`, and a ctest asserts the walker and
OpenSSL agree on a corpus of certificates.

#### 14.5 Revocation

**Status:** Partial — off by default everywhere (D-31); opt-in works on macOS
and Windows; OpenSSL refuses (D-56).

Off by default for two measured reasons (S0 F-4): it costs 7–15× in trust
evaluation, and the fetch runs inside the platform evaluator where zuhttp can
neither deadline nor cancel it. `zu_info()` reports the effective policy.

**D-62.** Revocation checking is whatever the platform's evaluator does when
asked; zuhttp never fetches OCSP or CRLs itself and offers no soft-fail mode.
Soft-fail passes whenever the responder is unreachable, which is exactly when
an attacker who can block it wants it to pass. On OpenSSL, which has no
source of its own, `revocation = TRUE` is refused unless the caller supplies
CRLs with `zu_tls(crl_file = )` — the enterprise case, where an internal PKI
publishes CRLs — and then `X509_V_FLAG_CRL_CHECK | CRL_CHECK_ALL` applies
against them. OCSP stapling is not pursued: the largest public CA retired OCSP
in 2025, so stapling would check less every year.

Measured caveat, macOS: under `revocation = TRUE` a valid certificate from a
CA that no longer answers revocation queries is rejected. Windows behaviour
(`CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT`) is unmeasured; W10 measures
it with a locally generated revoked certificate and CRL.

#### 14.6 Diagnosable failures

Separate classes for: expired or not-yet-valid, hostname mismatch, untrusted
issuer, revoked (where the platform reports it), handshake failure, pin
mismatch, and unsupported setting (§34.1). A message that is only a backend
code fails §61.9.

#### 14.7 Backend capabilities (D-56)

**Status:** Built 2026-09-25.

Each backend exports `zu_tls_backend_caps()`, a mask over `pins`, `tls13`,
`ca_file`, `ca_extra` and `revocation`. `zu_tls_config_check()` in `zu_tls.c`
applies it — from the R request path before DNS, and again first thing in
`zu_tls_connect()` — raising `zu_tls_unsupported_error` with the setting and
the backend named. `zu_info()$tls_capabilities` reports the mask. Tests read it
through `skip_unless_tls_supports()`; no R code keeps a table of backends.

| Setting | OpenSSL | macOS | Windows |
|---|---|---|---|
| `pins` | yes | W9 | W9 |
| `tls13` | yes | W13 (Network.framework) | W15 |
| `ca_file`, `ca_extra` | yes | yes | W8 |
| `revocation` | with `crl_file` (W10) | yes | yes |

### 15. Native TLS Backend Interface

**Status:** Built — `src/zu_tls.h`.

`zu_tls_connect(out, inner, hostname, cfg, deadline, err)` wraps an inner
stream and returns a TLS stream; `zu_tls_get_info()` reports protocol, cipher
and trust backend (§35.2); `zu_tls_backend_name()`, `zu_tls_available()` and
`zu_tls_backend_caps()` describe the build. Backends normalise their retry
states to would-block, closed and fatal before anything above them sees one.

### 16. Native System Configuration

**Status:** Partial — trust is native everywhere; proxies come from the
environment only.

System proxy settings (WinHTTP, SystemConfiguration) are not read (§59);
environment variables and explicit arguments are.

---

## Part 4 — HTTP Semantics

### 17. HTTP Request Construction

**Status:** Built — `src/zu_request.c`.

The builder writes the request line (origin-form, or absolute-form to an HTTP
proxy), `Host`, headers, and `Content-Length` into a checked buffer with
overflow-safe integer formatting.

#### 17.1 Header injection

Header names MUST be RFC 7230 tokens; values MUST NOT contain CR, LF or NUL.
Violations raise; nothing is silently stripped. The same rules apply to values
zuhttp derives from user input — the request target, `Host`, proxy
credentials.

#### 17.2 Default headers

`Host` (from the URI, never user-settable to a conflicting value),
`User-Agent: zuhttp/<version>`, `Accept: */*`, `Accept-Encoding: gzip` (§21.2),
`Connection: keep-alive` (`close` without a pool). Each is overridable.

#### 17.3 `Expect: 100-continue`

Never sent automatically. Informational `1xx` responses are skipped.

### 18. Response Parsing and Body Framing

**Status:** Built — `src/zu_framing.c`, the primary fuzz target.

Handles the status line, repeated `1xx`, headers, `Content-Length`, chunked,
close-delimited bodies, HEAD, and body-less `204`/`304`.

#### 18.1 Framing precedence and smuggling defenses

Strict, not permissive (D-15):

| Condition | Behaviour |
|---|---|
| `Transfer-Encoding` present, final coding `chunked` | chunked; ignore `Content-Length` |
| `Transfer-Encoding` present, final coding not `chunked` | reject |
| both `Transfer-Encoding` and `Content-Length` | reject |
| more than one `Content-Length`, equal or not | reject |
| `Content-Length` not plain decimal or overflowing `uint64` | reject |
| chunk size invalid hex, overflowing, or above `max_chunk_size` | reject |
| neither header, body possible | read to close; not poolable |
| `obs-fold` | reject |
| malformed status line, status not three digits | reject |

Rejections raise `zu_http_parse_error`, and the connection is closed, never
pooled (§26.3).

#### 18.2 Chunked trailers

Parsed, counted against the header limits, and discarded. Never merged into
the response headers.

#### 18.3 Duplicate response headers

Order and repetition are preserved. `zu_resp_header(res, name)` is
case-insensitive and returns a character vector — length 0 absent, more than
1 repeated — and never comma-joins (D-16).

#### 18.4 Header limits

Every §40 header limit is enforced before bytes reach the parser, as the
buffer grows.

### 19. Redirect Handling

**Status:** Built — `src/zu_redirect.c`.

#### 19.1 Method and body rewriting (D-17)

| Status | Method | Body |
|---|---|---|
| 301, 302 | POST → GET; others unchanged | dropped when rewritten |
| 303 | any → GET (HEAD stays HEAD) | always dropped |
| 307, 308 | never rewritten | preserved; must be rewindable (§28.2), else `zu_redirect_error` |

#### 19.2 Header stripping

On any change of scheme, host or port, strip `Authorization`, `Cookie`,
`Proxy-Authorization` and any header marked sensitive.

#### 19.3 Downgrade policy

HTTPS → HTTP is refused with `zu_redirect_error` by default.

#### 19.4 Limits applied across the chain

`redirects` (**default 10**, D-68) raises `zu_too_many_redirects` when a
chain would exceed it (`redirects = 0` returns the 3xx itself); the `total` deadline and `max_body` span the whole
chain; a repeated (method, URL) pair is a loop and raises.

#### 19.5 Interaction with sinks

Redirect bodies never reach the caller's sink. They are drained into a
discard sink up to `max_redirect_body` (64 KiB); beyond it the connection is
closed instead.

#### 19.6 Resolving the `Location` header

Resolved against the URL of the request that produced it, RFC 3986 §5.2.2
strict, from a byte range (not a C string), with the base rebuilt without
userinfo. The result passes the full §8.2 policy layer.

### 20. Proxy Support

**Status:** Built — `src/zu_proxy.c`.

#### 20.1 Environment variables

| Variable | Read | Note |
|---|---|---|
| `http_proxy` | lowercase only | `HTTP_PROXY` is ignored (httpoxy) |
| `https_proxy`, `HTTPS_PROXY` | both | |
| `all_proxy`, `ALL_PROXY` | both | fallback for both schemes |
| `no_proxy`, `NO_PROXY` | both | |

An explicit `proxy =` wins; `proxy = FALSE` disables proxying (D-48), and
`NULL` means "the package default", which is "consult the environment".

#### 20.2 `NO_PROXY` matching

Comma-separated; `*` matches everything; a leading dot is ignored; matching is
on label boundaries, case-insensitive; an entry may carry a port; IP literals
match exactly; CIDR is not supported.

#### 20.3 Request forms

HTTP through a proxy uses absolute-form. HTTPS tunnels with CONNECT, parsed
with §18 strictness; a non-2xx is `zu_proxy_error` carrying the proxy's
status. Nothing may follow the CONNECT response header block. The proxy is
resolved per hop, so a redirect across a `NO_PROXY` boundary goes the right
way.

On macOS after W13, the CONNECT for HTTPS is Network.framework's
(`nw_proxy_config_create_http_connect`, macOS 14+, D-71). zuhttp still
decides whether a hop is proxied and which proxy to use. On macOS 11–13 a
proxied HTTPS hop raises `zu_proxy_error`. Network.framework may also fall
back to a *system* proxy when a direct connection fails (F-20); W13 either
closes that gap or documents it next to `proxy = FALSE`.

#### 20.4 Credentials

None or Basic. `Proxy-Authorization` goes only to the proxy — on the CONNECT
for HTTPS — never to an origin, never across a redirect. Credentials in a
proxy URL are moved out of it at parse time and redacted everywhere (§42).
Pooled tunnels are keyed on proxy identity including credentials (§26.1).

### 21. Content Encoding

**Status:** Partial — the ratio limit is off (D-69, W6).

#### 21.1 zlib, not miniz

System zlib (D-7). `gzip` is decoded with `inflateInit2(15 + 16)`, which
accepts the gzip wrapper only — a zlib stream labelled `gzip` is refused as
malformed (measured 2026-09-26; edition 1 said `15 + 32`, auto-detect).
`ZUHTTP_NO_COMPRESSION` removes the module. Brotli and zstd are §59.

#### 21.2 `Accept-Encoding` policy

`gzip` is sent by default and decoded transparently (D-8); `zu_resp_raw()`
returns decoded bytes (D-9); `decode = FALSE` keeps the wire bytes and the
`Content-Encoding` header. `zu_resp_timings()` reports wire and decoded sizes.

#### 21.3 `deflate`

zlib-wrapped first, raw DEFLATE on a header error.

#### 21.4 Decompression limits

Enforced during inflation, not after: `max_body` caps decoded output
(16 MiB by default), and `max_decompression_ratio` caps output ÷ input once
32 input bytes have been seen. Either raises `zu_body_limit_error` and closes
the connection. **The ratio check exists in `zu_inflate.c` but is passed 0
by `zu_body.c:35` and so never runs; D-69 turns it on at 1000.** The absolute
cap bounds a bomb today; the ratio makes it fail after kilobytes, not
megabytes. `Transfer-Encoding: gzip` is rejected (§18.1).

### 22. Cookies

**Status:** Accepted scope. No cookie jar. `Cookie` may be sent manually;
`Set-Cookie` is exposed as a vector (§18.3).

### 23. Multipart

**Status:** Out of scope. If ever added, a body encoder above the core.

---

## Part 5 — Runtime Model

### 24. Timeout Model

**Status:** Partial — `total` only; W7 implements D-57 and D-58, after W4
lands the tests it is built against.

#### 24.1 Definitions (D-57)

| Phase | Bounds | Kind | Condition `phase` |
|---|---|---|---|
| `connect` | TCP connect and TLS handshake of one hop, including CONNECT through a proxy | elapsed, per hop | `"connect"` |
| `read` | time with no byte received — waiting for the first byte and between body bytes | inactivity | `"read"` |
| `write` | time with no byte sent | inactivity | `"write"` |
| `total` | the whole `zu_perform()` call: every hop, every retry, every backoff | elapsed | `"total"` |

`read` and `write` reset on every byte, so a slow 100 MB download that keeps
moving never trips them. DNS is inside `connect` once W14 makes it
interruptible; until then it is bounded by nothing.

`tls` is folded into `connect`, as in HTTPX: a user asks "how long may
establishing the connection take", and a separate handshake budget adds a
knob without adding an answer. `pool` is dropped: a synchronous,
single-threaded client never waits for a pooled connection — acquisition
either finds one or opens one.

API: `timeout =` on the verbs, the client and `zu_req_timeout()` takes a
number (seconds of `total`) or `zu_timeout(total, connect, read, write)`.
`zu_req_timeout(req, total, connect, read, write)` sets any subset.

#### 24.2 Composition

`effective_deadline(phase) = min(now + phase_timeout, request_deadline)`,
where `request_deadline` is fixed from `total` when the call begins. Whichever
fires first names the phase in `zu_timeout_error$phase`.

#### 24.3 Scope of `total` across retries and redirects (D-18)

`total` spans every hop and every attempt and is never reset. `zu_retry(
attempt_timeout = )` bounds each attempt within it. The retry layer checks the
remaining budget before sleeping and fails rather than sleep past it.

#### 24.4 Clocks

Monotonic only. A platform with no monotonic clock fails to **build**; the
suite asserts the clock advances, and `tools/check-feature-macros` guards the
feature-macro class of bug that once made `zu_now_ms()` return 0 on Linux.

#### 24.5 Defaults (D-58)

`total = 30` s, `connect = 10` s, `read` and `write` unset. No timeout is
infinite by default; `timeout = Inf` is explicit. The `connect` default exists
so that a black-holed host fails with a phase that says so, leaving budget for
a retry.

### 25. R Cancellation and Interrupts

**Status:** Partial — the unwind is built; the 200 ms bound is unmeasured
(#7, W11); DNS is outside it until W14.

#### 25.1 Model

Non-blocking sockets; poll in slices of at most 100 ms; between slices return
to an R-safe checkpoint and call `R_CheckUserInterrupt()`; unwind cleanly. No
native call blocks indefinitely and no thread other than R's calls the R API.
Measured: the checkpoint fires every ~100 ms over a 10 s request.

#### 25.2 The longjmp problem (D-21)

`R_CheckUserInterrupt()` and any R error raised from a callback longjmp past C
frames. All native state is owned through external pointers with finalizers,
and the request loop runs under `R_UnwindProtect()` so resources are released
at the unwind rather than at the next GC.

The poll-tick checkpoint never lets `R_CheckUserInterrupt()` longjmp through
the engine: it runs under `R_tryCatch` on `interrupt` and `error`, keeps the
condition, and the engine unwinds through its own error paths. A user
interrupt then becomes `zu_interrupted_error` (measured: ~10 ms after SIGINT
on Rscript); anything else — `setTimeLimit()`, `R.utils::withTimeout()` — is
re-raised as itself (D-74).

#### 25.3 Connection state after cancellation

An interrupted connection is closed, never pooled.

#### 25.4 Platform notes

GUI front-ends (Rgui, RStudio) may need `R_ProcessEvents()` for Ctrl-C to be
delivered; W11 measures all three front-ends. **DNS is not interruptible until
W14 (D-30 → D-59).** The limitation is in user-facing help.

#### 25.5 Explicit cancellation

A programmatic cancellation token is not planned before 1.0 (D-67); it would
reuse the §25.1 checkpoint.

### 26. Connection Pool

**Status:** Built — `src/zu_pool.c`, `src/zu_fork.c`.

#### 26.1 Pool key

Two requests share a connection only if all of these match, compared by
value: scheme, host as written, port, proxy identity including credentials,
the whole TLS configuration (verify flags, CA source, `ca_extra`, pins,
minimum version, revocation, ALPN), and the owning PID. A coarse key is a
security bug: without the TLS fields a pinned request is served over an
unpinned connection and the pin is never checked (asserted in `test-tls.R`).

#### 26.2 Policy

Keep-alive honouring `Connection: close`; global idle maximum, per-host
maximum, idle timeout; defaults `zu_pool(max_idle = 16, max_per_host = 4,
idle_timeout = 30)`. On by default (D-37); counters via `zu_pool_stats()`
(D-38). A pooled socket that is readable before a request is written is
stale and discarded; the probe never consumes a byte, and "unknown" is not
"safe". A dialled macOS stream has no descriptor to probe (D-71): it answers
"unknown", and the connection's state handler plus the idle timeout decide.

#### 26.3 When a connection must NOT be reused

Body not fully consumed; cancelled or timed out; any §18.1 rejection;
close-delimited framing; `Connection: close` from either side; a redirect body
over `max_redirect_body`; any TLS error, including an unsupported-setting
refusal; **any byte received past the response's framing** (D-73). When in
doubt, close.

#### 26.4 Fork safety

Two hazards, one mechanism (`zu_fork.{h,c}`):

1. **Inherited connections.** Every pool records its creator's PID and checks
   it on every acquire, release and free. On mismatch, inherited connections
   are dropped without a TLS shutdown (which would write into the parent's
   session) and the pool is re-initialised.
2. **The trust evaluator (macOS).** On a PID mismatch after the parent used
   Security.framework, trust evaluation is refused with `zu_fork_error`
   instead of a SIGSEGV (D-32). Forked HTTPS does not work on macOS; PSOCK
   clusters and `multisession` do, because they exec.

`tools/ci-fork-guard.R` runs the second hazard in CI and fails on a skip as
well as a failure.

#### 26.5 Serialization and session lifetime (D-23, D-36)

A client's value holds only pool **configuration**; the live pool hangs off an
attribute environment. A pointer that did not survive `readRDS()` is detected
by tag plus NULL address and rebuilt lazily. `zu_client_update()` copies share
the parent's pool, which the §26.1 key makes safe.

### 27. Streaming Model

**Status:** Built — `src/zu_sink.c`, `src/zu_body.c`.

One sink contract — write, finish, abort, destroy — for memory, file, discard
and callback. No whole-body allocation outside the memory sink: 100 MiB to a
file or discard grows peak RSS by 0 KiB (measured, with a memory-sink control
at ~100 MB).

#### 27.1 Sinks and limits

`max_body` applies to every sink. A file sink writes beside its destination
and renames on success, so failure never leaves a truncated file and an
existing destination is replaced only at the rename (D-53). A non-2xx
response still writes; `check` runs after the sink commits. `path` and
`callback` are mutually exclusive, and a committed path is `zu_resp_path()`.

#### 27.2 Calling back into R

Main thread only; everything reachable is protected; returning `FALSE` stops
the transfer cleanly and makes the connection unpoolable.

#### 27.3 Callback errors and the longjmp hazard (D-47)

Callbacks run under `R_tryCatch()` catching **error and interrupt only** —
warnings and messages continue. A caught condition unwinds the native loop,
releases the connection, and is re-signalled unchanged.

#### 27.4 Re-entrancy

A callback may issue requests, except on the client whose connection it is
reading from, which raises instead of deadlocking.

#### 27.5 R connections as sinks

**Rejected (D-67).** `callback =` covers the use case without routing bytes
through R's connection buffering.

#### 27.6 Implementation record

Retired: see edition 1 §27.6.

### 28. Request Body Sources

**Status:** Built for memory and file bodies; streaming request bodies are not
planned before 1.0.

#### 28.1 Framing

Known sizes send `Content-Length`, including a stat-ed file.

#### 28.2 Rewindability (D-24)

| Source | Rewindable |
|---|---|
| `NULL`, raw, character | yes |
| file | yes, if its size is unchanged |

`zu_body_rewindable()` is checked by retry (§33.1) and 307/308 redirects
(§19.1); a body that cannot be replayed raises `zu_body_not_replayable`.

#### 28.3 Body and content type

`zu_body_json()` sets `application/json`, `zu_body_form()` sets
`application/x-www-form-urlencoded`; file and raw bodies set nothing. An
explicit header always wins.

### 29. Threading and Process Model

**Status:** Built; W14 adds the one scoped exception.

#### 29.1 Threading

zuhttp creates no threads, with one exception after W14: the DNS helper of
D-59, which never calls the R API and communicates only through a pipe. The
process may still be multithreaded — Security.framework adds two `trustd`
threads after the first HTTPS request.

#### 29.2 Process model

Pools are not shared across a fork (§26.4); finalizers check the PID before
closing a descriptor, so a child's GC cannot close the parent's socket;
Security.framework is unusable in a forked child once the parent has used it.

#### 29.3 Object lifetime across sessions

Configuration is R data and survives serialization; native resources are
external pointers and are rebuilt lazily.

#### 29.4 Thread safety of public objects

Not thread-safe and not required to be; nested use on one thread follows
§27.4.

### 30. Async / Multiplexing

**Status:** Out of scope before 1.0 (D-67).

#### 30.1 Phases

Synchronous, one request at a time. Parallelism is the caller's, via PSOCK or
`future::plan("multisession")` — never a forked plan (§26.4).

#### 30.2 Integrate with `later`, do not invent an event loop

If concurrency is ever built, it registers descriptors with `later` and
returns promises (D-29); synchronous `zu_perform()` MUST NOT become "start
async, then block".

#### 30.3 Not planned

Pipelining; multiplexing over one connection (that is HTTP/2, §60).

---

## Part 6 — R API

### 31. Functional R API Design

**Status:** Built — all 13 §31.16 workflows pass.

Three levels over one request representation: one-shot verbs, reusable
clients, and explicit composition — synthesising Requests' simplicity, httr2's
functional composition, HTTPX's client/transport architecture, Fetch's
response model and reqwest's layering (§31.15).

#### 31.1 Design principles

1. Simple things are simple: `zu_get(url)`, `zu_post(url, json = x)`.
2. Composition is first-class, with execution only at `zu_perform()`.
3. One internal request model; the verbs are syntax.
4. Clients own reusable policy and resources; requests own request state.
5. Response decoding is explicit.
6. Functional values, not R6.

#### 31.2 Level 1: one-shot verbs

`zu_get`, `zu_head`, `zu_post`, `zu_put`, `zu_patch`, `zu_delete` take `url`
first, then `query`, `headers`, one of `body`/`json`/`form`/`file`, the policy
arguments, `path` or `callback`, and `client =`.

#### 31.3 Level 2: reusable clients

`zu_client(base_url, headers, query, timeout, redirects, verify, max_body,
user_agent, check, decode, transport, pool, retry, middleware, hooks, proxy,
tls)`.
The client is always a named `client =` argument (D-19). `base_url` is joined
textually (D-34). One-shot calls use a PID-guarded default client, replaceable
with `zu_set_default_client()` and reported by `zu_info()`.

#### 31.4 Level 3: explicit composition

`zu_request(method, url) |> zu_query() |> zu_headers() |> zu_body_json() |>
zu_req_timeout() |> zu_perform(client = )`.

#### 31.5 Method and URL are request identity

A request's method and URL are fixed at construction; transformers change
everything else.

#### 31.6 Request body ergonomics

`body`, `json`, `form` and `file` are mutually exclusive; semantic bodies set
their content type unless one is set (§28.3). `file =` is a request body;
the response destination is `path =` (D-45).

#### 31.7 Response ergonomics

Accessors are the contract; `$fields` are not. `zu_resp_raw()` is decoded
bytes (D-9). `zu_resp_text()` chooses an encoding by: explicit `encoding`,
then `charset`, then a BOM, then UTF-8; JSON is always UTF-8; invalid bytes
raise `zu_body_decode_error` unless `on_invalid = "substitute"`.
`zu_resp_json()` uses `jsonlite` if installed (D-25).

#### 31.8 Response body lifecycle

Bodies are fully consumed into memory, a file, or a callback before
`zu_perform()` returns. A lazy or streaming response object is not planned.

#### 31.9 Client/request configuration merge rules (D-35)

Headers and query merge (request wins per name; `NA` removes an inherited
header). Scalar policy — `timeout`, `retry`, `redirects`, `verify`, `tls`,
`proxy`, `check`, `max_body` — is replaced by the request value. Three
states: argument absent inherits, `NULL` resets to the package default, a
value overrides.

#### 31.10 Derived clients

`zu_client_update(client, …)` returns a new client and shares the pool
(§26.5).

#### 31.11 Client and request naming

Constructors `zu_client`, `zu_request`; execution `zu_perform`; transformers
`zu_query`, `zu_headers`, `zu_body_*`, `zu_req_*`; responses `zu_resp_*`.
W3 trims the surface from 75 exports to 58 (D-65, §53).

#### 31.12 Transport as an explicit client dependency

`zu_client(transport = )` takes the native, mock or cassette transport. After
W3 the transport-extension contract (`zu_transport_perform`,
`zu_native_transport`) is internal until a second implementation needs it.

#### 31.13 Middleware and hooks (D-20, D-44)

Policy objects are declarative arguments; middleware is a list of
`function(req, next)`. Retry runs inside middleware, so middleware sees one
logical request. Hooks (`before_request`, `after_response`, `before_retry`)
observe and cannot mutate.

#### 31.14 Error-status philosophy (D-33)

Transport failure, error status and decode failure are distinct. `check =
TRUE` by default raises `zu_http_client_error` / `zu_http_server_error`;
`check = FALSE` returns the response for `zu_resp_check()`.

#### 31.15 API design references

httr2, Requests, HTTPX, Fetch, Ky, reqwest — design references, not
dependencies. Edition 1 §31.15 has the links.

#### 31.16 Workflows

The API is judged against 13 workflows, all passing in `test-workflows.R`:
one-line GET; JSON POST; API client with token and base URL; build without
executing; retried idempotent request; streaming download; mocked package
test; per-request timeout override; redirect/error inspection; pool reuse;
`mclapply()`; `saveRDS()` round-trip; text without `charset`.

### 32. Middleware

**Status:** Built — `R/middleware.R`. R-level only; the C core carries no
policy flags.

### 33. Retry Model

**Status:** Built — `R/retry.R`.

`zu_retry(attempts, backoff, base, max_delay, jitter, retry_after,
max_retry_after, attempt_timeout, on)`; `attempts` counts the first try, and
the default policy is `attempts = 1` (D-42).

#### 33.1 When a retry is permitted (D-43)

All three: the failure is retryable (§33.2); the request is replay-safe (an
idempotent method, `zu_req_replay_safe()`, or an `Idempotency-Key` header);
the body is rewindable. Decided once, before the first attempt.

#### 33.2 Retryable conditions

| Condition | Retry |
|---|---|
| DNS, connect, I/O failure before any response byte | yes |
| stale pooled connection on first write | yes, not counted |
| timeout | only if `total` budget remains |
| 408, 429, 500, 502, 503, 504 | yes |
| TLS failure of any kind, including unsupported settings | no |
| other 4xx and 5xx | no |
| reset after a partial response | no |

#### 33.3 Backoff and `Retry-After`

Exponential with full jitter; `Retry-After` honoured in both forms and
clamped to `max_retry_after` (60 s); the budget is checked before sleeping;
sleeps are interruptible.

#### 33.4 Observability

Every retry fires `before_retry` with the attempt, the condition and the
delay.

#### 33.5 Implementation record

Retired: see edition 1 §33.5.

### 34. Error Model

**Status:** Built; W3 adds the `zuhttp_error` root (D-65).

#### 34.1 Condition hierarchy

The one definition is `src/zu_error.c` (`k_class[]`, `class_parent()`); R
reads it through `zu_condition()`. This tree is its documentation.

```text
zuhttp_error  (D-65, W3; inherits error, condition)
└── zu_error
    ├── zu_memory_error, zu_overflow_error
    ├── zu_dns_error, zu_connect_error, zu_timeout_error ($phase, §24.1)
    ├── zu_tls_error
    │   ├── zu_tls_certificate_error
    │   ├── zu_tls_hostname_error
    │   ├── zu_tls_handshake_error
    │   ├── zu_tls_pin_error           the pin was compared and did not match
    │   └── zu_tls_unsupported_error   D-56: the backend cannot honour a setting
    ├── zu_http_parse_error, zu_url_error
    ├── zu_proxy_error
    │   └── zu_proxy_auth_error
    ├── zu_redirect_error
    │   └── zu_too_many_redirects
    ├── zu_body_limit_error, zu_body_decode_error, zu_body_not_replayable
    ├── zu_fork_error, zu_io_error
    ├── zu_http_status_error
    │   ├── zu_http_client_error (4xx)
    │   └── zu_http_server_error (5xx)
    └── zu_cancelled_error
        └── zu_interrupted_error
```

`zuhttp_error` goes *above* `zu_error` so that every existing handler keeps
working and the family convention (`<pkg>_error`) holds.

#### 34.2 Payload

Stable integer `code`; message; redacted URL; `phase`; backend and native
code; `retryable`; request and response where they exist.

#### 34.3 No rlang dependency (D-26)

Base R `structure()` + `stop()`, laid out so `rlang::catch_cnd()` works.

#### 34.4 Messages

Each message states what was attempted, what failed, and the likely fix; the
backend code comes last. §61.9 audits the catalogue at 1.0.

### 35. Observability

**Status:** Built — `src/zu_trace.c`, `R/verbose.R`.

#### 35.1 Timings

`zu_resp_timings()`: `dns`, `connect`, `tls`, `request_write`, `ttfb`,
`response_read`, `total`, `body_bytes_wire`, `body_bytes_decoded`, monotonic.
A phase that did not happen is `NA`, not 0, and `total` is never shorter than
a phase inside it. On macOS after W13, `dns`,
`connect` and `tls` for HTTPS come from Network.framework's establishment
report.

#### 35.2 Connection metadata

`zu_resp_connection()`: `reused_connection`, `remote_ip`, `tls_protocol`,
`tls_cipher` (an IANA name), `trust_backend`, `http_version`, `proxy_used`,
`retries_performed`, `redirect_count` — for the final hop.

#### 35.3 Event trace

`request.start`, `dns.*`, `connect.*`, `tls.*`, `headers.received`,
`body.chunk`, `retry.scheduled`, `redirect.followed`, `request.done`, read
with `zu_resp_trace()` and printed by `zu_verbose()`. Payloads are redacted
before any handler sees them; URLs enter only through `zu_trace_add_url()`
(D-51), and `redirect.followed` carries the resolved target (D-50).

#### 35.4 Cost

Off by default; a NULL check when off. The log is fixed-capacity and
allocation-free except the two URL-bearing events. The `body.chunk` overhead
on a large download is unmeasured (§51, W18).

### 36. Pluggable Transport

**Status:** Built.

A transport is a function of one request returning one response or signalling
a `zu_error`; it implements network semantics only, never redirects, retries
or merging. `zu_response()` takes a raw body (character is UTF-8-encoded).

#### 36.1 The transport contract

Native, mock and cassette today. The contract is internal until a second
external implementation exists (§31.12, D-65).

### 37. Mocking and Record/Replay

**Status:** Built — `R/mock.R`, `R/record.R`; marked experimental by W3.

`zu_stub(response, method, url, regex, headers, body, times)` for canned
responses; `zu_mock_transport()` for full control;
`zu_cassette_transport(dir, name, mode = c("auto", "replay", "record"))` for
record/replay, uncompressed `.rds` under `tempdir()` by default (D-41), keyed
on the redacted request (D-40), with the extended §42.1 list (D-39).

#### 37.1 Implementation record

Retired: see edition 1 §37.1.

### 38. Authentication Scope

**Status:** Accepted scope. Basic, Bearer and arbitrary headers. Client
certificates post-1.0 on demand (D-67). OAuth, cloud signing, NTLM and
Kerberos belong in middleware or other packages.

### 39. Information API

**Status:** Built — `zu_info()`.

`version`, `http`, `tls_backend`, `trust`, `tls_available`,
`revocation_default`, `tls_capabilities` (D-56), `compression`, `ipv6`,
`proxy_env` (redacted, flagging an ignored `HTTP_PROXY`) and `default_client`.
Reported from C, so it describes the loaded build. Printed as a report meant
for pasting into bug reports.

---

## Part 7 — Security

### 40. Resource Limits and Security Defaults

**Status:** Built, with the ratio default pending (D-69).

| Limit | Default |
|---|---|
| `max_header_bytes` | 64 KiB |
| `max_header_count` | 100 |
| `max_header_name` / `max_header_value` | 256 B / 8 KiB |
| `redirects` | 10 (D-68) |
| `max_body` (decoded, every sink) | 16 MiB |
| `max_decompression_ratio` | off → 1000 (D-69) |
| `max_redirect_body` | 64 KiB |
| `max_retry_after` | 60 s |

Plus: checked integer arithmetic, no network-sized stack allocation, no CRLF
injection, strict framing, verification on by default, credentials stripped
across origins, proxy credentials confined to the proxy.

### 41. Memory Management

**Status:** Built — `src/zu_alloc.c`.

All allocations go through `zu_alloc`/`zu_realloc`/`zu_free` with overflow
checks, accounting, and OOM injection for the offline suite (0 leaks at every
injection point on the URI resolve path). No pointer into R memory is kept
across calls.

### 42. Secret Redaction (D-27)

**Status:** Built — `src/zu_redact.c`, called from R so the policy has one
definition.

#### 42.1 What is redacted

Headers `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`,
`X-Api-Key`, `X-Auth-Token` and a configurable list; URL userinfo; query and
form parameters named `access_token`, `api_key`, `apikey`, `signature`, `sig`,
`client_secret`, `password`, `passwd`, `pwd`, `secret`, `token`,
`refresh_token`, `id_token`, `private_key`, `auth_token`, `session_token`
(exact, case-insensitive; extend with `zuhttp.redact_params`). Values render
as `<redacted>`, never a prefix. The redactor does not use the URI parser —
the malformed URL is the one an error is about — and anchors the scheme
match. Known gap: a URL nested inside a query value is not descended into.

#### 42.2 Where it applies

`print()`/`format()` of requests and responses; condition messages and
payloads; trace and hook payloads; cassettes; `zu_resp_url()` (D-52); verbose
output. The one exception is the caller asking for their own header by name.

#### 42.3 Implementation constraint

Redaction happens in the formatting layer; a redacted request stays
executable.

#### 42.4 Testing

`test-redact.R` greps every egress for a canary credential. A new egress
without a canary arm is a defect.

### 43. Fuzzing

**Status:** Partial — ten targets, corpus replay on three OSes in CI; the
24 h soak per target (§61.8) is W17.

Targets: response parser, chunked decoder, headers, URI, redirect, proxy
environment, inflate limits, body path, redaction, and the **engine** — the
whole request path through the D-72 seam, with termination, the `max_body`
bound and per-input allocation balance as oracles (9.1M executions in its
first 10-minute soak, clean). W9 adds the DER walker as the eleventh. Each harness builds against libFuzzer and against a plain replay
driver, so the corpus is a regression suite everywhere, Windows included.
Only curated seeds are committed.

### 44. Static Analysis

**Status:** Partial — warnings-as-errors for project C on three compilers;
rchk and sanitizers over the R glue are W1.

### 45. Security Review Requirements

**Status:** Planned (W19) — before 1.0.

External review of the TLS glue and framing; CRLF injection; redirect
credential stripping; certificate failures; malformed proxy responses;
timeout and cancellation cleanup; decompression bombs; ASan, UBSan and
valgrind; no R API off the main thread (which W14 makes non-trivial);
allocation overflow checks.

### 46. Ongoing Security Policy

**Status:** Planned (W19).

#### 46.1 Required artifacts

`SECURITY.md` with a disclosure address, acknowledgement within 72 h, fix or
mitigation of a remotely triggerable memory-safety issue within 14 days, and
supported versions.

#### 46.2 Dependency watch

Upstream security channels for picohttpparser and uriparser; `tools/update-*` make an update a same-day mechanical change;
`tools/vendor/checksums` (W1) verifies what is vendored.

#### 46.3 The maintainer-count risk

A second maintainer with CRAN rights before 1.0, or the risk stated in the
README (R-6).

---

## Part 8 — Build, Test, Release

### 47. CRAN Build Strategy

**Status:** Partial — builds on all three platforms; CRAN submission is
milestone M2.

#### 47.1 Per-platform dependencies

| Platform | Link |
|---|---|
| Windows | `-lws2_32 -lsecur32 -lcrypt32 -lz` (+ `-lbcrypt` after W9) |
| macOS | `-framework Network -framework Security -framework CoreFoundation -lz` (after W13) |
| Unix | `-lssl -lcrypto -lz` |

#### 47.2 DESCRIPTION requirements

`SystemRequirements: OpenSSL >= 1.1.1 (Linux/Unix only), zlib`.

#### 47.3 configure

POSIX `sh`, pkg-config with a compile-and-link fallback, respects
`PKG_CPPFLAGS`/`PKG_LIBS`, uses R's compiler, writes only inside the package,
and names the missing package per distribution. `dash -n` in CI (W1).

#### 47.4 Windows toolchain: TLS 1.3 structures are missing from Rtools

Rtools' mingw-w64 declares the TLS 1.3 constants but not `SCH_CREDENTIALS` /
`TLS_PARAMETERS`, at any `_WIN32_WINNT` (S1, re-confirmed on Rtools45). D-64
is the only way the local declaration ships.

#### 47.5 CRAN policy constraints

No network in examples or tests by default (network tests need
`ZU_TEST_NETWORK=1`, not merely `NOT_CRAN`); no writes outside `tempdir()`;
no compiled-code output outside R's facilities; the Secure Transport pragma
NOTE removed by W13.

### 48. Vendoring Policy

**Status:** Built; checksums are W1.

Permissive licence, small, narrow, maintained, no hidden runtime, easy
updates. Each vendored library has `VENDOR` (version, commit, licence,
modifications) and a `tools/update-*` script. After W1,
`tools/vendor/{manifest.tsv,checksums.sha256,verify}` follows the family
layout and runs in CI.

### 49. Licensing

**Status:** Built.

#### 49.1 Package license

MIT: `License: MIT + file LICENSE`, the two-line `LICENSE`.

#### 49.2 Third-party attribution

`inst/COPYRIGHTS` per component; full texts installed under `licenses/`,
kept equal to `src/vendor/*/LICENSE` by `tools/check-vendor-licenses` (#52);
`LICENSE.note` summarises. picohttpparser is MIT, uriparser BSD-3-Clause.

#### 49.3 System TLS

OpenSSL, zlib and the platform stacks are linked, not distributed, and are
named in `COPYRIGHTS` for the reader.

### 50. Testing Strategy

**Status:** Partial — see §50.4 and §50.6.

#### 50.1 Test the engine, not just the seam (D-28)

| Level | Substitutes | Exercises | Used for |
|---|---|---|---|
| R transport mock | everything below R | API, merging, middleware | ergonomics; downstream packages |
| `zu_stream` mock | sockets and TLS | parser, framing, pool, redirects, decompression, body path — and, through the D-72 seam, the whole engine | most of zuhttp's own tests (`ctest/`, 1,630 checks) |
| local servers | nothing | the whole stack | integration: webfakes, a raw-bytes server, `openssl s_server`, a logging proxy |

#### 50.2 Unit tests

Every row of §18.1, §19.1, §28.2, §33.2 and §40 is a test; so are §20.2
matching, §24.2 arithmetic, §31.7 charset fallback and §42.4 canaries.

#### 50.3 Parser corpus

Malformed inputs are fixture files shared with the fuzzer as seeds.

#### 50.4 Integration server

**Partial.** `openssl s_server` for the TLS matrix; `httpbin.org` for the rest,
which is the one third-party dependency that can redden CI without a code
change. W4 replaces it with go-httpbin started in CI on all three runners,
reached through `ZU_HTTPBIN_URL`, and adds real slow and stalled endpoints so
timeouts are tested against servers that actually stall.

#### 50.5 TLS integration tests

Against locally generated certificates, on every backend, in CI: trusted,
untrusted issuer, wrong host, expired, not yet valid, `ca_file` replace,
`ca_extra` add, pin match, pin mismatch, and matching-pin-over-untrusted-chain.
Negative rows are mandatory from a backend's first commit (S0 F-3: a build
that accepted every certificate). Rows a backend refuses skip via
`skip_unless_tls_supports()`. The fixture needs a POSIX shell today, so
Windows runs none of it; W8 ports it so the Windows backend is tested by the
same rows.

#### 50.6 Concurrency and lifecycle tests

Built: `mclapply()` with a pooled client (both hazards), `saveRDS()`
round-trip, callback errors, nested requests. Open: interrupt at every phase
with no leaked descriptor under ASan and valgrind (W11), finalizers under GC
and in a forked child (W4).

### 51. Performance Targets

**Status:** Unmeasured except LOC — W18.

#### 51.1 Architectural targets

Low per-request overhead, connection reuse, zero-copy header parsing,
streaming without whole-body copies, bounded allocations, TLS session
resumption (not implemented).

#### 51.2 Benchmarks

1,000 sequential keep-alive GETs over HTTP and HTTPS; 100 fresh-connection
HTTPS requests; 1 MB to memory; 100 MB streamed to a file; a 10 MB gzip
response; the same with a `body.chunk` hook — each against `curl` on each
platform.

#### 51.3 Pass/fail thresholds

| Metric | Target | Abort | Measured |
|---|---|---|---|
| p50 local keep-alive GET vs `curl` | ≤ 1.5× | > 2× | — |
| 100 MB streaming throughput vs `curl` | ≤ 1.2× | > 1.5× | — |
| peak RSS, 100 MB stream | < 16 MB over baseline | any full-body allocation | 0 KiB (2026-09-08) |
| allocations per simple request | < 50 | > 200 | — |
| project-owned C, code lines | ≤ 8,000 | > 12,000 | **6,379** (2026-09-25) |
| total C incl. vendored | ≤ 25,000 | > 40,000 | ~11k code |
| source tarball | ≤ 2 MB | > 5 MB | 261 KB |
| cold compile, one core | ≤ 90 s | > 180 s | — |

Project-owned C is at 80% of its target with W7, W8, W9, W10 and W14 still to
add (estimated +900 lines). R-4 is now a live risk, not a hypothetical one.

### 52. Compatibility Targets

**Status:** Accepted. Windows x86_64 (ARM64 when Rtools allows), macOS arm64
and x86_64, Linux x86_64 and arm64; portable C99; no compiler extensions in
project code, except Apple blocks in the macOS backend, which
Network.framework's C API requires. On macOS, direct HTTPS works on every
version R supports; HTTPS through a proxy needs macOS 14 (D-63).

### 53. API Stability

**Status:** Partial — W3.

Only the R API is stable. Before 0.2.0 the export surface is trimmed from 75
to 58 (D-65) by exactly these 17 removals: the six `zu_client_*` verb wrappers are removed; `zu_transport_perform`,
`zu_native_transport`, `zu_error_codes`, `zu_code_retryable`,
`zu_set_json_backend` and the six redaction helpers other than `zu_redact_url`
become internal; the testing tools (`zu_mock_transport`, `zu_stub`,
`zu_response`, cassettes) stay exported and are marked experimental. After
0.2.0 an export is removed only after a deprecation release. C headers stay
in `src/`.

### 54. Potential Public C API

**Status:** Out of scope before 1.0. If ever, a small `zuh_client` /
`zuh_request` / `zuh_response` API through a registered table, following the
family's `zukomp-r.h` pattern, exposing no vendored type.

### 55. Documentation Requirements

**Status:** Partial — W12.

User: TLS backends and trust per OS, and what each refuses (a shipped
vignette, #8); getting started (#10); testing code that makes requests (#9);
retries, timeouts and cancellation (#11, after W7); differences from `curl`
and §6.1. Every documented limitation appears in user-facing help.
Developer: stream abstraction, parser ownership, TLS backend contract and
capability mask, cancellation model, allocation ownership, porting.

---

## Part 9 — Plan

The plan itself is [roadmap.md](roadmap.md). This part keeps the constraints
and criteria the plan is judged against.

### 56. Design Constraints

**Status:** Accepted.

1. HTTP only. 2. Native TLS; no vendored cryptography (D-63 — the only
future exception is an engine built on `zucrypt`, which would amend this
line). 3. Small core. 4. Bounded
behaviour. 5. R-first cancellation. 6. Every networking layer mockable.
7. System-native trust. 8. Portable C99 with isolated platform shims. 9. No
hidden runtime. 10. Do not become libcurl.

### 57. Initial MVP

**Status:** Shipped as 0.1.0 (2026-09-10), with a single `total` timeout in
place of §24's phase model.

#### 57.1 Not optional in the MVP

Strict framing (§18.1), redaction (§42) and the fork guard (§26.4) — each is a
breaking change or a security fix to retrofit, and all three shipped.

### 58. Phase 2

**Status:** Superseded by the roadmap's milestones M1 and M2.

### 59. Phase 3

**Status:** Unscheduled, "only if justified": native system proxy settings,
Unix-domain sockets, OpenTelemetry, Brotli, zstd (the last two via a `zukomp`
satellite, D-54).

### 60. HTTP/2 Policy

**Status:** Accepted. Not implemented for parity. Only if real R workloads
benefit, parallel HTTP/1.1 is insufficient, a small library exists, and the
size budget holds — and if it changes the project's character, outside
zuhttp.

### 61. Success Criteria

**Status:** 3 of 14 met — the gate for 1.0.

| # | Criterion | Threshold | Now |
|---|---|---|---|
| 1 | Installs on CRAN toolchains | 0 errors, 0 warnings, §52 platforms | GitHub CI green; not submitted |
| 2 | HTTPS on native trust, no CA bundle | three platforms, no CA file in tarball | **met** |
| 3 | REST workloads need no libcurl | 13 §31.16 workflows with `curl` absent | **met** |
| 4 | Ctrl-C cancels stalled requests | ≤ 200 ms every phase, three front-ends | unmeasured (W11); DNS excluded until W14 |
| 5 | Competitive keep-alive latency | ≤ 1.5× `curl` | unmeasured (W18) |
| 6 | Streaming without full-body allocation | < 16 MB peak over baseline | **met** (0 KiB) |
| 7 | Auditable size | ≤ 8,000 project-owned code lines | met today (6,379); at risk (R-4) |
| 8 | Fuzzing clean | 24 h per target, 0 reports | 15 min soaks only (W17) |
| 9 | Actionable errors | catalogue review | W19 |
| 10 | HTTP-focused | §4 review per release | met |
| 11 | No builder needed for GET/POST | 3 new users, 5 minutes | W12 |
| 12 | One coherent request model | workflows 4, 7, 12 | met |
| 13 | No httr2 masking | 0 masking warnings | met, not asserted in CI (W1) |
| 14 | Fork- and session-safe | §50.6 | met |

("3 of 14" counts criteria met *and* asserted in CI: 2, 3, 6. Criteria 7, 10,
12, 13 and 14 are met but not all gated by CI.)

### 62. Open Questions

**Status:** Maintained. Answered questions move to the register.

#### 62.1 Blocking — must be answered before CRAN

| # | Question | Answered by |
|---|---|---|
| ~~1a~~ | ~~Which macOS engine?~~ **Answered: Network.framework** (D-63), measured 2026-09-26. | — |
| 2a | Is a local `SCH_CREDENTIALS` ABI-correct? | W15 (D-64) |

#### 62.2 Important — answer before 1.0

| # | Question |
|---|---|
| 6 | OpenSSL baseline: 1.1.1 or 3.x only? (1.1.1 is end-of-life upstream.) |
| 7 | LibreSSL: supported or best effort? |
| 10 | Does the 100 ms checkpoint cost measurable throughput? (W18) |
| 12 | Answered by D-59, pending W14. |
| 19 | Is TLS session resumption worth its pool-key and security complexity? (W18 measures the handshake share first.) |

#### 62.3 Open — may remain open past 1.0

| # | Question |
|---|---|
| 14 | A stable C API (§54)? |
| 15 | Async in this package at all? — **not before 1.0 (D-67)** |
| 16 | An httr2 backend? |
| 17 | An in-memory cookie store? |

### 63. Recommended First Prototype

**Status:** Complete. S0 (macOS spike, GO), S1 (Windows headers), and the §63.2
vertical slice are recorded in edition 1 §63 and the spike `FINDINGS.md`
files.

#### 63.1 Order of work: spikes before slices

Kept as a rule for new platform work: a spike answers a go/no-go question
before code depends on it, and its exit criteria MUST include "shippable on
the target toolchain" — S0 validated an engine CRAN could not ship.

#### 63.2 Vertical slice

Complete 2026-09-08: `zu_get()` → request builder → URI → TCP → TLS → parser →
memory → raw vector, on all three platforms.

#### 63.3 Build both open options

Complete: D-10 and D-11 were decided by building the decision-independent
parts first.

#### 63.4 Measure, then decide

The measurement half is W18.

### 64. Effort Estimate

**Status:** Replaced by per-work-package estimates in the roadmap. Edition 1
estimated 39–46 person-weeks to 1.0; 0.1.0 took four calendar days of
concentrated work and left the items below it at the bottom of the confidence
scale — platform TLS details, measurement, and review — which is where the
remaining estimate sits.

---

## Appendix A — Rejected Alternatives

**Status:** Accepted. Full arguments in edition 1.

| Alternative | Why not |
|---|---|
| A.1 Gambit Scheme | a second GC, exception model and runtime inside R |
| A.2 CRUNCH | young toolchain, no runtime advantage once picohttpparser is used |
| A.3 llhttp | ~8k vendored lines against 0.8k, once the framing layer was written and tested anyway (D-10) |
| A.4 Mbed TLS, vendored | duplicates platform cryptography; a private copy is rejected on every platform (D-63). A bundled engine, if ever needed on macOS, comes from `zucrypt` |
| A.5 Static OpenSSL on macOS | 4.64 MB of bundled cryptography |
| A.8 Secure Transport, kept as a fallback below macOS 14 | deprecated, TLS 1.2, and its presence alone keeps the `--as-cran` NOTE (D-63) |
| A.6 R connection sinks | `callback` covers them (D-67) |
| A.7 OCSP fetching, soft-fail revocation | §14.5 (D-62) |

---

## Appendix B — Risk Register

**Status:** Maintained. Retired risks R-1, R-2, R-12 and R-13 are in edition 1.
R-14 is unused.

| ID | Risk | L | I | Mitigation | Trigger |
|---|---|---|---|---|---|
| R-15 | Apple removes Secure Transport | Low | High | **retired by W13**, which removes it (D-63) | — |
| R-18 | Proxied HTTPS on macOS 11–13 has no route after W13 | Medium | Low | a clear `zu_proxy_error`; the README says so | a user who cannot upgrade → the `zucrypt` engine (§13.2) |
| R-3 | Rtools lacks `SCH_CREDENTIALS` | Certain | Medium | D-64's ABI job | ABI unprovable → TLS 1.2 on Windows, documented |
| R-4 | Size budget blown | **Medium, rising** | High | measure per PR (W1); W7–W14 sized before starting | > 8,000 owned code lines → cut before adding; > 12,000 → revise §1 publicly |
| R-5 | Security defect in own TLS glue, framing or DER walker | Medium | Very high | fuzzing (§43), sanitizers, review (§45) | verification bypass post-release → external audit before the next release |
| R-6 | Bus factor | High | High | second maintainer, or README statement | none at 1.0 → label 1.0 experimental |
| R-7 | Architecture slower than `curl` | Medium | Medium | W18 early | > 2× on keep-alive p50 → premise fails |
| R-8 | Cancellation leaks | Medium | High | D-21; W11's leak tests | leaks under test → fix before any release |
| R-9 | Fork corruption | Low (guarded) | High | PID guard; `ci-fork-guard.R` | — |
| R-10 | CRAN friction | Medium | Low | W16 | — |
| R-11 | No adopter | Medium | Medium | ship 0.2.0 to real users; ask | no interest by M2 → stop at M2, do not take on §46 |
| R-16 | Untested merges: same-repository PRs get no CI | **Certain** today | High | W1 (D-70) | — |
| R-17 | Helper-thread DNS (D-59) touches R or leaks without bound | Low | High | never calls R; cap of 8 abandoned lookups; W14 tests under TSan | any R API from the thread → revert to D-30 |

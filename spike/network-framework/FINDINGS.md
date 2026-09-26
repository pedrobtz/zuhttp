# D-63 / W13 — can Network.framework be zuhttp's macOS engine?

**Run date:** 2026-09-26 · macOS 15.7.9 (arm64), Xcode SDK, Apple clang
**Artifacts:** [`nw_probe.c`](nw_probe.c), [`connect_proxy.py`](connect_proxy.py), [`Makefile`](Makefile)
**Question:** F-11 ([`../macos-engine/FINDINGS.md`](../macos-engine/FINDINGS.md))
rejected Network.framework on reading its API: it owns the socket, so zuhttp
cannot run TLS over its own CONNECT tunnel. That was never run, and two APIs
it did not consider — native HTTP CONNECT and the TLS verify block — could
remove the objection. The maintainer wants to avoid the `--as-cran` NOTE that
Secure Transport's deprecation brings, and accepts losing some older Macs.

---

## Verdict: GO, with a macOS 14 floor for proxied HTTPS only

| Question | Result |
|---|---|
| Trust decided by our `SecTrustEvaluateWithError` | **yes** — F-13 |
| TLS 1.3 | **yes** — F-14 |
| Driven from a synchronous poll loop | **yes** — F-15 |
| Cancellation latency | **0.4 ms** — F-16 |
| HTTPS through an HTTP CONNECT proxy | **yes, macOS 14+** — F-17 |
| Builds with no warning, so no CRAN NOTE | **yes**, at deployment target 11.0 with `-Werror` — F-18 |
| Fork after use | **child killed (SIGILL)** — the same hazard as today, F-19 |
| `proxy = FALSE` strictly honoured | **not guaranteed** — F-20 |

F-11's objection is answered rather than refuted: Network.framework does own
the socket, but for HTTPS it no longer needs ours. It does the CONNECT itself
and hands the trust decision back to us. What changes is where the §9 seam
sits on macOS: an HTTPS stream is *dialled* by the backend, not *wrapped*
around a socket the engine opened.

---

## F-13 · Trust stays ours

`sec_protocol_options_set_verify_block` hands the peer's `sec_trust_t` to
our block; `sec_trust_copy_ref()` gives the `SecTrustRef`, and we call
`SecTrustSetPolicies` + `SecTrustEvaluateWithError` exactly as the Secure
Transport backend does after `kSSLSessionOptionBreakOnServerAuth`.

The control: the same host with `SecTrustSetAnchorCertificatesOnly(true)`
over an empty anchor set.

```text
get example.com          ready, tls=1.3, verify_block_ran=1   -> 200 OK
anchors-only example.com connect failed: domain 3 code -9808   (errSSLBadCert)
```

So the block is authoritative, not advisory — §13.1's split survives, and
`ca_file`, `ca_extra`, revocation and (with W9's DER walker on the leaf)
pinning carry over from `zu_tls_sectransport.c` unchanged in substance.

## F-14 · TLS 1.3

Negotiated against example.com and www.google.com, reported by
`sec_protocol_metadata_get_negotiated_tls_protocol_version()`. The minimum is
set with `sec_protocol_options_set_min_tls_protocol_version()` (10.15+), so
`min_version = 13` becomes honourable on macOS.

## F-15 · The poll loop still owns the waiting

Every completion — state changes, receives, send completions — runs on the
connection's dispatch queue, copies into a mutex-protected buffer and writes
one byte to a pipe. The main thread `poll()`s that pipe in ≤ 100 ms slices,
which is where zuhttp's `R_CheckUserInterrupt()` checkpoint goes (§25.1). No
completion touches anything that would be the R API.

Threads go from 1 to 4 after the first request (Security.framework's `trustd`
connection alone took Secure Transport from 1 to 3). §29.1's "zuhttp creates
no threads" still holds; the process was already multithreaded.

## F-16 · Cancellation is immediate, DNS included

Connecting to a non-routable address and calling `nw_connection_cancel()`
from the poll loop after 150 ms and after 1,000 ms: the `cancelled` state
arrived **0.4 ms** later both times. Network.framework resolves names itself,
asynchronously, so **on macOS, DNS becomes cancellable with no helper thread**
— D-59's thread is needed on Linux and Windows only.

## F-17 · Native CONNECT works — from macOS 14

`nw_proxy_config_create_http_connect()` added to a per-connection
`nw_privacy_context_t`, set on the parameters. Through
`connect_proxy.py`:

```text
ready in 39.7 ms  tls=1.3  verify_block_ran=1  proxy=127.0.0.1
status line: HTTP/1.1 200 OK
proxy saw: CONNECT example.com:443 HTTP/1.1
```

The proxy's own log is what makes this non-vacuous: the request went through
the tunnel, not around it. Basic proxy credentials have
`nw_proxy_config_set_username_and_password()`, also 14+, and `NO_PROXY` maps
onto `nw_proxy_config_add_excluded_domain()`.

All three are `API_AVAILABLE(macos(14.0))`. Below 14, HTTPS **through a
proxy** has no native route; direct HTTPS and all plain HTTP (which stays on
zuhttp's own sockets) are unaffected. The APIs everything else uses are
10.14–10.15, older than any macOS R supports.

## F-18 · No deprecated API, no NOTE

Built with `-mmacosx-version-min=11.0 -Wall -Wextra -Wpedantic
-Wdeprecated-declarations -Wunguarded-availability -Werror`: clean. The
14.0-only proxy calls sit under `__builtin_available(macOS 14.0, *)`, and the
guard is load-bearing — replacing it with `if (1)` fails the build with two
errors. Nothing here is deprecated, so there is no pragma to suppress
anything, and `--as-cran` has nothing to note.

## F-19 · Fork after use still kills the child

Parent makes one request, forks, child makes one: the child dies with
**SIGILL** (libdispatch refuses to run in a forked child). Secure Transport
plus `SecTrust` died with SIGSEGV (S0 F-5). Same hazard, same mitigation: the
§26.4 PID guard must fire before *any* Network.framework call, not only
before trust evaluation, and `zu_fork_error` stays the answer. PSOCK and
`multisession` remain the supported parallel paths.

## F-20 · `proxy = FALSE` cannot be made strict

`nw_parameters_set_prefer_no_proxy(true)` is documented as a *preference*:
configured system proxies are still used "if the connections cannot
otherwise be completed". zuhttp's contract (§20.1, D-48) is that proxies come
from the environment or the caller, never from system settings, and
`proxy = FALSE` means direct. On a Mac with a system proxy configured, a
direct connection that fails may be retried through it. Not observed here
(no system proxy on this machine); W13 must measure it on a runner with one
configured and either find a strict switch or document the difference.

---

## Not measured, for W13

- Per-phase timings: `nw_connection_access_establishment_report()` (10.15+)
  reports resolution and handshake durations; whether they map onto
  §35.1's `dns` / `connect` / `tls` needs checking.
- Pool liveness: there is no descriptor to `poll()` for the §26.2 probe; the
  state handler plus the idle timeout, with the probe answering "unknown",
  is the likely design.
- F-20 on a machine with a system proxy.
- The probe against the §50.5 fixture (local CA, `ca_extra`, expired, wrong
  host) — the logic is the Secure Transport backend's, but it runs in a
  different place.

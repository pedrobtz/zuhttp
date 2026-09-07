# Stage S0 — macOS TLS spike: findings

**Run date:** 2026-09-07
**Environment:** macOS 26.6.2 (build 25G83), arm64 · Apple clang 21.0.0 · SDK 26.5 · OpenSSL 3.6.3 (Homebrew) · R 4.6.1
**Artifacts:** [`tls_spike.c`](tls_spike.c), [`run.sh`](run.sh), [`fork_trust_test.c`](fork_trust_test.c), [`fork_curl_test.R`](fork_curl_test.R)
**Reproduce:** `make test` (16 assertions), `make forktest`

---

## Verdict: **GO** — D-4 is viable

The design's preferred architecture works, end to end, exactly as §13.1 hoped:

> OpenSSL as the protocol engine + `SecTrustEvaluateWithError` against the system Keychain for trust, driven entirely from a synchronous non-blocking `poll()` loop that we own, with no dispatch queue and no networking thread.

All 16 assertions in `run.sh` pass. **Appendix B R-1 is retired.**

But the spike surfaced four findings that change the design, one of which (F-5) is a new blocking risk that did not previously appear anywhere in the document.

---

## S0 exit criteria

| Criterion | Result |
|---|---|
| Connects to ≥5 real hosts | ✅ example.com, cloudflare, api.github.com, plus 5 badssl endpoints |
| Custom root honoured | ✅ proven via `SecTrustSetAnchorCertificates` (F-6) rather than by modifying the user's Keychain |
| Expired / wrong-host / unknown-issuer distinguishable | ✅ with excellent messages (F-2) |
| Non-blocking socket, caller owns `poll()` | ✅ 3 checkpoints, longest block 12.9 ms at a 100 ms tick |
| Peak thread count 1 | ❌ **1 → 3** (F-5) |

The thread criterion failed. It turns out to matter far more than expected.

---

## F-1 · Secure Transport caps at TLS 1.2 — the fallback is weaker than assumed

`SecureTransport.h` in SDK 26.5 has no `kTLSProtocol13`; the enum stops at `kTLSProtocol12`. Confirmed empirically against a server that offers 1.3:

```
engine=st       OK TLSv1.2 / cipher 0xc02b / trust=SecTrust:yes
engine=openssl  OK TLSv1.3 / TLS_AES_256_GCM_SHA384 / trust=SecTrust:yes
```

Every symbol is marked `__API_DEPRECATED("No longer supported. Use Network.framework.")`; the spike needs `-Wno-deprecated-declarations` to build.

**Consequence.** §13.2's fallback ("accept Secure Transport's deprecation for v1") would ship a **TLS 1.2-only macOS backend** — not merely a deprecated one. That is a materially worse fallback than the design assumed, which raises the stakes on the primary path. Since the primary path works, this is now academic, but the fallback text must be corrected so nobody reaches for it later believing it is equivalent.

## F-2 · Keychain error messages are excellent, and free

```
TRUST REJECTED: “*.badssl.com” certificate is expired
TRUST REJECTED: “*.badssl.com” certificate name does not match input
TRUST REJECTED: “BadSSL Untrusted Root Certificate Authority” certificate is not trusted
```

`CFErrorCopyDescription` on the `CFError` from `SecTrustEvaluateWithError` yields human-readable, cause-naming strings with no work on our part. This directly serves §34.4 and success criterion §61.9 on the macOS path.

Note `SecTrustCopyProperties` — the API for *detailed* failure breakdowns — **is** deprecated (macOS 10.7–12.0). Failure detail must come from the `CFError`, which is what the spike does.

## F-3 · `SSL_VERIFY_NONE` silently bypasses custom verification — a real bug, found

The first working build accepted **every** bad certificate:

```
host=expired.badssl.com   rc=0  OK TLSv1.2 / trust=SecTrust:no   ← handshake succeeded anyway
```

Cause: OpenSSL clients default to `SSL_VERIFY_NONE`. Under it, returning 0 from an `SSL_CTX_set_cert_verify_callback` records the verification failure but **does not abort the handshake**. The fix is one line:

```c
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
```

This is precisely the Appendix B R-5 class — a verification bypass that produces a *working connection* and so passes any test that only checks the happy path. It is invisible without a negative test.

**Action:** the §50.5 certificate matrix is not optional and must run on every platform, in CI, from the first commit of the TLS backend. A "does HTTPS work?" test would have shipped this bug.

## F-4 · Revocation is NOT checked by default — §14.5 is wrong

```
revoked.badssl.com, default policy      → rc=0  trust=SecTrust:yes   ← accepted
revoked.badssl.com, --revocation        → rc=1  TRUST REJECTED
```

`SecPolicyCreateSSL()` alone performs no revocation checking. It must be combined with an explicit `SecPolicyCreateRevocation(kSecRevocationUseAnyAvailableMethod | kSecRevocationRequirePositiveResponse)`.

Design §14.5 currently claims "Schannel and `SecTrustEvaluateWithError` perform revocation checking according to system policy". **That is false as written** and must be corrected.

Enabling it is not free:

| | trust eval | total |
|---|---|---|
| default | 3.9–8.8 ms | 35–76 ms |
| `--revocation` | **61.8 ms** | 102 ms |

~7–15× slower, because `RequirePositiveResponse` forces an OCSP/CRL fetch. Worse, **that fetch is a network request made inside `SecTrustEvaluateWithError`, which we neither own nor can interrupt or deadline.** It is invisible to the §24 timeout model and to the §25 cancellation loop.

**Recommendation:** keep revocation **off** by default (matching the measured platform default), expose it as `zu_tls(revocation = TRUE)`, and document both the latency cost and the fact that it makes an uninterruptible network call. Also document that Linux/OpenSSL, Windows/Schannel and macOS now differ here — the asymmetry §14.5 already flagged is real, just not in the direction stated.

## F-5 · **`SecTrustEvaluateWithError` is not fork-safe — new blocking risk**

The thread count goes 1 → 3 on the first trust evaluation and stays there; it never rises with additional evaluations, and it stays at 1 if trust never runs. The two extra threads are Security.framework's XPC connection to `trustd`.

That connection does not survive `fork()`:

```
A. parent evaluates trust, then forks:
   [parent-before-fork] evaluate -> 0
   [CHILD-after-fork] create -> 0
   [parent] child KILLED by signal 11        ← SIGSEGV

B. parent never evaluates, then forks:
   [CHILD-after-fork] evaluate -> 0
   [CHILD] SURVIVED
```

**It is fork-after-use, not fork-at-all.** A child that touches Security.framework after the parent has done so crashes the process.

For R this is severe, because the pattern is ubiquitous:

```r
zu_get("https://api.example.com/x")             # parent: one HTTPS request
parallel::mclapply(urls, function(u) zu_get(u)) # every child segfaults
```

`future::plan(multicore)` has the same shape. `PSOCK` clusters and `plan(multisession)` are safe, because they `exec` fresh R processes.

**§26.4's mitigation is insufficient.** Dropping inherited *connections* does not help: the problem is not the sockets, it is that the child cannot call the trust API at all.

**Required change.** The PID guard must extend from the pool to the trust evaluator: on a PID mismatch, refuse to perform trust evaluation and raise an actionable R condition instead of letting the process die. Turning a SIGSEGV into

```
Error: zuhttp cannot make HTTPS requests in a forked process on macOS.
  The system trust evaluator (Security.framework) does not survive fork().
  * Use a PSOCK cluster or future::plan("multisession") instead of mclapply()/multicore.
  * See ?zuhttp_fork for details.
```

is the difference between a diagnosable limitation and an unreportable crash.

### How does R's `curl` compare?

R's `curl` on this machine links Security.framework (`ssl_version: LibreSSL/3.3.6 (SecureTransport)`), so the same question applies. Measured:

```
parent https request               ok
mclapply after parent request ->   200 | ERR: Error in the HTTP2 framing layer [example.com]
```

`curl` **does not crash**, but one of two workers fails with a framing error — the inherited-connection corruption that §26.4 predicts, demonstrated independently and against a different implementation.

So: `curl`'s failure mode is a confusing error; ours would be a segfault. **On this axis the native-trust design is currently worse than the incumbent**, and the mitigation above is what closes the gap. This belongs in §6.1 and in the user documentation, not buried in a design note.

(The spike did not determine *why* libcurl survives where a direct `SecTrustEvaluateWithError` call does not. That question is not on the critical path and is left open.)

## F-6 · Custom-anchor semantics are implementable exactly as §14.2 specifies

`SecTrustSetAnchorCertificates` + `SecTrustSetAnchorCertificatesOnly` give both behaviours cleanly, proven against a locally generated CA and a real public host:

| Test | anchors | `AnchorCertificatesOnly` | Result |
|---|---|---|---|
| local CA host, no anchor | — | — | rejected ✅ |
| local CA host, additive | our CA | `false` | accepted ✅ |
| local CA host, replacing | our CA | `true` | accepted ✅ |
| **public host, additive** | our CA | `false` | **accepted** ✅ — system trust still active |
| **public host, replacing** | our CA | `true` | **rejected** ✅ — system trust really is replaced |

The last two rows are the ones that matter: they prove `ca_extra` (additive) and `ca_file` (replacing) are distinguishable and correct on macOS.

```c
SecTrustSetAnchorCertificates(trust, anchors);
SecTrustSetAnchorCertificatesOnly(trust, replace ? true : false);
```

This also validates the §14.3 approach without requiring test machinery that modifies the user's Keychain — a genuine win for CI (§50.5).

## F-7 · Loop ownership confirmed; DNS gap confirmed

```
timing   connect=7.8ms handshake=12.7ms trust=3.9ms total=35.5ms
loop     checkpoints=3  longest_block=12934us  (tick=100ms)
```

The poll loop is ours, blocking is bounded by the tick, and every `wait_fd()` is a viable `R_CheckUserInterrupt()` site — §25.1 is sound on macOS.

The one exception is as documented: `getaddrinfo()` is synchronous and uninterruptible (§8.4, §25.4). The spike does not fix it and confirms it is a real gap, not a theoretical one.

---

## Changes required to the design document

| Finding | Section | Change |
|---|---|---|
| Verdict | D-4, §13.2 | Blocked → **Accepted**; record the measured evidence |
| F-1 | §13.2 | Fallback is TLS 1.2-only, not merely deprecated |
| F-3 | §50.5, §57.1 | Negative certificate tests are mandatory from day one |
| F-4 | §14.5 | **Correct the false claim.** Revocation off by default; cost and uninterruptible fetch documented |
| F-5 | §26.4, §29.2, §6.1 | **New blocking risk.** PID guard extends to the trust evaluator; document the macOS fork limitation |
| F-6 | §14.2, §14.3 | Confirmed implementable; record the exact API calls |
| F-7 | §25.4 | DNS gap confirmed by measurement |

---

## What S0 did not answer

- Which portable engine to use on macOS for CRAN builds. The spike used Homebrew OpenSSL; CRAN macOS binaries would need a static OpenSSL from the recipes toolchain, or another engine. **This is now the top open question on the macOS path** and belongs in §62.1.
- Why libcurl survives fork where direct `SecTrustEvaluateWithError` does not.
- Whether TLS session resumption (§51.1) behaves across the engine/trust split.
- Anything about Windows. That is S1/S3.

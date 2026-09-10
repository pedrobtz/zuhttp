# R-13 — is there a CRAN-viable macOS TLS engine?

**Run date:** 2026-09-08 · macOS 26.6.2 (arm64), Xcode SDK, OpenSSL 3.6.3
**Artifacts:** [`st_probe.c`](st_probe.c), [`sizeprobe.c`](sizeprobe.c)
**Question:** S0 validated the §13.1 engine/trust split using **Homebrew**
OpenSSL, which is not something a CRAN package can rely on. What engine can
actually ship?

---

## Verdict: there is no free option. R-13 is a real trade, now measured.

| | TLS 1.3 | Caller-owned socket (§9) | Bundles crypto | Status |
|---|---|---|---|---|
| **Secure Transport** | ❌ **1.2 max** | ✅ **works today** | no | deprecated |
| **Network.framework** | ✅ | ❌ **owns the socket** | no | breaks §9, §13.1, §20.3 |
| **Static OpenSSL** | ✅ | ✅ (memory BIOs, S7) | ❌ **4.64 MB** | contradicts §2 |

Every row fails one of the project's own constraints. That is the finding.

---

## F-10 · Secure Transport still works, and still caps at TLS 1.2

Not merely "not removed" — a full handshake to a real host over a socket the
caller owns, which is exactly the §9 `zu_stream` model:

```text
Secure Transport WORKS over a caller-owned socket on this macOS.
  negotiated : TLS 1.2 (enum 8)
  cipher     : 0xc02b            (ECDHE-ECDSA-AES128-GCM-SHA256)
  ceiling    : TLS 1.2 -- kTLSProtocol13 does not exist in the SDK
```

`SecureTransport.h` declares `kTLSProtocol1`, `kTLSProtocol11`,
`kTLSProtocol12` and **no** `kTLSProtocol13`, alongside 87 deprecation
markers. This confirms S0's F-1 on current macOS and adds the part F-1 did
not establish: the API is deprecated but fully functional, and
`SSLSetIOFuncs`/`SSLSetConnection` still give TLS over a socket we own.

## F-11 · TLS 1.3 on macOS exists only behind an API that owns the socket

`tls_protocol_version_TLSv13` is declared in `Security.framework`'s
`SecProtocolTypes.h`, and it is reachable only through `sec_protocol_options`,
i.e. **Network.framework**. `nw_connection` requires
`nw_connection_set_queue` (a dispatch queue, so async and at least one extra
thread) and is created from an *endpoint*: there is no public API to adopt an
existing file descriptor.

Three consequences, in increasing severity:

1. it breaks §9's stream abstraction, which the whole engine is built on;
2. it breaks §13.1's engine/trust split, because it does both;
3. **it cannot do §20.3 proxy CONNECT at all** — tunnelled HTTPS means running
   TLS over a socket we already established, which is the one thing
   `nw_connection` will not do.

(3) is architectural, not an inconvenience. Network.framework is out.

## F-12 · Static OpenSSL costs 4.64 MB, for zuhttp's actual usage

Not the `openssl` package's full surface — a probe using exactly the calls
`zu_tls_openssl.c` makes:

```text
dynamic link :   0.03 MB
STATIC link  :   4.94 MB
stripped     :   4.64 MB     <- what would ship
```

For reference the CRAN `openssl` package's binary is 5.3 MB and is statically
linked the same way (verified: OpenSSL symbols defined in the `.so`, none
undefined). So static OpenSSL **is** CRAN-viable — it is what the most
depended-upon crypto package in R already does. The cost is not viability, it
is that 4.64 MB of bundled cryptography is precisely what DESCRIPTION says
this package does not do:

> uses the operating system's own TLS implementation and certificate trust
> store **rather than a bundled cryptography library** or certificate bundle

and what §2 lists as advantage 1, "smaller native code and dependency
surface".

---

## What this does and does not change

**The trust half of §13.1 is unaffected and still works.** `SecTrust` against
the system Keychain is available in every option, and it is the half that
delivers the operationally valuable behaviour: enterprise roots, MITM
inspection proxies, OS-managed certificate updates. S0 proved it; nothing here
disturbs it.

**Only the engine half is in question**, and only on macOS. Linux links the
system OpenSSL dynamically (no bundling). Windows will use Schannel (no
bundling, and §13.4 now shows it is mandatory rather than preferred). macOS is
the sole platform where the premise and the protocol version conflict.

## The decision

This is a product decision with a measured trade, not a technical unknown:

- **Static OpenSSL engine + SecTrust trust.** TLS 1.3, keeps §9, §13.1 and
  §20.3 intact, ships today. Costs 4.64 MB on macOS and requires DESCRIPTION
  and §2 to stop claiming no bundled cryptography library.
- **Secure Transport engine + SecTrust trust.** True to the premise, no
  bundle, works today over our own socket. Costs TLS 1.3 on macOS and builds
  on an API with 87 deprecation markers that Apple may remove.

There is no third option that satisfies both. R-13 should be recorded as
answered — the engine question has an answer set — and D-4 amended to say
which one, and at what stated cost.

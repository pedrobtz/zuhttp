# Stage S1 — Rtools Schannel header probe: findings

**Run date:** 2026-09-07 (GitHub Actions, `windows-latest`)
**Toolchain:** mingw-w64 11.0 via Rtools, R release, compiler taken from `R CMD config CC`
**Re-confirmed:** 2026-09-08 on **Rtools45 / GCC 14.3.0** — still MISSING, at the
default `_WIN32_WINNT=0x0601` *and* at `0x0A00`. This is not an artifact of an
old mingw-w64; the declarations are absent in the current toolchain too, so the
S8 decision to ship TLS 1.2 stands rather than being something a toolchain
bump would resolve.
**Artifacts:** [`probe.c`](probe.c), [`probe_struct.c`](probe_struct.c), workflow `.github/workflows/tls-spike.yaml`
**Reproduce:** push to `develop`, or `gh workflow run tls-spike.yaml`

---

## Verdict: **Appendix B R-3 is CONFIRMED**

`SCH_CREDENTIALS` and `TLS_PARAMETERS` are **not declared** in the `schannel.h` shipped with Rtools' mingw-w64 11.0, at any Windows target version. `zuhttp` must declare them itself, or ship Windows TLS 1.2-only for v1.

```
probe_struct.c:23:8: error: unknown type name 'SCH_CREDENTIALS'; did you mean 'PCRYPT_CREDENTIALS'?
probe_struct.c:24:8: error: unknown type name 'TLS_PARAMETERS'; did you mean 'VIDEOPARAMETERS'?
```

---

## F-8 · It is not a version gate — the header is incomplete

The first run reported `_WIN32_WINNT: 0x0601` (Windows 7), which made a version gate the obvious explanation: mingw-w64 hides many Win10 declarations behind `_WIN32_WINNT >= 0x0A00`, so "missing" would have meant "not requested", and the fix would have been a compile flag.

**That hypothesis was tested and is wrong.** Probe C recompiled with `-D_WIN32_WINNT=0x0A00 -DNTDDI_VERSION=0x0A000000` and the typedefs are still absent.

The distinguishing evidence is the *split* result:

| Symbol | Kind | Present at default target? |
|---|---|---|
| `SCH_CREDENTIALS_VERSION` | macro | **yes** |
| `SCH_USE_STRONG_CRYPTO` | macro | **yes** |
| `SP_PROT_TLS1_3_CLIENT` | macro | **yes** |
| `SCH_CRED_MAX_SUPPORTED_PARAMETERS` | macro | no |
| `TLS_PARAMETERS_DISABLE_TLS_1_3` | macro | no |
| `SCH_CREDENTIALS` | **typedef** | **no** |
| `TLS_PARAMETERS` | **typedef** | **no** |

A version gate would hide the macros and the typedefs together. Having the constants but not the structures means mingw-w64 11.0's `schannel.h` was partially updated for TLS 1.3: the manifest constants landed, the structure definitions did not.

**This is good news for the remediation.** Because the constants already exist, `zuhttp` needs to declare only the two structures — not a constant table it would have to keep in sync with the SDK. That is a bounded, low-risk piece of work.

## F-9 · Everything else Schannel needs is already present

The TLS 1.2 path and the chain-validation machinery are complete, so only TLS 1.3 is affected:

```
TLS 1.2 fallback path:
  SCHANNEL_CRED_VERSION              present
  SP_PROT_TLS1_2_CLIENT              present
  UNISP_NAME_A                       present

Chain validation (design 13.4, 14.3):
  CERT_CHAIN_POLICY_SSL              present
  CERT_STORE_PROV_MEMORY             present     <- additive custom CA is implementable

Link check:
  sizeof(SCHANNEL_CRED)              80 bytes
  sizeof(SecBuffer)                  16 bytes
  sizeof(SecBufferDesc)              16 bytes
  InitSecurityInterfaceA()           linked, non-NULL
  CertOpenStore(MEMORY)              ok
```

`InitSecurityInterfaceA()` returning non-NULL and `CertOpenStore` succeeding confirm the SSPI and CryptoAPI entry points genuinely **link and run** under Rtools, not merely parse. So the design's Windows plan (§13.4, §14.3) is sound apart from the TLS 1.3 structures.

---

## Options for §47.4

1. **Declare the two structures locally, guarded by a feature test.** Preferred. Roughly 30 lines. The constants already exist, so only `SCH_CREDENTIALS` and `TLS_PARAMETERS` need declaring, matching the documented Microsoft layout. Must be guarded so it compiles away if a future Rtools ships them, and must be ABI-verified against a real Windows 10+ target before being trusted.
2. **Ship Windows TLS 1.2-only for v1.** Safe and cheap; leaves Windows behind the other platforms on protocol version.
3. **Require a newer mingw-w64 than Rtools ships.** Not viable — CRAN builds with Rtools.

Option 1, with option 2 as the fallback if the ABI cannot be verified confidently.

**Not yet done:** no local declaration has been written or ABI-checked. Until that exists, R-3 remains open in practice, and the Windows TLS 1.3 estimate in §64 should carry the extra work.

---

## Note on method

Probing with `R CMD config CC` rather than the runner's default `gcc` was load-bearing: the question is about the toolchain *R uses to build packages*, and the runner has other compilers on `PATH` that would have given an answer about the wrong toolchain.

Two probes were needed because `SCH_CREDENTIALS` is a typedef, and `#ifdef` cannot detect a typedef. `probe.c` reports macros and always compiles; `probe_struct.c` is designed to fail compilation when the structures are absent, which is the only reliable detection.

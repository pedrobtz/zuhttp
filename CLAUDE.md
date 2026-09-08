# zuhttp

A minimal HTTP/1.1 client for R that uses **each platform's own TLS stack and
trust store** — Schannel on Windows, Secure Transport + SecTrust on macOS,
system OpenSSL elsewhere — rather than bundling cryptography or a CA bundle.
Zero hard R dependencies.

## The two documents that govern this repo

Both live in [`.agents/`](.agents/) and are excluded from the R package build:

| File | What it is | When to read it |
|---|---|---|
| [`.agents/zuhttp-design.md`](.agents/zuhttp-design.md) | The design. ~65 numbered sections, a Decision Register (D-1…D-35), and a risk register (R-1…R-15). | Before changing behaviour. Cite the section, e.g. §31.9. |
| [`.agents/roadmap.md`](.agents/roadmap.md) | Stages S0–S21, each with exit criteria and current status. | Before starting work, to see what stage owns it. |

**Read the relevant section before implementing.** Nearly every non-obvious
choice in this codebase is already decided and justified there; the design is
the specification, not a summary written after the fact. When work resolves a
question the design left open, write the decision back into it — a new `D-nn`
row plus the prose — in the same commit as the code.

## Commands

```sh
# C core — no R, no network, no TLS. 1240 checks against a mock stream.
make -C ctest strict          # warnings-as-errors; the one to run by default
make -C ctest asan            # ASan + UBSan
make -C ctest engine-st       # live engine over macOS Secure Transport (network)
make -C ctest engine          # same, over OpenSSL
make -C ctest tls             # OpenSSL backend only (network)

# Fuzzing — 8 targets, each buildable two ways
make -C fuzz replay-run       # corpus replay, needs no clang; a regression suite
make -C fuzz replay-asan      # the same corpus under ASan + UBSan
make -C fuzz fuzz-run         # libFuzzer, needs clang

# R
R CMD INSTALL .
Rscript -e 'testthat::test_local()'                     # offline
ZU_TEST_NETWORK=1 Rscript -e 'testthat::test_local()'   # + the network suite
Rscript -e 'roxygen2::roxygenise()'                     # after touching roxygen blocks

# What CI actually runs for the R suite — reproduce THIS before claiming green,
# because it differs from R CMD check in ways that have bitten before.
Rscript -e 'library(testthat); library(zuhttp);
  test_dir("tests/testthat", reporter="summary", stop_on_failure=TRUE)'
```

Network tests are gated on `ZU_TEST_NETWORK=1`, not on `NOT_CRAN` — `rcmdcheck`
sets `NOT_CRAN`, so gating on it alone would make every check depend on
example.com and badssl.com.

## Layout

```
src/            the C core; only init.c includes R headers
  zu_stream.h   the vtable that decouples the HTTP engine from the network
  zu_engine.c   the composed request path: URI → TCP → TLS → framing → body
  zu_tls_*.c    one file per backend, selected by ./configure
  vendor/       picohttpparser (D-10) and a subset of uriparser (D-11)
R/              the public API; see .agents/zuhttp-design.md §31
ctest/          C tests. zu_ctest is offline; the engine/tls binaries are not.
fuzz/           libFuzzer harnesses + a portable replay driver, and the corpus
tools/          update-uriparser, update-picohttpparser, check-feature-macros
.github/        4 workflows: R-CMD-check, c-core, fuzz, tls-spike
```

`configure` / `configure.win` pick the TLS backend and substitute
`@SSL_CFLAGS@` / `@SSL_LIBS@` / `@TLS_OBJ@` into `src/Makevars{,.win}`.

## Conventions this project actually enforces

- **One definition.** The §34.1 condition class chain and the §42 redaction
  policy live in C and are called from R, so neither can drift. Do not add an R
  table that mirrors a C enum.
- **A stage is done when its exit criteria pass in CI**, not when the code
  works locally. A criterion that cannot be met yet stays unticked and says
  why; a test for unimplemented behaviour uses `skip()` with the owning stage
  named, so a gap looks like a gap in the test output rather than like
  coverage.
- **Verify non-vacuously.** Several bugs here survived because a test passed
  for the wrong reason: `suite_time` asserted the clock was *monotonic*, which
  a constant satisfies, while `zu_now_ms()` returned 0 on Linux for six
  commits. When a test guards a mechanism, break the mechanism once and confirm
  the test fails.
- **The C core builds without R headers.** That is what makes the fuzzing and
  the mock-stream suites possible; keep it true.
- **Every R check in CI runs from a file, never `Rscript -e` with a multi-line
  argument** — that form dies on Windows before executing anything, and cost
  five debugging rounds in S8. Diagnostic steps must not carry
  `continue-on-error`, which turns a failing step into a green tick.
- **Credentials never reach an egress.** Redaction happens in the formatting
  layer, so a redacted request stays executable (§42.3). The canary tests in
  `test-redact.R` are the guard.
- Comments explain *why*, and cite the design section. The codebase assumes a
  reader who wants the reasoning, not a narration of the code.

## Current state

S0–S12 and S15 are complete or explicitly partial. S11 (the R API surface) and
S16 (the connection pool) both landed 2026-09-08; S16 closed R-12, so forked
HTTPS on macOS now raises `zu_fork_error` rather than killing the worker. The
roadmap's status markers and per-stage exit criteria are authoritative — check
them rather than inferring status from the code, and note that its mermaid
graph is stale for S7 and S9.

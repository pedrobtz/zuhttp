# zuhttp

A minimal HTTP/1.1 client for R that uses **each platform’s own TLS
stack and trust store** — Schannel on Windows, Secure Transport +
SecTrust on macOS, system OpenSSL elsewhere — rather than bundling
cryptography or a CA bundle. Zero hard R dependencies.

## The two documents that govern this repo

Both live in [`.agents/`](https://pedrobtz.github.io/zuhttp/.agents/)
and are excluded from the R package build:

| File | What it is | When to read it |
|----|----|----|
| [`.agents/zuhttp-design.md`](https://pedrobtz.github.io/zuhttp/.agents/zuhttp-design.md) | The design. ~65 numbered sections, a Decision Register (D-1…D-56), and a risk register (R-1…R-15; R-14 is unused). | Before changing behaviour. Cite the section, e.g. §31.9. |
| [`.agents/roadmap.md`](https://pedrobtz.github.io/zuhttp/.agents/roadmap.md) | Stages S0–S21 with exit criteria, and six sections no stage owned (U1–U6). Each carries a `**Status:**` line; status never goes in a heading, because issues link the anchors. | Before starting work, to see what stage owns it. |

**Read the relevant section before implementing.** Nearly every
non-obvious choice in this codebase is already decided and justified
there; the design is the specification, not a summary written after the
fact. When work resolves a question the design left open, write the
decision back into it — a new `D-nn` row plus the prose — in the same
commit as the code.

## Commands

``` sh
# C core — no R, no network, no TLS. 1630 checks against mock streams,
# including the whole engine through the dial seam (test_engine_mock.c).
make -C ctest strict          # warnings-as-errors; the one to run by default
make -C ctest asan            # ASan + UBSan
make -C ctest engine-st       # live engine over macOS Secure Transport (network)
make -C ctest engine          # same, over OpenSSL
make -C ctest tls             # OpenSSL backend only (network)

# Fuzzing — 10 targets (engine is the whole request path), each built two ways
make -C fuzz replay-run       # corpus replay, needs no clang; a regression suite
make -C fuzz replay-asan      # the same corpus under ASan + UBSan
make -C fuzz fuzz-run         # libFuzzer, needs clang

# R
R CMD INSTALL .
Rscript -e 'testthat::test_local()'                     # offline
ZU_TEST_NETWORK=1 Rscript -e 'testthat::test_local()'   # + the network suite
Rscript -e 'roxygen2::roxygenise()'                     # after touching roxygen blocks
./tools/check-vendor-licenses                           # after a re-vendor

# What CI actually runs for the R suite — reproduce THIS before claiming green,
# because it differs from R CMD check in ways that have bitten before.
Rscript tools/ci-run-tests.R
```

**A pull request from a branch of this repository gets no CI.** Every
job skips on same-repository `pull_request` events and `push` fires only
on `main`/`develop`. Before merging, dispatch the workflows on the
branch:

``` sh
for w in R-CMD-check c-core fuzz tls-spike; do gh workflow run $w.yaml --ref <branch>; done
```

Network tests are gated on `ZU_TEST_NETWORK=1`, not on `NOT_CRAN` —
`rcmdcheck` sets `NOT_CRAN`, so gating on it alone would make every
check depend on example.com and badssl.com.

## Layout

    src/            the C core; only init.c includes R headers
      zu_stream.h   the vtable that decouples the HTTP engine from the network
      zu_engine.c   the composed request path: URI → TCP → TLS → framing → body
      zu_tls_*.c    one file per backend, selected by ./configure
      vendor/       picohttpparser (D-10) and a subset of uriparser (D-11)
    R/              the public API; see .agents/zuhttp-design.md §31
    ctest/          C tests. zu_ctest is offline; the engine/tls binaries are not.
    fuzz/           libFuzzer harnesses + a portable replay driver, and the corpus
    tools/          update-uriparser, update-picohttpparser, check-feature-macros,
                    check-objects-sync, check-vendor-licenses, ci-fork-guard.R,
                    ci-run-tests.R
    .github/        6 workflows: R-CMD-check, c-core, fuzz, tls-spike (the network
                    and per-backend jobs, despite the name), coverage, pkgdown

`configure` / `configure.win` pick the TLS backend and substitute
`@SSL_CFLAGS@` / `@SSL_LIBS@` / `@TLS_OBJ@` into `src/Makevars{,.win}`.

## Conventions this project actually enforces

- **One definition.** The §34.1 condition class chain and the §42
  redaction policy live in C and are called from R, so neither can
  drift. Do not add an R table that mirrors a C enum.
- **A stage is done when its exit criteria pass in CI**, not when the
  code works locally. A criterion that cannot be met yet stays unticked
  and says why; a test for unimplemented behaviour uses `skip()` with
  the owning stage named, so a gap looks like a gap in the test output
  rather than like coverage.
- **Verify non-vacuously.** Several bugs here survived because a test
  passed for the wrong reason: `suite_time` asserted the clock was
  *monotonic*, which a constant satisfies, while `zu_now_ms()` returned
  0 on Linux for six commits. When a test guards a mechanism, break the
  mechanism once and confirm the test fails.
- **The C core builds without R headers.** That is what makes the
  fuzzing and the mock-stream suites possible; keep it true.
- **Every R check in CI runs from a file, never `Rscript -e` with a
  multi-line argument** — that form dies on Windows before executing
  anything, and cost five debugging rounds in S8. Diagnostic steps must
  not carry `continue-on-error`, which turns a failing step into a green
  tick.
- **Refuse, never downgrade (D-56).** A
  [`zu_tls()`](https://pedrobtz.github.io/zuhttp/reference/zu_tls.md)
  setting the backend cannot honour raises `zu_tls_unsupported_error`
  before any I/O. What a backend supports is its `zu_tls_backend_caps()`
  mask in C; tests read it through `zu_info()$tls_capabilities` /
  `skip_unless_tls_supports()`, never from a table of backend names.
- **Credentials never reach an egress.** Redaction happens in the
  formatting layer, so a redacted request stays executable (§42.3). The
  canary tests in `test-redact.R` are the guard.
- Comments explain *why*, and cite the design section. The codebase
  assumes a reader who wants the reasoning, not a narration of the code.

## The `zu*` family

`zukomp`, `zucrypt`, `zuxml` and `zuxlsx` are siblings, and three of
them name `zuhttp` as a consumer. In 0.x it consumes none of them:
compression is system zlib (D-7), pin digests come from each TLS
backend, and `zuxml` could at most be a `Suggests`. Design §5.1 (D-54)
records this and carries the family table shared by all five
repositories. One practical consequence: the internal C prefix
`zu_`/`ZU_` is `zukomp`’s public ABI namespace and already collides with
`zukomp.h` (`ZU_OK`, `zu_buffer`), so do not add new `zu_` C names that
a `zukomp` header could also declare (#15).

## Current state

v0.1.0 shipped on 2026-09-10 as a GitHub release, and no `v0.1.0` tag
exists yet. Complete: S0–S5, S10–S14, S16, S17, U1, U4–U6; all 13 §31.16
workflows pass. Partial: S6 (no phase timeouts, \#13), S7, S8, S9, S15,
S18, S20. Not started: S19 (deferred with the CRAN submission), S21, U2
except A1, and U3. S16 closed R-12, so forked HTTPS on macOS now raises
`zu_fork_error` rather than killing the worker. The roadmap’s per-stage
exit criteria are authoritative — check them rather than inferring
status from the code — and the two issues that gated the tag (#12, \#14)
closed with the review’s merge on 2026-09-25 — see its “Amends before
merge” section.

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
| [`.agents/zuhttp-design.md`](https://pedrobtz.github.io/zuhttp/.agents/zuhttp-design.md) | The design, edition 2: a normative specification in 64 numbered sections, each with a status line; a Decision Register (D-1…D-70); a risk register. | Before changing behaviour. Cite the section, e.g. §31.9. |
| [`.agents/roadmap.md`](https://pedrobtz.github.io/zuhttp/.agents/roadmap.md) | The plan, edition 2: milestones M0–M3 (0.1.0 tag → 0.2.0 → CRAN 0.3.0 → 1.0), work packages W1–W19 with exit criteria, and an append-only findings log. | Before starting work, to see which work package owns it. |
| [`.agents/history/`](https://pedrobtz.github.io/zuhttp/.agents/history/) | Edition 1 of both, verbatim: every spike measurement and how each stage landed. | When you need the *why* behind a decision, or a measurement. |

**Read the relevant section before implementing.** Nearly every
non-obvious choice in this codebase is already decided and justified
there; the design is the specification, not a summary written after the
fact. When work resolves a question the design left open, write the
decision back into it — a new `D-nn` row plus the prose — in the same
commit as the code.

Edition 2 is a specification, not a log: write what the code *is*, in
the present tense, and put dated findings in the roadmap’s findings log.
**Never renumber or delete a design section** — the code cites them
~1,100 times; retire a section by saying so in its status line.

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

v0.1.0 is built and awaiting its tag (roadmap M0); the review and its
amends merged on 2026-09-25 (#20). Next is **M1 → v0.2.0**, and its
first work package is **W1: CI on pull requests** — until it lands, a
pull request from a branch of this repository runs no CI, so dispatch
the workflows by hand as shown under Commands. Then W2 (the `zuh_` C
prefix rename) before any other C work, because it touches every file.
The roadmap’s work-package exit criteria are authoritative — check them
rather than inferring status from the code. Forked HTTPS on macOS raises
`zu_fork_error` by design (D-32); it is not a bug to fix.

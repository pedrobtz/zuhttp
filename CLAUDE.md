# zuhttp

A minimal HTTP/1.1 and HTTP/2 client for R that uses **each platform's own TLS stack and
trust store** — Schannel on Windows, Network.framework + SecTrust on macOS,
system OpenSSL elsewhere — rather than bundling cryptography or a CA bundle.
One hard R dependency, the sibling `zujson` (D-88); `zuxml` and `zuhtml` are
Suggests.

## Shared conventions

The portfolio's shared rules are synced into `.claude/shared/` from
`pedrobtz/packages:claude/shared/`. Never edit them here. Where this file and
a shared file disagree, this file wins for this package.

@.claude/shared/workflow.md
@.claude/shared/r-package.md
@.claude/shared/ci.md
@.claude/shared/native-code.md
@.claude/shared/correctness.md
@.claude/shared/assurance.md

## The two documents that govern this repo

Both live in [`.agents/`](.agents/) and are excluded from the R package build:

| File | What it is | When to read it |
|---|---|---|
| [`.agents/zuhttp-design.md`](.agents/zuhttp-design.md) | The design, edition 2: a normative specification in 65 numbered sections, each with a status line; a Decision Register (D-1…D-97); a risk register. | Before changing behaviour. Cite the section, e.g. §31.9. |
| [`.agents/roadmap.md`](.agents/roadmap.md) | The plan, edition 2: milestones M0–M3 (0.1.0 on CRAN with HTTP/2 → 0.2.0 → 0.3.0 → 1.0; M4 folded into M0, D-96), work packages W1–W22 with exit criteria, and an append-only findings log. | Before starting work, to see which work package owns it. |
| [`.agents/assurance.md`](.agents/assurance.md) | What checks each boundary, long-lived object and limit, against the portfolio's assurance standard; every gap names an issue. CI's `assurance` job holds it to the standard. | Before adding a boundary, object or limit: add its row and its test. |
| [`.agents/history/`](.agents/history/) | Edition 1 of both, verbatim: every spike measurement and how each stage landed. | When you need the *why* behind a decision, or a measurement. |

**Read the relevant section before implementing.** Nearly every non-obvious
choice in this codebase is already decided and justified there; the design is
the specification, not a summary written after the fact. When work resolves a
question the design left open, write the decision back into it — a new `D-nn`
row plus the prose — in the same commit as the code.

Edition 2 is a specification, not a log: write what the code *is*, in the
present tense, and put dated findings in the roadmap's findings log. **Never
renumber or delete a design section** — the code cites them ~1,100 times;
retire a section by saying so in its status line.

## Commands

```sh
# C core — no R, no network, no TLS. 2269 checks against mock streams,
# including the whole engine through the dial seam (test_engine_mock.c) and
# over HTTP/2 against an in-process nghttp2 server (test_h2.c).
make -C ctest strict          # warnings-as-errors; the one to run by default
make -C ctest asan            # ASan + UBSan
make -C ctest engine-nw       # live engine over macOS Network.framework (network)
make -C ctest engine          # same, over OpenSSL
make -C ctest tls             # OpenSSL backend only (network)
make -C ctest tls-eof         # OpenSSL vs a loopback TLS server that closes badly
                              #   (needs python3 and the openssl CLI; D-86)
make -C ctest tls-eof-asan    # the same under ASan: a renegotiating server (#215)
make -C ctest tls-fork-nw     # tls-eof's fork case on Network.framework (#249);
                              #   tls-fork-nw-asan under ASan + UBSan
make -C ctest engine-asan      # engine-nw-asan, tls-asan: the live binaries under
                              #   ASan + UBSan (#231); CI runs all four

# Fuzzing — 13 targets (engine and h2 are the whole request path; pull is the
# streamed-body API as a state machine; pool is the connection pool against a
# model), each built two ways
make -C fuzz replay-run       # corpus replay, needs no clang; a regression suite
make -C fuzz replay-asan      # the same corpus under ASan + UBSan
make -C fuzz fuzz-run         # libFuzzer, needs clang
tools/coverage/fuzz-lcov.sh fuzz.lcov   # fuzz reach: what the corpus runs (#230)
tools/coverage/fuzz-gaps.sh fuzz.lcov ctest.lcov   # what it misses: unentered functions,
                              #   one-sided conditions, lines only ctest reaches
make -C fuzz mutate-asan      # 33,000 deterministic mutants of the seeds under ASan + UBSan;
                              #   MUT_SEED=1 for a fresh set. A soak, not a bug-finder: see below
gh workflow run mutation.yaml # Mull over src/zuh_*.c against zuh_ctest (#238): the
                              #   mutants no check kills, listed in the job summary

# R
R CMD INSTALL --preclean .    # --preclean: an in-tree build reuses stale src/*.o,
                              #   which once linked in pre-visibility vendored objects
Rscript -e 'testthat::test_local()'                     # offline
ZU_TEST_NETWORK=1 Rscript -e 'testthat::test_local()'   # + the network suite
Rscript -e 'roxygen2::roxygenise()'                     # after touching roxygen blocks
air format R tests && air format --check .              # before every push that touches R;
                                                        #   the conventions job fails otherwise
./tools/check-vendor-licenses                           # after a re-vendor
tools/make-tls-fixture                                  # the §50.5 certificates; 397-day leaves,
                                                        #   test-certs.R says when (fixtures/README.md)

# HTTP/2 live tests (test-http2.R): a local server whose HTTP/2 is not nghttp2's
tools/h2-test-cert.sh /tmp/h2 && python3 tools/h2-test-server.py 18080 18443 /tmp/h2/cert.pem /tmp/h2/key.pem &
ZU_H2_TEST_SERVER=http://127.0.0.1:18080 ZU_H2_TEST_TLS=https://localhost:18443 \
  ZU_H2_TEST_CA=/tmp/h2/ca.pem Rscript -e 'testthat::test_local(filter = "http2")'

# The R glue (init.c) under valgrind: Linux only; CI runs it on every PR (#164)
tools/ci-valgrind-glue.sh

# The R glue with each allocation failed in turn, R's included (#237): weekly
# in alloc-failure.yaml; tools/alloc/exercise.R is the workload
Rscript tools/alloc/exercise.R

# What CI actually runs for the R suite — reproduce THIS before claiming green,
# because it differs from R CMD check in ways that have bitten before.
Rscript tools/ci-run-tests.R
```

**Every pull request runs CI** (W1). R-CMD-check, native-checks and the
r-actions jobs run a quick profile on a pull request and the full one on
`main`. Work-package pull requests merge on the quick profile; the `full-ci`
label, which runs the full profile on a pull request, goes only on the pull
request that closes a milestone (the maintainer's rule, 2026-10-29). One
memory check runs on every pull request regardless: the R glue under
valgrind (2026-11-05, #164). Every
merge still runs the full profile on `main`: read it before opening the next
pull request, and fix what it finds there.

```sh
tools/vendor/verify            # src/vendor/ is byte-for-byte what was recorded
tools/vendor/record            # after tools/update-*, never after a hand edit
tools/update-nghttp2 1.71.0    # re-vendor nghttp2 with the §48 patches
tools/check-code-lines         # project-owned C against the §51.3 budget
```

Network tests are gated on `ZU_TEST_NETWORK=1`, not on `NOT_CRAN` — `rcmdcheck`
sets `NOT_CRAN`, so gating on it alone would make every check depend on
example.com and badssl.com.

## Layout

```
src/            the C core; only init.c includes R headers
  zuh_stream.h   the vtable that decouples the HTTP engine from the network
  zuh_engine.c   the composed request path: URI → TCP → TLS → framing → body
  zuh_h2.c       HTTP/2: an nghttp2 session behind the stream contract (§65)
  zu_tls_*.c    one file per backend, selected by ./configure
  vendor/       picohttpparser (D-10), a subset of uriparser (D-11), nghttp2 lib/ (D-89)
R/              the public API; see .agents/zuhttp-design.md §31
ctest/          C tests. zuh_ctest is offline; the engine/tls binaries are not.
                zuh_mock_stream.{c,h} live here: test-only, not in the package.
fuzz/           libFuzzer harnesses + a portable replay driver, and the corpus
tools/          update-uriparser, update-picohttpparser, update-nghttp2,
                h2-test-server.py, h2-test-cert.sh, check-feature-macros,
                check-objects-sync, check-vendor-licenses, check-code-lines,
                ci-fork-guard.R, ci-masking.R, ci-run-tests.R, vendor/
.github/        R-CMD-check, native-checks and assurance (pedrobtz/r-actions),
                c-core, fuzz, network (the Linux network and per-backend jobs),
                platforms (every macOS and Windows check, one job per OS:
                tools/ci/platform.sh), vendor, conventions, coverage,
                coverage-union, pkgdown
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
  a constant satisfies, while `zuh_now_ms()` returned 0 on Linux for six
  commits. When a test guards a mechanism, break the mechanism once and confirm
  the test fails.
- **The C core builds without R headers.** That is what makes the fuzzing and
  the mock-stream suites possible; keep it true.
- **Every R check in CI runs from a file, never `Rscript -e` with a multi-line
  argument** — that form dies on Windows before executing anything, and cost
  five debugging rounds in S8. Diagnostic steps must not carry
  `continue-on-error`, which turns a failing step into a green tick.
- **Refuse, never downgrade (D-56).** A `zu_tls()` setting the backend cannot
  honour raises `zu_tls_unsupported_error` before any I/O. What a backend
  supports is its `zuh_tls_backend_caps()` mask in C; tests read it through
  `zu_info()$tls_capabilities` / `skip_unless_tls_supports()`, never from a
  table of backend names.
- **Credentials never reach an egress.** Redaction happens in the formatting
  layer, so a redacted request stays executable (§42.3). The canary tests in
  `test-redact.R` are the guard.
- **Test helpers live in `tests/testthat/helper-*.R`**, never at top level
  in a `test-*.R` file: `tools/ci-run-tests.R` shuffles test order, so a
  function defined between `test_that()` calls can run after a test that
  needs it. Run a new test file through `tools/ci-run-tests.R` once before
  pushing; `test_local()` does not shuffle and will not show it.
- Comments explain *why*, and cite the design section. The codebase assumes a
  reader who wants the reasoning, not a narration of the code.

## What the 2026-11-09 reviews found here

The four bug families and the tests they call for are portfolio rules now
(`.claude/shared/correctness.md`); they were written from this package. Three
outside reviews (`.agents/reviews/2026-11-09-fable.md` consolidates them)
found 16 valid bugs, #208–#223, in code that passed 2,526 C checks, the full
R suite and 33,000 sanitised fuzz inputs. What is specific to zuhttp:

- **The wire is the oracle.** No test counted what a server received for an
  HTTP/1.1 upload, and no in-memory upload between 32 KiB and 64 KiB was
  tested, so a 40 KB body went out twice (#208) for months. The upload
  check is in C: `ctest/test_engine_mock.c` records every byte the engine
  writes and asserts each body goes out exactly once, at sizes straddling
  the 64 KiB header-plus-body combine, and `fuzz_engine` checks the same
  framing on fuzzed uploads. `helper-rawserver.R` records only the request
  head, so an R test of a body's bytes needs a server that reads the body.
- **`max_body` is decoded bytes, everywhere.** The chunk decoder billed
  compressed bytes against it (#212). Equivalent payloads under
  Content-Length and chunked framing are tested as a pair.
- **Open bodies are long-lived objects.** W21's streams had no fork guard
  (#209) and an abort that ignored undelivered bytes (#213); the pool and the
  Network.framework backend already had the guards. Anything that outlives
  `C_zu_perform` gets the PID, unwind and lifetime checks they have.
- **The OpenSSL backend is only tested where it is built.** This machine and
  the ASan ctest never compile it, so a stack-use-after-return on
  renegotiation (#215) and IP-literal verification (#216) were reachable only
  by a reviewer who built it by hand. The Ubuntu network job builds it under
  ASan, and server-initiated TLS behaviour comes from a scripted loopback
  server.
- **`make -C fuzz mutate-asan`** is the reviewers' 33,000-mutant soak, made
  reproducible. It passed clean on the tree that carried all 16 bugs: it is a
  crash oracle, not evidence of correctness.

## The `zu*` family

`zukomp`, `zucrypt`, `zujson`, `zuxml`, `zuhtml` and `zuxlsx` are siblings.
zuhttp imports `zujson` for JSON and suggests `zuxml` and `zuhtml` for
`zu_resp_xml()` and `zu_resp_html()` (D-88); compression is still system zlib
(D-7), and pin digests come from each TLS backend. Design §5.1 (D-54) records this and carries the
family table shared by all five repositories. One practical consequence: `zu_`/`ZU_`
is `zukomp`'s public C ABI namespace, so zuhttp's internal C prefix is
`zuh_`/`ZUH_` (D-66, W2). Never write a `zu_` C identifier, even a static one;
`tools/check-c-prefix` fails CI on it. `zu_` stays right in R names, R
condition classes in C strings, comments citing R functions, and the
`C_zu_*` routines `init.c` registers, which R calls by those names.

## Current state

v0.1.0 is CRAN's first submission (roadmap M0, tracker #21, D-82). It was
ready to submit on 2026-10-30; on 2026-11-04 HTTP/2 joined it (D-96), so
W20 (#129), W21 (#130) and W22 (#131) come first, in that order, and the
submission itself, #40, the maintainer's, waits on them. Nothing is tagged until CRAN accepts a version: the tag is
the maintainer's post-acceptance step. M0's work packages (W1, W2, W3, W6,
W13, W16) are merged, and so is the fix of the 2026-10-30 critical review
(#91–#123). Next is W20; after 0.1.0, M1 (#72, v0.2.0). The roadmap's work-package exit
criteria are authoritative: check them rather than inferring status from the
code. Forked HTTPS on macOS raises `zu_fork_error` by design (D-32); it is not
a bug to fix.

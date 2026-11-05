# zuhttp

A minimal HTTP/1.1 and HTTP/2 client for R that uses **each platform’s
own TLS stack and trust store** — Schannel on Windows,
Network.framework + SecTrust on macOS, system OpenSSL elsewhere — rather
than bundling cryptography or a CA bundle. One hard R dependency, the
sibling `zujson` (D-88); `zuxml` and `zuhtml` are Suggests.

## The two documents that govern this repo

Both live in [`.agents/`](https://pedrobtz.github.io/zuhttp/.agents/)
and are excluded from the R package build:

| File | What it is | When to read it |
|----|----|----|
| [`.agents/zuhttp-design.md`](https://pedrobtz.github.io/zuhttp/.agents/zuhttp-design.md) | The design, edition 2: a normative specification in 65 numbered sections, each with a status line; a Decision Register (D-1…D-97); a risk register. | Before changing behaviour. Cite the section, e.g. §31.9. |
| [`.agents/roadmap.md`](https://pedrobtz.github.io/zuhttp/.agents/roadmap.md) | The plan, edition 2: milestones M0–M3 (0.1.0 on CRAN with HTTP/2 → 0.2.0 → 0.3.0 → 1.0; M4 folded into M0, D-96), work packages W1–W22 with exit criteria, and an append-only findings log. | Before starting work, to see which work package owns it. |
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

# Fuzzing — 11 targets (engine and h2 are the whole request path), each built two ways
make -C fuzz replay-run       # corpus replay, needs no clang; a regression suite
make -C fuzz replay-asan      # the same corpus under ASan + UBSan
make -C fuzz fuzz-run         # libFuzzer, needs clang

# R
R CMD INSTALL .
Rscript -e 'testthat::test_local()'                     # offline
ZU_TEST_NETWORK=1 Rscript -e 'testthat::test_local()'   # + the network suite
Rscript -e 'roxygen2::roxygenise()'                     # after touching roxygen blocks
air format R tests && air format --check .              # before every push that touches R;
                                                        #   the conventions job fails otherwise
./tools/check-vendor-licenses                           # after a re-vendor

# HTTP/2 live tests (test-http2.R): a local server whose HTTP/2 is not nghttp2's
tools/h2-test-cert.sh /tmp/h2 && python3 tools/h2-test-server.py 18080 18443 /tmp/h2/cert.pem /tmp/h2/key.pem &
ZU_H2_TEST_SERVER=http://127.0.0.1:18080 ZU_H2_TEST_TLS=https://localhost:18443 \
  ZU_H2_TEST_CA=/tmp/h2/ca.pem Rscript -e 'testthat::test_local(filter = "http2")'

# The R glue (init.c) under valgrind: Linux only; CI runs it on every PR (#164)
tools/ci-valgrind-glue.sh

# What CI actually runs for the R suite — reproduce THIS before claiming green,
# because it differs from R CMD check in ways that have bitten before.
Rscript tools/ci-run-tests.R
```

**Every pull request runs CI** (W1). R-CMD-check, native-checks and the
r-actions jobs run a quick profile on a pull request and the full one on
`main`. Work-package pull requests merge on the quick profile; the
`full-ci` label, which runs the full profile on a pull request, goes
only on the pull request that closes a milestone (the maintainer’s rule,
2026-10-29). One memory check runs on every pull request regardless: the
R glue under valgrind (2026-11-05, \#164). Every merge still runs the
full profile on `main`: read it before opening the next pull request,
and fix what it finds there.

``` sh
tools/vendor/verify            # src/vendor/ is byte-for-byte what was recorded
tools/vendor/record            # after tools/update-*, never after a hand edit
tools/update-nghttp2 1.71.0    # re-vendor nghttp2 with the §48 patches
tools/check-code-lines         # project-owned C against the §51.3 budget
```

Network tests are gated on `ZU_TEST_NETWORK=1`, not on `NOT_CRAN` —
`rcmdcheck` sets `NOT_CRAN`, so gating on it alone would make every
check depend on example.com and badssl.com.

## Layout

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
    .github/        R-CMD-check and native-checks (pedrobtz/r-actions), c-core, fuzz,
                    network (the network and per-backend jobs), vendor,
                    conventions, coverage, coverage-union, pkgdown

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
  *monotonic*, which a constant satisfies, while `zuh_now_ms()` returned
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
  before any I/O. What a backend supports is its
  `zuh_tls_backend_caps()` mask in C; tests read it through
  `zu_info()$tls_capabilities` / `skip_unless_tls_supports()`, never
  from a table of backend names.
- **Credentials never reach an egress.** Redaction happens in the
  formatting layer, so a redacted request stays executable (§42.3). The
  canary tests in `test-redact.R` are the guard.
- **Test helpers live in `tests/testthat/helper-*.R`**, never at top
  level in a `test-*.R` file: `tools/ci-run-tests.R` shuffles test
  order, so a function defined between `test_that()` calls can run after
  a test that needs it. Run a new test file through
  `tools/ci-run-tests.R` once before pushing; `test_local()` does not
  shuffle and will not show it.
- Comments explain *why*, and cite the design section. The codebase
  assumes a reader who wants the reasoning, not a narration of the code.

## The `zu*` family

`zukomp`, `zucrypt`, `zujson`, `zuxml`, `zuhtml` and `zuxlsx` are
siblings. zuhttp imports `zujson` for JSON and suggests `zuxml` and
`zuhtml` for
[`zu_resp_xml()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_json.md)
and
[`zu_resp_html()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_json.md)
(D-88); compression is still system zlib (D-7), and pin digests come
from each TLS backend. Design §5.1 (D-54) records this and carries the
family table shared by all five repositories. One practical consequence:
`zu_`/`ZU_` is `zukomp`’s public C ABI namespace, so zuhttp’s internal C
prefix is `zuh_`/`ZUH_` (D-66, W2). Never write a `zu_` C identifier,
even a static one; `tools/check-c-prefix` fails CI on it. `zu_` stays
right in R names, R condition classes in C strings, comments citing R
functions, and the `C_zu_*` routines `init.c` registers, which R calls
by those names.

## Current state

v0.1.0 is CRAN’s first submission (roadmap M0, tracker \#21, D-82). It
was ready to submit on 2026-10-30; on 2026-11-04 HTTP/2 joined it
(D-96), so W20 (#129), W21 (#130) and W22 (#131) come first, in that
order, and the submission itself, \#40, the maintainer’s, waits on them.
Nothing is tagged until CRAN accepts a version: the tag is the
maintainer’s post-acceptance step. M0’s work packages (W1, W2, W3, W6,
W13, W16) are merged, and so is the fix of the 2026-10-30 critical
review (#91–#123). Next is W20; after 0.1.0, M1 (#72, v0.2.0). The
roadmap’s work-package exit criteria are authoritative: check them
rather than inferring status from the code. Forked HTTPS on macOS raises
`zu_fork_error` by design (D-32); it is not a bug to fix.

#!/usr/bin/env Rscript
# The R-12 / D-32 regression gate for the S9 macOS job (design §26.4 hazard 2).
#
# S0's finding F-5 measured unmitigated forked HTTPS on macOS as a SIGSEGV in
# the worker. tests/testthat/test-fork.R turns that into assertions; this file
# is what CI runs, because every CI R check in this repo runs FROM A FILE.
#
# The one thing this adds over `test_file()` is that IT FAILS ON A SKIP.
# test-fork.R skips unless it is on macOS, on the Secure Transport backend and
# online — correct when someone runs the suite on Linux, but on THIS job a skip
# would mean the regression test silently did not run and the step still went
# green. That is the same failure mode as `continue-on-error`.

library(testthat)
library(zuhttp)

cat("TLS backend: ", zu_tls_backend(), "\n", sep = "")
if (!identical(zu_tls_backend(), "securetransport"))
  stop("this job must build against Secure Transport, got ", zu_tls_backend())

res <- as.data.frame(test_file("tests/testthat/test-fork.R", reporter = "summary"))

skipped <- sum(res$skipped)
failed  <- sum(res$failed) + sum(res$error)

if (skipped > 0)
  stop("R-12 gate: ", skipped, " test(s) SKIPPED — the guard was never exercised")
if (failed > 0)
  stop("R-12 gate: ", failed, " failure(s) — a forked child crashed or did not raise zu_fork_error")

cat("R-12 mitigated: every forked child raised zu_fork_error and survived\n")

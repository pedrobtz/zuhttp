# §26.4 hazard 2 / D-32 / R-12 — HTTPS in a forked child on macOS.
#
# Security.framework opens an XPC connection to trustd on first use, and that
# connection does not survive fork(): the child SIGSEGVs rather than failing.
# S0 measured it as finding F-5. The PID guard in zu_tls_connect() cannot make
# forked HTTPS work; it converts an un-catchable crash into a named condition.
# So this file asserts two things, and the first one is the point:
#
#   1. the worker SURVIVES  — mccollect() gets a value back, not a dead child;
#   2. what it gets back inherits zu_fork_error, with the canonical message.
#
# Non-vacuity: comment out the zu_fork_guard_tripped() branch in
# src/zu_tls_sectransport.c and assertion 1 fails — mccollect() returns NULL
# for a child killed by a signal. That is what makes this a test of the
# mechanism rather than of the error text.

# The guard is armed on the first zu_tls_connect() in the process, so the
# parent must have completed an HTTPS request before forking. A child forked
# from a parent that never armed it arms it fresh and is not in a child at all
# as far as the guard is concerned — which is correct, and would make this
# test pass for the wrong reason.
skip_unless_forked_https_is_testable <- function() {
  testthat::skip_on_cran()
  if (!identical(Sys.getenv("ZU_TEST_NETWORK"), "1"))
    testthat::skip("set ZU_TEST_NETWORK=1 to run network tests")
  if (!identical(Sys.info()[["sysname"]], "Darwin"))
    testthat::skip("R-12 is a macOS Security.framework hazard")
  if (!identical(zu_tls_backend(), "securetransport"))
    testthat::skip("guard lives in the Secure Transport backend")
  testthat::skip_if_not_installed("parallel")
  if (!zu_have_network()) testthat::skip("no network")
}

test_that("HTTPS in a forked child raises zu_fork_error and does not kill the worker", {
  skip_unless_forked_https_is_testable()

  # Arms the guard in the parent (see above).
  expect_identical(zu_resp_status(zu_get("https://example.com")), 200L)

  # Two children, not one: R-12 is about the trust evaluator being dead in
  # every child, so "every child raised it" is the claim worth asserting.
  res <- parallel::mclapply(1:2, function(i) {
    tryCatch(
      { zu_get("https://example.com"); "UNEXPECTED SUCCESS" },
      condition = function(e) list(classes = class(e), message = conditionMessage(e))
    )
  }, mc.cores = 2)

  for (r in res) {
    # (1) The worker came back at all. NULL here means it died on a signal.
    expect_false(is.null(r))
    expect_type(r, "list")

    # (2) ...with the §34.1 class and the one canonical wording (§6.1).
    expect_true("zu_fork_error" %in% r$classes)
    expect_true("zu_error" %in% r$classes)
    expect_true("error" %in% r$classes)
    expect_match(r$message, "fork", ignore.case = TRUE)
  }
})

test_that("the parent's own requests still work after a child has tripped the guard", {
  skip_unless_forked_https_is_testable()

  expect_identical(zu_resp_status(zu_get("https://example.com")), 200L)
  parallel::mclapply(1, function(i)
    tryCatch(zu_get("https://example.com"), condition = function(e) "tripped"),
    mc.cores = 1)

  # The guard is per-process state; a child tripping it must not disarm the
  # parent, which never forked and whose trustd connection is intact.
  expect_identical(zu_resp_status(zu_get("https://example.com")), 200L)
})

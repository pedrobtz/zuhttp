# §26.4 hazard 2 / D-32 / R-12 — HTTPS in a forked child on macOS.
#
# Network.framework runs on libdispatch, which refuses to run after fork():
# the child dies with SIGILL rather than failing (F-19; Security.framework's
# trustd connection did the same with SIGSEGV, S0 F-5). The PID guard in
# zuh_tls_dial() cannot make forked HTTPS work; it converts an un-catchable
# crash into a named condition.
# So this file asserts two things, and the first one is the point:
#
#   1. the worker SURVIVES  — mccollect() gets a value back, not a dead child;
#   2. what it gets back inherits zu_fork_error, with the canonical message.
#
# Non-vacuity: comment out the zuh_fork_guard_tripped() branch in
# src/zuh_tls_nw.c and assertion 1 fails — mccollect() returns NULL
# for a child killed by a signal. That is what makes this a test of the
# mechanism rather than of the error text.

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
  }, mc.cores = 2, mc.cleanup = FALSE)

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
    mc.cores = 1, mc.cleanup = FALSE)

  # The guard is per-process state; a child tripping it must not disarm the
  # parent, which never forked and whose trustd connection is intact.
  expect_identical(zu_resp_status(zu_get("https://example.com")), 200L)
})

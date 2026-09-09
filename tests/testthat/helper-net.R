# The one network gate (CLAUDE.md's "one definition"; §50's determinism rule).
#
# It was six identical copies of the same five lines, one per network test
# file, plus three files that inlined the same logic — and every one of them
# ended in testthat::skip_if_offline(), which calls rlang::check_installed()
# and therefore ERRORS rather than skips on a machine without the `curl`
# package. A skip helper that fails when its dependency is missing is worse
# than no skip helper: it turns "this machine has no network" into a test
# failure. `curl` is not in Suggests either, so R CMD check on such a machine
# fails — an S19 blocker — and the suite of a package whose first line is
# "zero hard R dependencies" was reaching for another HTTP client to decide
# whether to run.
#
# The probe below is base R only. It deliberately does NOT use zuhttp: a
# broken zuhttp must fail its own network tests, not quietly skip them, which
# is the vacuous-pass shape §50 keeps warning about.
#
# The gate is ZU_TEST_NETWORK=1, never NOT_CRAN alone — rcmdcheck sets
# NOT_CRAN, so gating on it would make every check depend on example.com,
# github.com and badssl.com.

# One connection per session, not one per test.
zu_have_network <- local({
  known <- NULL
  function() {
    if (!is.null(known)) return(known)
    con <- try(suppressWarnings(
      socketConnection("example.com", port = 80L, open = "r+",
                       blocking = TRUE, timeout = 5L)), silent = TRUE)
    known <<- !inherits(con, "try-error")
    if (known) try(close(con), silent = TRUE)
    known
  }
})

skip_unless_online <- function() {
  testthat::skip_on_cran()
  if (!identical(Sys.getenv("ZU_TEST_NETWORK"), "1"))
    testthat::skip("set ZU_TEST_NETWORK=1 to run network tests")
  if (!zu_have_network()) testthat::skip("no network")
}

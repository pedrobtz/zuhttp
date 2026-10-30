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
    if (!is.null(known)) {
      return(known)
    }
    con <- try(
      suppressWarnings(
        socketConnection(
          "example.com",
          port = 80L,
          open = "r+",
          blocking = TRUE,
          timeout = 5L
        )
      ),
      silent = TRUE
    )
    known <<- !inherits(con, "try-error")
    if (known) {
      try(close(con), silent = TRUE)
    }
    known
  }
})

skip_unless_online <- function() {
  testthat::skip_on_cran()
  if (!identical(Sys.getenv("ZU_TEST_NETWORK"), "1")) {
    testthat::skip("set ZU_TEST_NETWORK=1 to run network tests")
  }
  if (!zu_have_network()) testthat::skip("no network")
}

# D-56: a zu_tls() setting the linked backend cannot honour is refused before
# any network I/O, so a test that needs the setting to WORK must skip where it
# is refused. The capability list comes from C (zuh_tls_backend_caps), the one
# definition; a table of backends here would drift the first time one gained
# a capability.
tls_supports <- function(cap) cap %in% zu_info()$tls_capabilities

skip_unless_tls_supports <- function(cap) {
  if (!tls_supports(cap)) {
    testthat::skip(paste0(
      "the ",
      zu_tls_backend(),
      " backend refuses `",
      cap,
      "` (zu_tls_unsupported_error; see ?zuhttp_tls)"
    ))
  }
}

# A test whose assertion is a wall-clock bound -- a request timeout that must
# not fire, an elapsed time under N seconds -- cannot hold under gctorture,
# which makes R many times slower. native-checks.yaml sets ZU_GCTORTURE there.
# Such a test checks timing, which gctorture neither tests nor needs.
# The local-server families -- the TLS fixture, the helper proxy, raw
# servers and webfakes -- skip as a whole: at that speed each of them races a
# timeout somewhere, and what gctorture exists to check, the PROTECT
# discipline of init.c, is exercised by every other test.
skip_under_gctorture <- function() {
  if (identical(Sys.getenv("ZU_GCTORTURE"), "true")) {
    testthat::skip("a wall-clock bound, under gctorture")
  }
}

# zu_get() against badssl.com, which resets connections from CI runners now
# and then ("Connection reset by peer" on macOS). A transport failure is
# retried, twice; anything else -- a response, a TLS verdict -- is returned on
# the first attempt, so a flaky network can neither fail a test nor make one
# pass. The same rule as ctest's get_retrying() and dial().
zu_get_badssl <- function(...) {
  transient <- c("zu_connect_error", "zu_io_error", "zu_timeout_error")
  for (attempt in 1:3) {
    r <- tryCatch(zu_get(...), error = function(e) e)
    if (!inherits(r, "error")) {
      return(r)
    }
    if (!inherits(r, transient) || attempt == 3L) stop(r)
  }
}

# For test-fork.R (D-32).
# The guard is armed on the first zuh_tls_dial() in the process, so the
# parent must have completed an HTTPS request before forking. A child forked
# from a parent that never armed it arms it fresh and is not in a child at all
# as far as the guard is concerned — which is correct, and would make this
# test pass for the wrong reason.
skip_unless_forked_https_is_testable <- function() {
  testthat::skip_on_cran()
  if (!identical(Sys.getenv("ZU_TEST_NETWORK"), "1")) {
    testthat::skip("set ZU_TEST_NETWORK=1 to run network tests")
  }
  if (!identical(Sys.info()[["sysname"]], "Darwin")) {
    testthat::skip("R-12 is a macOS Network.framework hazard")
  }
  if (!identical(zu_tls_backend(), "network-framework")) {
    testthat::skip("guard lives in the Network.framework backend")
  }
  testthat::skip_if_not_installed("parallel")
  if (!zu_have_network()) testthat::skip("no network")
}

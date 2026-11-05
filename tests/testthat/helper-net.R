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
    if (!inherits(r, transient) || attempt == 3L) {
      stop(r)
    }
    # Back to back, the retries met the same reset in the same millisecond.
    Sys.sleep(c(1, 3)[attempt])
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

# §65 (test-http2.R). Here rather than in that file: tools/ci-run-tests.R
# shuffles test order, so a top-level definition between test_that() calls
# can run after a test that needs it.
# httpbingo.org speaks h2 and echoes the request, so one host answers "which
# protocol?" and "did the body arrive?" for all three TLS stacks.
# (nghttp2.org/httpbin was the first choice and answered 502 on 2026-11-04.)

h2_host <- "https://httpbingo.org"

# tools/h2-test-server.py, whose HTTP/2 is not nghttp2's; network.yaml starts
# it on Ubuntu and sets these variables (§65.8).
skip_unless_h2_server <- function() {
  if (!nzchar(Sys.getenv("ZU_H2_TEST_SERVER"))) {
    skip("set ZU_H2_TEST_SERVER to a tools/h2-test-server.py h2c URL")
  }
}

# §65.8 (test-http2.R): gRPC by hand against grpc-go's interop server. A
# message is a 5-byte prefix (a compressed flag and a big-endian length) and
# protobuf bytes; the status is in the trailers. Here, not in the test file,
# for the shuffle reason above.
grpc_frame <- function(msg = raw()) {
  n <- length(msg)
  c(as.raw(0), as.raw(bitwAnd(bitwShiftR(n, c(24, 16, 8, 0)), 255L)), msg)
}

grpc_messages <- function(bytes) {
  out <- list()
  i <- 1L
  while (i + 4L <= length(bytes)) {
    n <- sum(as.integer(bytes[(i + 1L):(i + 4L)]) * 256^(3:0))
    out[[length(out) + 1L]] <- bytes[seq_len(n) + i + 4L]
    i <- i + 5L + n
  }
  out
}

skip_unless_grpc_server <- function() {
  if (!nzchar(Sys.getenv("ZU_GRPC_TEST_SERVER"))) {
    skip("set ZU_GRPC_TEST_SERVER to a grpc-go interop server (h2c)")
  }
}

grpc_client <- function() {
  zu_client(
    base_url = Sys.getenv("ZU_GRPC_TEST_SERVER"),
    http2 = "required",
    proxy = FALSE,
    headers = c(`Content-Type` = "application/grpc", TE = "trailers")
  )
}

# test-pull.R: a client whose transport answers with a stored body (and
# trailers), for the pulled-body R surface offline.
mock_client <- function(
  body = charToRaw("hello world"),
  trailers = NULL,
  status = 200L
) {
  zu_client(
    transport = zu_mock_transport(function(req) {
      zu_response(status, body = body, trailers = trailers)
    })
  )
}

# §65.7 (test-http2.R, test-pull.R): a body function producing `total` bytes
# in pieces of `piece`, byte k being k %% 251, which tools/h2-test-server.py's
# /check verifies in order. Returns the function; `calls()` on its
# environment counts how often it was asked.
pattern_body <- function(total, piece) {
  pos <- 0
  n_calls <- 0L
  f <- function() {
    n_calls <<- n_calls + 1L
    if (pos >= total) {
      return(NULL)
    }
    n <- min(piece, total - pos)
    out <- as.raw((pos + seq_len(n) - 1) %% 251)
    pos <<- pos + n
    out
  }
  attr(f, "calls") <- function() n_calls
  f
}

# Open file descriptors of this process, or NA where they cannot be listed
# (Windows). A leaked connection shows as one more; tests compare counts
# around a loop, so the descriptors R itself holds cancel out.
open_fds <- function() {
  for (d in c("/proc/self/fd", "/dev/fd")) {
    if (dir.exists(d)) {
      return(length(list.files(d)))
    }
  }
  NA_integer_
}

# A local app that answers 503 to its first request on /flaky and 200 after,
# for the retry-abort path of a streamed response (#151). One per test: the
# counter lives in the app's process.
local_flaky_app <- function(.local_envir = parent.frame()) {
  skip_if_not_installed("webfakes")
  app <- webfakes::new_app()
  app$locals$n <- 0L
  app$get("/flaky", function(req, res) {
    req$app$locals$n <- req$app$locals$n + 1L
    if (req$app$locals$n == 1L) {
      res$set_status(503L)$send(strrep("x", 50000))
    } else {
      res$set_status(200L)$send("ok")
    }
  })
  webfakes::local_app_process(app, .local_envir = .local_envir)
}

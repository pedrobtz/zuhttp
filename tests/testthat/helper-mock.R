# Mock transports and small constructors shared across test files. They live
# here rather than at the top of the file that first needed them, so every
# test is self-sufficient and the suite passes under
# devtools::test(shuffle = TRUE), which reorders a file's top-level
# expressions.

# A transport that answers 200, optionally recording the request it was given.
null_transport <- function(record = NULL) {
  zu_mock_transport(function(req) {
    if (!is.null(record)) {
      record$req <- req
    }
    zu_response(200L)
  })
}

# A transport that records what it was asked to do and answers from a script.
recorder <- function(respond = function(req) zu_response(200L, body = "ok")) {
  calls <- list()
  t <- zu_mock_transport(function(req) {
    calls[[length(calls) + 1L]] <<- req
    respond(req)
  })
  list(transport = t, calls = function() calls, n = function() length(calls))
}

# A transport that counts its calls and answers f(call_number, request).
counting <- function(f) {
  n <- 0L
  list(
    transport = zu_mock_transport(function(req) {
      n <<- n + 1L
      f(n, req)
    }),
    n = function() n
  )
}

resp <- function(...) zu_response(...)

# A client of its own per test. The DEFAULT client pools, so a test that ran
# earlier leaves a warm connection and the next request correctly skips
# dns/connect/tls — which then looks like missing instrumentation.
fresh <- function(...) zu_client(...)

# A fresh, empty cassette directory.
cassette_dir <- function() {
  d <- file.path(tempdir(), paste0("zu-cass-", as.integer(runif(1, 1, 1e9))))
  unlink(d, recursive = TRUE)
  d
}

# .package is required, not optional: without it testthat asks pkgload which
# package is being developed, and there is no such package when the tests run
# against an INSTALLED zuhttp -- which is how CI runs them, and how a user
# would. It passed locally only because R CMD check supplies that context.
without_jsonlite <- function(env = parent.frame()) {
  testthat::local_mocked_bindings(
    has_jsonlite = function() FALSE,
    .package = "zuhttp",
    .env = env
  )
}

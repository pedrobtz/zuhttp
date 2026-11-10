# The rule zu_get_badssl() uses to skip rather than fail (#283). A wrong
# answer either fails every pull request while badssl.com is down, or skips
# a test on the very outcome it checks: the first version skipped the
# HTTP/2-required refusal, which is a zu_connect_error too.
test_that("only a failure to reach the host counts as unreachable", {
  cond <- function(cls, ...) {
    structure(
      c(list(message = "m", call = NULL), list(...)),
      class = c(cls, "zu_error", "zuhttp_error", "error", "condition")
    )
  }
  # The network never answered.
  expect_true(badssl_unreachable(cond("zu_connect_error", backend_code = 61L)))
  expect_true(badssl_unreachable(cond("zu_io_error", backend_code = 54L)))
  # OpenSSL on Linux: "read failed (104)", a reset, with no backend_code.
  expect_true(badssl_unreachable(cond("zu_io_error")))
  expect_true(badssl_unreachable(cond("zu_timeout_error")))
  # zuhttp's own verdicts, reached over a working connection.
  expect_false(badssl_unreachable(cond("zu_connect_error")))
  expect_false(badssl_unreachable(cond("zu_tls_certificate_error")))
  expect_false(badssl_unreachable(cond("zu_tls_hostname_error")))
  expect_false(badssl_unreachable(simpleError("not ours")))
})

test_that("the HTTP/2-required refusal is a verdict, not unreachable", {
  skip_unless_online()
  api <- zu_client(http2 = "required", pool = NULL)
  e <- tryCatch(
    zu_get("https://badssl.com/", client = api, timeout = 20),
    error = function(e) e
  )
  # An unreachable host is the one outcome this test cannot judge.
  if (inherits(e, "error") && badssl_unreachable(e)) {
    skip(paste("badssl.com unreachable (#63):", conditionMessage(e)))
  }
  if (inherits(e, "zu_connect_error")) {
    expect_false(badssl_unreachable(e))
  }
})

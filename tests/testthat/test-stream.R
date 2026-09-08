# S17 — §27 streaming sinks, from R.
#
# The C suite (ctest/test_body.c) owns the memory guarantee and the atomic
# file mechanics, because those need a 100 MB body and a mock stream. What
# lives here is the R-visible half: the arguments, the callback contract, and
# §27.4's re-entrancy rule.

skip_unless_online <- function() {
  testthat::skip_on_cran()
  if (!identical(Sys.getenv("ZU_TEST_NETWORK"), "1"))
    testthat::skip("set ZU_TEST_NETWORK=1 to run network tests")
  testthat::skip_if_offline()
}

# --- argument validation (offline) ---------------------------------------

test_that("zu_req_path() and zu_req_callback() validate", {
  req <- zu_request("GET", "https://x.test/")
  expect_error(zu_req_path(req, ""), "non-empty")
  expect_error(zu_req_path(req, c("a", "b")), "non-empty")
  expect_error(zu_req_path(req, NA_character_), "non-empty")
  expect_error(zu_req_callback(req, "not a function"), "must be a function")

  expect_identical(zu_req_path(req, "out.bin")$path, path.expand("out.bin"))
  expect_true(is.function(zu_req_callback(req, function(x) NULL)$callback))
})

test_that("`path` is a response destination, `file` is a request body source", {
  # The two are easy to confuse, so the distinction is asserted rather than
  # only documented: §31.6 gives `file` to the body, §27 gives `path` to the
  # sink, and a verb that has both must keep them apart.
  f <- tempfile(); on.exit(unlink(f), add = TRUE)
  writeLines("payload", f)

  seen <- NULL
  cli <- zu_client(transport = zu_mock_transport(function(r) {
    seen <<- r; zu_response(200L)
  }))
  invisible(zu_post("https://x.test/", file = f, client = cli))
  expect_true(length(seen$body) > 0)      # the file became the request body
  expect_null(seen$path)                  # and did not become a sink
})

# --- §27.4 re-entrancy (offline) -----------------------------------------

test_that("the re-entrancy guard is armed only while a callback runs", {
  api <- zu_client(transport = zu_mock_transport(function(r) zu_response(200L)))
  st  <- attr(api, "pool_state")

  # Not armed before or after an ordinary request...
  expect_null(st$in_callback)
  invisible(zu_get("https://x.test/", client = api))
  expect_false(isTRUE(st$in_callback))

  # ...and a request made while the flag is set is refused (§27.4).
  st$in_callback <- TRUE
  expect_error(zu_get("https://x.test/", client = api),
               "cannot make a request on the same client")
  st$in_callback <- FALSE
  expect_identical(zu_resp_status(zu_get("https://x.test/", client = api)), 200L)
})

test_that("the guard clears even when the callback errors", {
  # Otherwise one failed callback would leave the client permanently unusable,
  # which is a worse bug than the one the guard prevents.
  st <- new.env(parent = emptyenv())
  g  <- zuhttp:::guard_callback(function(chunk) stop("boom"), st)
  expect_error(g(raw(1)), "boom")
  expect_false(isTRUE(st$in_callback))
})

test_that("guard_callback() forces its argument", {
  # Regression. The caller does `r$callback <- guard_callback(r$callback, st)`,
  # so `f` is a promise for a binding that is then REPLACED by the wrapper.
  # Unforced, calling the wrapper resolves f to the wrapper and recurses until
  # R's expression depth runs out — from inside a C callback, where the error
  # points nowhere near the cause.
  env <- new.env(parent = emptyenv())
  holder <- list(cb = function(chunk) "original")
  holder$cb <- zuhttp:::guard_callback(holder$cb, env)
  expect_identical(holder$cb(raw(1)), "original")
})

# --- streaming over a real connection ------------------------------------

test_that("a download goes to the file and not into memory", {
  skip_unless_online()
  d <- tempfile(); dir.create(d); on.exit(unlink(d, recursive = TRUE), add = TRUE)
  f <- file.path(d, "out.bin")

  r <- zu_get("https://example.com", path = f)
  expect_identical(zu_resp_status(r), 200L)
  expect_true(file.exists(f))
  expect_gt(file.size(f), 0)
  # The body went to disk, so holding it in memory too would defeat the point.
  expect_identical(length(zu_resp_raw(r)), 0L)
  # §27.1: the temporary file is gone once the download is committed.
  expect_length(list.files(d, pattern = "zudl"), 0L)
})

test_that("a failed download leaves nothing at the target path (§27.1)", {
  skip_unless_online()
  d <- tempfile(); dir.create(d); on.exit(unlink(d, recursive = TRUE), add = TRUE)
  f <- file.path(d, "never.bin")

  # A body limit is a clean way to make the transfer fail partway with a real
  # server, which is what the atomicity rule is actually about.
  expect_error(zu_get("https://example.com", path = f, max_body = 10),
               class = "zu_body_limit_error")
  expect_false(file.exists(f))
  expect_length(list.files(d), 0L)     # not even a stray temporary
})

test_that("a download replaces an existing file only on success", {
  skip_unless_online()
  d <- tempfile(); dir.create(d); on.exit(unlink(d, recursive = TRUE), add = TRUE)
  f <- file.path(d, "existing.bin")
  writeLines("PRECIOUS", f)

  expect_error(zu_get("https://example.com", path = f, max_body = 10),
               class = "zu_body_limit_error")
  # The old file is still there and still intact: a failed download must not
  # destroy what it was going to replace.
  expect_identical(readLines(f), "PRECIOUS")

  expect_identical(zu_resp_status(zu_get("https://example.com", path = f)), 200L)
  expect_false(identical(readLines(f, warn = FALSE)[1], "PRECIOUS"))
})

test_that("a callback receives the body in chunks and can stop it", {
  skip_unless_online()
  chunks <- 0L; total <- 0L
  r <- zu_get("https://example.com", callback = function(chunk) {
    expect_true(is.raw(chunk))
    chunks <<- chunks + 1L
    total  <<- total + length(chunk)
  })
  expect_identical(zu_resp_status(r), 200L)
  expect_gt(chunks, 0L)
  expect_gt(total, 0L)
  expect_identical(length(zu_resp_raw(r)), 0L)

  # §27.2: FALSE stops the transfer cleanly — a response, not an error.
  seen <- 0L
  r2 <- zu_get("https://example.com", callback = function(chunk) {
    seen <<- seen + 1L; FALSE
  })
  expect_identical(seen, 1L)
  expect_identical(zu_resp_status(r2), 200L)
})

test_that("a callback's own error reaches the caller unwrapped (§27.3)", {
  skip_unless_online()
  e <- tryCatch(
    zu_get("https://example.com", callback = function(chunk) stop("my own problem")),
    error = function(e) e)

  # THE user's error, not a zu_* transport error that swallowed it. Getting
  # this wrong turns "object 'x' not found" in someone's callback into a
  # mysterious network failure.
  expect_identical(conditionMessage(e), "my own problem")
  expect_false(inherits(e, "zu_error"))

  # And the client still works: the read loop unwound normally and released
  # the connection rather than longjmping out of the middle of it.
  expect_identical(zu_resp_status(zu_get("https://example.com")), 200L)
})

test_that("a callback may not request on the same client, but may on another (§27.4)", {
  skip_unless_online()
  api   <- zu_client()
  other <- zu_client()

  expect_error(
    zu_get("https://example.com", client = api,
           callback = function(chunk) zu_get("https://example.com", client = api)),
    "cannot make a request on the same client")

  inner <- NULL
  invisible(zu_get("https://example.com", client = api, callback = function(chunk) {
    if (is.null(inner)) inner <<- zu_resp_status(zu_get("https://example.com", client = other))
  }))
  expect_identical(inner, 200L)
})

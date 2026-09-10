# S14 — §36 transports, §37 mocking and record/replay.
#
# Every test here runs offline, which is not incidental: S14's exit criterion
# is that a downstream package's suite runs with no network, and a test file
# that needed one to prove it would be arguing against itself. Where a "real"
# transport is required, a zu_mock_transport() plays that part — §36.1 makes
# that faithful, since a transport implements network semantics only and
# everything above it (merging, redirects, redaction) is the same code either
# way.

cassette_dir <- function() {
  d <- file.path(tempdir(), paste0("zu-cass-", as.integer(runif(1, 1, 1e9))))
  unlink(d, recursive = TRUE)
  d
}

# --- §37 mock matching ---------------------------------------------------

test_that("a stub matches on method, URL, headers and body", {
  api <- function(...) zu_client(transport = zu_mock_transport(...))

  m <- api(zu_stub(zu_response(201L), method = "POST"))
  expect_identical(zu_resp_status(zu_perform(zu_request("POST", "https://h/x"), client = m)), 201L)
  expect_error(zu_perform(zu_request("GET", "https://h/x"), client = m), "no zu_stub")

  m <- api(zu_stub(zu_response(200L), url = "https://h/exact"))
  expect_identical(zu_resp_status(zu_get("https://h/exact", client = m)), 200L)
  expect_error(zu_get("https://h/other", client = m), "no zu_stub")

  m <- api(zu_stub(zu_response(200L), regex = "/users/[0-9]+$"))
  expect_identical(zu_resp_status(zu_get("https://h/users/42", client = m)), 200L)
  expect_error(zu_get("https://h/users/abc", client = m), "no zu_stub")

  m <- api(zu_stub(zu_response(200L), headers = c(Accept = "application/json")))
  expect_identical(zu_resp_status(
    zu_get("https://h/x", headers = c(Accept = "application/json"), client = m)), 200L)
  expect_error(zu_get("https://h/x", headers = c(Accept = "text/csv"), client = m),
               "no zu_stub")

  m <- api(zu_stub(zu_response(200L), body = "ping"))
  expect_identical(zu_resp_status(
    zu_perform(zu_body_raw(zu_request("POST", "https://h/x"), "ping"), client = m)), 200L)
  expect_error(
    zu_perform(zu_body_raw(zu_request("POST", "https://h/x"), "pong"), client = m),
    "no zu_stub")
})

test_that("header matching is case-insensitive and ignores unlisted headers", {
  m <- zu_client(transport = zu_mock_transport(
    zu_stub(zu_response(200L), headers = c("x-api-version" = "2"))))
  # §18.3: the name's case is not part of its identity.
  expect_identical(zu_resp_status(
    zu_get("https://h/x", headers = c("X-API-Version" = "2"), client = m)), 200L)
  # An unlisted header must not narrow the match.
  expect_identical(zu_resp_status(
    zu_get("https://h/x", headers = c("X-API-Version" = "2", "X-Other" = "z"),
           client = m)), 200L)
})

test_that("a stub with no criteria matches everything, and order decides", {
  m <- zu_client(transport = zu_mock_transport(
    zu_stub(zu_response(201L), method = "POST"),
    zu_stub(zu_response(200L))))
  expect_identical(zu_resp_status(zu_perform(zu_request("POST", "https://h/a"), client = m)), 201L)
  expect_identical(zu_resp_status(zu_get("https://h/b", client = m)), 200L)
  expect_identical(zu_resp_status(zu_get("https://h/c", client = m)), 200L)
})

test_that("`times` bounds how often a stub may match", {
  m <- zu_client(transport = zu_mock_transport(
    zu_stub(zu_response(500L), times = 1), zu_stub(zu_response(200L))))
  # The count has to survive across calls, or `times` means nothing.
  expect_identical(zu_resp_status(zu_get("https://h/x", check = FALSE, client = m)), 500L)
  expect_identical(zu_resp_status(zu_get("https://h/x", client = m)), 200L)
  expect_identical(zu_resp_status(zu_get("https://h/x", client = m)), 200L)
})

test_that("a stub response may be a function of the request", {
  m <- zu_client(transport = zu_mock_transport(
    zu_stub(function(req) zu_response(200L, body = toupper(req$method)))))
  expect_identical(zu_resp_text(zu_get("https://h/x", client = m)), "GET")
  expect_identical(zu_resp_text(zu_perform(zu_request("delete", "https://h/x"), client = m)),
                   "DELETE")
})

test_that("the mock transport rejects malformed configuration", {
  expect_error(zu_mock_transport(), "handler function or one or more")
  expect_error(zu_mock_transport(list(1, 2)), "every stub must come from zu_stub")
  expect_error(zu_stub("not a response"), "must be a zu_response")
  expect_error(zu_stub(zu_response(), url = "u", regex = "r"), "not both")
  expect_error(
    zu_perform(zu_request("GET", "https://h/x"),
               client = zu_client(transport = zu_mock_transport(function(r) "nope"))),
    "must return a zu_response")
})

test_that("the bare-function form still works (§36)", {
  m <- zu_client(transport = zu_mock_transport(function(req) zu_response(204L)))
  expect_identical(zu_resp_status(zu_get("https://h/x", client = m)), 204L)
})

# --- §37 record/replay ---------------------------------------------------

test_that("a recorded interaction replays without touching the transport", {
  d <- cassette_dir(); on.exit(unlink(d, recursive = TRUE), add = TRUE)
  calls <- 0L
  live <- zu_mock_transport(function(req) {
    calls <<- calls + 1L
    zu_response(200L, headers = c("Content-Type" = "text/plain"), body = "recorded")
  })

  rec <- zu_client(transport = zu_cassette_transport(d, "t", transport = live))
  expect_identical(zu_resp_text(zu_get("https://h/a", client = rec)), "recorded")
  expect_identical(calls, 1L)

  # Replay mode has no underlying transport at all, so a miss cannot silently
  # fall through to the network.
  rep <- zu_client(transport = zu_cassette_transport(d, "t", mode = "replay"))
  r <- zu_get("https://h/a", client = rep)
  expect_identical(zu_resp_text(r), "recorded")
  expect_identical(zu_resp_status(r), 200L)
  expect_identical(zu_resp_header(r, "content-type"), "text/plain")
  expect_true(isTRUE(r$replayed))
  expect_identical(calls, 1L)          # unchanged: nothing was performed
})

test_that("auto mode records a miss and replays a hit", {
  d <- cassette_dir(); on.exit(unlink(d, recursive = TRUE), add = TRUE)
  calls <- 0L
  live <- zu_mock_transport(function(req) {
    calls <<- calls + 1L
    zu_response(200L, body = paste0("n=", calls))
  })
  cli <- zu_client(transport = zu_cassette_transport(d, "t", transport = live))

  expect_identical(zu_resp_text(zu_get("https://h/a", client = cli)), "n=1")
  expect_identical(zu_resp_text(zu_get("https://h/a", client = cli)), "n=1")  # replayed
  expect_identical(calls, 1L)
  expect_identical(zu_resp_text(zu_get("https://h/b", client = cli)), "n=2")  # new
  expect_identical(calls, 2L)
  expect_length(zu_cassette_interactions(d, "t"), 2L)
})

test_that("replay mode errors on a miss rather than reaching the network", {
  d <- cassette_dir(); on.exit(unlink(d, recursive = TRUE), add = TRUE)
  rep <- zu_client(transport = zu_cassette_transport(d, "empty", mode = "replay"))
  expect_error(zu_get("https://h/nothing", client = rep),
               "no recorded interaction")
})

test_that("record mode re-performs and overwrites an existing interaction", {
  d <- cassette_dir(); on.exit(unlink(d, recursive = TRUE), add = TRUE)
  n <- 0L
  live <- zu_mock_transport(function(req) { n <<- n + 1L; zu_response(200L, body = paste0("v", n)) })

  auto <- zu_client(transport = zu_cassette_transport(d, "t", transport = live))
  expect_identical(zu_resp_text(zu_get("https://h/a", client = auto)), "v1")

  force <- zu_client(transport = zu_cassette_transport(d, "t", mode = "record",
                                                       transport = live))
  expect_identical(zu_resp_text(zu_get("https://h/a", client = force)), "v2")
  # Overwritten in place, not appended: one request, one interaction.
  expect_length(zu_cassette_interactions(d, "t"), 1L)
  expect_identical(zu_resp_text(zu_get("https://h/a", client = auto)), "v2")
})

test_that("matching is on method, URL and body, but not on headers", {
  d <- cassette_dir(); on.exit(unlink(d, recursive = TRUE), add = TRUE)
  n <- 0L
  live <- zu_mock_transport(function(req) { n <<- n + 1L; zu_response(200L, body = paste0("v", n)) })
  cli <- zu_client(transport = zu_cassette_transport(d, "t", transport = live))

  expect_identical(zu_resp_text(zu_get("https://h/a", client = cli)), "v1")

  # A header the client happens to add must not cause a miss...
  expect_identical(zu_resp_text(
    zu_get("https://h/a", headers = c("X-Trace" = "abc"), client = cli)), "v1")
  expect_identical(n, 1L)

  # ...but a different method, URL or body must.
  expect_identical(zu_resp_text(zu_perform(zu_request("POST", "https://h/a"), client = cli)), "v2")
  expect_identical(zu_resp_text(zu_get("https://h/b", client = cli)), "v3")
  expect_identical(zu_resp_text(zu_perform(
    zu_body_raw(zu_request("POST", "https://h/a"), "payload"), client = cli)), "v4")
})

test_that("two requests differing only in a secret share one interaction", {
  # A consequence of keying on the REDACTED request, and the reason that is
  # safe: the cassette index cannot carry a credential, and a rotated token
  # does not invalidate a recorded suite.
  d <- cassette_dir(); on.exit(unlink(d, recursive = TRUE), add = TRUE)
  n <- 0L
  live <- zu_mock_transport(function(req) { n <<- n + 1L; zu_response(200L, body = paste0("v", n)) })
  cli <- zu_client(transport = zu_cassette_transport(d, "t", transport = live))

  expect_identical(zu_resp_text(zu_get("https://h/a?api_key=AAA", client = cli)), "v1")
  expect_identical(zu_resp_text(zu_get("https://h/a?api_key=BBB", client = cli)), "v1")
  expect_identical(n, 1L)
  expect_length(zu_cassette_interactions(d, "t"), 1L)
})

test_that("a cassette survives a fresh session, which is the point of one", {
  d <- cassette_dir(); on.exit(unlink(d, recursive = TRUE), add = TRUE)
  live <- zu_mock_transport(function(req) zu_response(200L, body = "from the network"))
  cli <- zu_client(transport = zu_cassette_transport(d, "t", transport = live))
  invisible(zu_get("https://h/a", client = cli))

  # A new transport object, reading only what is on disk.
  fresh <- zu_client(transport = zu_cassette_transport(d, "t", mode = "replay"))
  expect_identical(zu_resp_text(zu_get("https://h/a", client = fresh)), "from the network")
})

test_that("cassette housekeeping", {
  d <- cassette_dir(); on.exit(unlink(d, recursive = TRUE), add = TRUE)
  expect_identical(zu_cassette_interactions(d, "absent"), list())
  expect_false(zu_cassette_clear(d, "absent"))

  live <- zu_mock_transport(function(req) zu_response(200L))
  cli <- zu_client(transport = zu_cassette_transport(d, "t", transport = live))
  invisible(zu_get("https://h/a", client = cli))
  expect_length(zu_cassette_interactions(d, "t"), 1L)
  expect_true(zu_cassette_clear(d, "t"))
  expect_identical(zu_cassette_interactions(d, "t"), list())

  expect_error(zu_cassette_transport(d, name = ""), "non-empty")
  expect_error(zu_cassette_transport(d, mode = "nonsense"), "should be one of")
})

test_that("the default cassette directory is under tempdir()", {
  # Nothing is written outside the session unless the caller asks: a test tool
  # that littered a user's working directory would not be usable in a check.
  # Compared unnormalised on purpose: on macOS tempdir() is under /var, which
  # is a symlink to /private/var, and normalizePath() resolves it only for a
  # path that already exists — so normalising one side and not the other
  # compares two spellings of the same directory and fails.
  t <- zu_cassette_transport()
  expect_true(startsWith(t$dir, tempdir()))
})

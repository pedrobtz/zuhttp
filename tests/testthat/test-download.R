# §27.1 — the response sink as a destination, from R.
#
# The streaming guarantee itself (memory does not grow with the body) is
# ctest's, against a 100 MB response no server should be asked for. What is
# testable here is the contract around it: one sink, replaced atomically,
# readable back afterwards.

test_that("`path` and `callback` are mutually exclusive (§27.1)", {
  # They were not. init.c picks the callback when both are set and drops the
  # path, so this exact call used to return a response, write nothing, and
  # say nothing — a download that silently did not happen.
  #
  # Against a mock transport deliberately: the check lives in
  # resolve_request(), which runs before any transport, so the mock proves
  # the refusal happens without a socket. Pointed at a real URL this test
  # would pass today and attempt a DNS lookup the moment the check regressed,
  # which is the wrong way round — the offline suite must stay offline in
  # both states, not only in the passing one.
  f   <- tempfile()
  cli <- zu_client(transport = zu_mock_transport(function(req) zu_response(200L)))
  cb  <- function(chunk) NULL

  expect_error(zu_get("https://x.test/a", path = f, callback = cb, client = cli),
               "one destination")
  expect_false(file.exists(f))

  # Both orderings, and the composable form as well as the one-shot: the
  # check lives where the request is resolved precisely so that where the
  # two were set cannot change the answer.
  req <- zu_req_callback(zu_req_path(zu_request("GET", "https://x.test/a"), f), cb)
  expect_error(zu_perform(req, client = cli), "one destination")
  req2 <- zu_req_path(zu_req_callback(zu_request("GET", "https://x.test/a"), cb), f)
  expect_error(zu_perform(req2, client = cli), "one destination")
})

test_that("a download lands whole, and reports where (§27.1)", {
  with_redirect_origin(function(start, target) {
    d <- tempfile(); dir.create(d)
    on.exit(unlink(d, recursive = TRUE), add = TRUE)
    f <- file.path(d, "out.bin")

    r <- zu_get(start, path = f, redirects = 1, timeout = 20,
                client = zu_client(pool = NULL))

    expect_identical(zu_resp_status(r), 200L)
    expect_identical(zu_resp_path(r), f)
    # The body went to the file and NOT through memory.
    expect_identical(length(zu_resp_raw(r)), 0L)
    expect_identical(rawToChar(readBin(f, "raw", file.size(f))), "hi")
    # §19.5: the 302's own body must never reach the caller's sink, and the
    # temporary file must not survive. One file in the directory, the
    # committed one.
    expect_identical(list.files(d), "out.bin")
  })
})

test_that("an existing file is replaced, and only on success (§27.1)", {
  with_redirect_origin(function(start, target) {
    d <- tempfile(); dir.create(d)
    on.exit(unlink(d, recursive = TRUE), add = TRUE)
    f <- file.path(d, "out.bin")
    writeLines("previous contents", f)

    r <- zu_get(start, path = f, redirects = 1, timeout = 20,
                client = zu_client(pool = NULL))
    expect_identical(zu_resp_status(r), 200L)
    expect_identical(rawToChar(readBin(f, "raw", file.size(f))), "hi")
  })

  # ...and the other half of the same rule: a request that fails leaves what
  # was already there untouched, because nothing touches the destination
  # until the body has arrived whole. Port 9 (discard) refuses.
  d <- tempfile(); dir.create(d)
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  f <- file.path(d, "keep.bin")
  writeLines("previous contents", f)
  expect_error(zu_get("http://127.0.0.1:9/x", path = f, timeout = 5),
               class = "zu_connect_error")
  expect_identical(readLines(f, warn = FALSE), "previous contents")
  expect_identical(list.files(d), "keep.bin")   # no temporary file left over
})

test_that("a response that was not written to a file reports no path", {
  # zu_resp_path() is set by the transport that actually wrote the file, so a
  # mock must keep reporting NULL even when the request asked for one — an
  # accessor that echoed the request back would be reporting an intention as
  # though it were a fact.
  f <- tempfile()
  cli <- zu_client(transport = zu_mock_transport(function(req) zu_response(200L)))
  expect_null(zu_resp_path(zu_get("https://x.test/a", path = f, client = cli)))
  expect_false(file.exists(f))
  expect_null(zu_resp_path(zu_response(200L)))
})

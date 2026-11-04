# §65.3-§65.5 offline: the R surface of the pulled body, trailers and abort.
# The live paths are test-http2.R's; the C paths are ctest/test_h2.c's. What
# is here needs no network: argument checking, and the mock path, where a
# response the transport did not stream is served from its stored body.

test_that("a mock response requested with stream = TRUE is read in pieces", {
  r <- zu_perform(
    zu_request("GET", "https://x.test/"),
    client = mock_client(),
    stream = TRUE
  )
  expect_identical(rawToChar(zu_resp_read(r, 4)), "hell")
  expect_identical(rawToChar(zu_resp_read(r, 4)), "o wo")
  expect_identical(rawToChar(zu_resp_read(r, 100)), "rld")
  expect_length(zu_resp_read(r), 0L)
  expect_length(zu_resp_read(r), 0L) # past the end is still the end
})

test_that("an empty mock body ends at once", {
  r <- zu_perform(
    zu_request("GET", "https://x.test/"),
    client = mock_client(raw()),
    stream = TRUE
  )
  expect_length(zu_resp_read(r), 0L)
})

test_that("zu_resp_abort() stops a mock stream; reading after it is zu_cancelled_error", {
  r <- zu_perform(
    zu_request("GET", "https://x.test/"),
    client = mock_client(),
    stream = TRUE
  )
  zu_resp_read(r, 2)
  expect_identical(zu_resp_abort(r), r)
  expect_error(zu_resp_read(r), class = "zu_cancelled_error")
  # Aborting a body already read to its end is a no-op.
  r2 <- zu_perform(
    zu_request("GET", "https://x.test/"),
    client = mock_client(),
    stream = TRUE
  )
  zu_resp_read(r2, 100)
  zu_resp_abort(r2)
  expect_length(zu_resp_read(r2), 0L)
})

test_that("zu_resp_read() refuses a response that was not streamed", {
  r <- zu_perform(zu_request("GET", "https://x.test/"), client = mock_client())
  expect_error(zu_resp_read(r), "stream = TRUE")
  expect_invisible(zu_resp_abort(r)) # a no-op, not an error
})

test_that("zu_resp_read() checks n", {
  r <- zu_perform(
    zu_request("GET", "https://x.test/"),
    client = mock_client(),
    stream = TRUE
  )
  for (bad in list(0, -1, NA_real_, "5", c(1, 2))) {
    expect_error(zu_resp_read(r, bad), "`n` must be")
  }
})

test_that("stream must be TRUE or FALSE, and excludes path and callback", {
  req <- zu_request("GET", "https://x.test/")
  expect_error(zu_perform(req, client = mock_client(), stream = NA), "`stream`")
  expect_error(
    zu_perform(req, client = mock_client(), stream = "yes"),
    "`stream`"
  )
  expect_error(
    zu_perform(
      zu_req_path(req, tempfile()),
      client = mock_client(),
      stream = TRUE
    ),
    "one destination"
  )
  expect_error(
    zu_perform(
      zu_req_callback(req, function(x) TRUE),
      client = mock_client(),
      stream = TRUE
    ),
    "one destination"
  )
})

test_that("a streamed response with an error status raises after aborting it", {
  expect_error(
    zu_perform(
      zu_request("GET", "https://x.test/"),
      client = mock_client(status = 503L),
      stream = TRUE
    ),
    class = "zu_http_server_error"
  )
})

test_that("zu_resp_trailers() on a buffered response: all, by name, case-insensitively", {
  tr <- c(`grpc-status` = "0", `Grpc-Message` = "ok")
  r <- zu_perform(
    zu_request("GET", "https://x.test/"),
    client = mock_client(trailers = tr)
  )
  expect_identical(zu_resp_trailers(r), tr)
  expect_identical(zu_resp_trailers(r, "GRPC-STATUS"), "0")
  expect_identical(zu_resp_trailers(r, "grpc-message"), "ok")
  expect_identical(zu_resp_trailers(r, "absent"), character())
})

test_that("a response without trailers has none", {
  r <- zu_perform(zu_request("GET", "https://x.test/"), client = mock_client())
  expect_length(zu_resp_trailers(r), 0L)
  expect_identical(zu_resp_trailers(r, "grpc-status"), character())
})

test_that("zu_pool() checks keepalive_time and keepalive_timeout", {
  expect_identical(zu_pool()$keepalive_time_ms, 0L)
  p <- zu_pool(keepalive_time = 60, keepalive_timeout = 20)
  expect_identical(p$keepalive_time_ms, 60000L)
  expect_identical(p$keepalive_timeout_ms, 20000L)
  for (bad in list(0, -1, NA_real_, "60", c(1, 2))) {
    expect_error(zu_pool(keepalive_time = bad), "`keepalive_time`")
    expect_error(zu_pool(keepalive_timeout = bad), "`keepalive_timeout`")
  }
})

test_that("a client with keepalive set builds its pool", {
  # The pool is created lazily, on the first request; client_pool() is what
  # that request calls, with the keepalive settings passed to C.
  api <- zu_client(pool = zu_pool(keepalive_time = 1, keepalive_timeout = 1))
  expect_true(pool_valid(client_pool(api)))
})

# --- §65.7 zu_body_stream(), offline ------------------------------------------

test_that("zu_body_stream() marks the body unrewindable and replaces any other", {
  f <- pattern_body(10, 4)
  req <- zu_body_stream(
    zu_body_raw(zu_request("POST", "https://x.test/"), "old"),
    f
  )
  expect_null(req$body)
  expect_identical(req$body_stream, f)
  expect_false(zu_body_rewindable(req))
  expect_output(print(req), "streamed by a function")
  # A later in-memory body replaces the stream, and is rewindable again.
  req2 <- zu_body_raw(req, "new")
  expect_null(req2$body_stream)
  expect_true(zu_body_rewindable(req2))
  expect_error(zu_body_stream(req, "not a function"), "must be a function")
})

test_that("a mock transport sees a streamed body collected whole", {
  seen <- NULL
  api <- zu_client(
    transport = zu_mock_transport(function(req) {
      seen <<- req$body
      zu_response(200L)
    })
  )
  zu_perform(
    zu_body_stream(zu_request("POST", "https://x.test/"), pattern_body(10, 4)),
    client = api
  )
  expect_identical(seen, as.raw(0:9))
  bad <- function() "not raw"
  expect_error(
    zu_perform(
      zu_body_stream(zu_request("POST", "https://x.test/"), bad),
      client = api
    ),
    "raw vector"
  )
})

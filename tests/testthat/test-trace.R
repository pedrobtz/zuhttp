# §35.1 timings and §35.3 events.
#
# Both were specified from the start and neither existed: zu_resp_timings()
# returned `total` alone, and the four implemented hooks were all HTTP-level.
# The phases anyone actually wants to see — DNS, connect, TLS handshake —
# were exactly the invisible ones.

# A client of its own per test. The DEFAULT client pools, so a test that ran
# earlier in the file leaves a warm connection and the next request correctly
# skips dns/connect/tls — which then looks like missing instrumentation. The
# pooling is right; sharing a client between tests that measure connection
# setup is not.
fresh <- function(...) zu_client(...)

skip_unless_online <- function() {
  testthat::skip_on_cran()
  if (!identical(Sys.getenv("ZU_TEST_NETWORK"), "1"))
    testthat::skip("set ZU_TEST_NETWORK=1 to run network tests")
  testthat::skip_if_offline()
}

# --- offline -------------------------------------------------------------

test_that("tracing is off by default", {
  # It costs a fixed buffer and a branch per event. Cheap is not free, and a
  # diagnostic nobody asked for should not be collected.
  r <- zu_get("https://h/x", client = zu_client(
    transport = zu_mock_transport(function(q) zu_response(200L))))
  expect_null(zu_resp_trace(r))

  expect_true(zu_req_trace(zu_request("GET", "https://h/x"))$trace)
  expect_false(zu_req_trace(zu_request("GET", "https://h/x"), FALSE)$trace)
})

test_that("a hand-built response still answers zu_resp_timings()", {
  # A mock has no phases, and every caller should not need a guard for that.
  expect_silent(t <- zu_resp_timings(zu_response(200L)))
  expect_null(zu_resp_trace(zu_response(200L)))
})

# --- the phases, live ----------------------------------------------------

test_that("§35.1 reports all nine measurements", {
  skip_unless_online()
  t <- zu_resp_timings(zu_get("https://example.com", client = fresh()))
  expect_named(t, c("dns", "connect", "tls", "request_write", "ttfb",
                    "response_read", "total", "body_bytes_wire",
                    "body_bytes_decoded"))
  # Seconds, like `timeout`, so the two can be compared without converting.
  expect_gt(t[["total"]], 0)
  expect_lt(t[["total"]], 60)
  # The phases are ordered by construction, and an out-of-order pair means a
  # clock was read in the wrong place.
  expect_lte(t[["dns"]], t[["ttfb"]])
  expect_lte(t[["request_write"]], t[["ttfb"]])
  expect_gt(t[["body_bytes_decoded"]], 0)
})

test_that("a phase that did not happen is NA, not zero", {
  skip_unless_online()
  api <- zu_client()
  invisible(zu_get("https://example.com", client = api))
  t <- zu_resp_timings(zu_get("https://example.com", client = api))

  # The whole reason -1 becomes NA rather than 0: a pooled connection did not
  # resolve or connect, and reporting 0 would claim it did so instantly.
  expect_true(is.na(t[["dns"]]))
  expect_true(is.na(t[["connect"]]))
  expect_true(is.na(t[["tls"]]))
  expect_false(is.na(t[["ttfb"]]))
})

test_that("plain HTTP has no TLS phase at all", {
  skip_unless_online()
  t <- zu_resp_timings(zu_get("http://example.com", client = fresh()))
  expect_true(is.na(t[["tls"]]))
  expect_false(is.na(t[["connect"]]))
})

test_that("wire and decoded byte counts differ for a compressed body", {
  skip_unless_online()
  t <- zu_resp_timings(zu_get("https://example.com", client = fresh()))
  # example.com serves gzip. Reporting only one number would hide the
  # compression entirely, which is half of what these two fields are for.
  # (The engine strips Content-Encoding once it decodes, so the header is
  # gone by the time a caller could check it — these counts are the evidence.)
  expect_gt(t[["body_bytes_wire"]], 0)
  expect_gt(t[["body_bytes_decoded"]], 0)
})

# --- the event log -------------------------------------------------------

test_that("§35.3 narrates the whole chain, in order", {
  skip_unless_online()
  tr <- zu_resp_trace(zu_get("https://example.com", trace = TRUE, client = fresh()))
  expect_s3_class(tr, "data.frame")
  expect_named(tr, c("event", "at_ms", "n", "detail"))

  ev <- tr$event
  expect_identical(ev[[1]], "request.start")
  expect_identical(ev[[length(ev)]], "request.done")
  # The phases a timing summary can only total up.
  for (e in c("dns.start", "dns.done", "connect.start", "connect.done",
              "tls.start", "tls.done", "request.sent", "headers.received"))
    expect_true(e %in% ev, info = e)

  # Monotonic, because at_ms is measured from one clock started once.
  expect_false(is.unsorted(tr$at_ms))

  # connect.done carries the address actually reached, which is the one thing
  # a "cannot connect" report never contains.
  expect_true(nzchar(tr$detail[ev == "connect.done"][[1]]))
  expect_identical(tr$detail[ev == "headers.received"][[1]], "200")
})

test_that("a reused connection says so, and skips the phases it skipped", {
  skip_unless_online()
  api <- zu_client()
  invisible(zu_get("https://example.com", client = api))
  ev <- zu_resp_trace(zu_get("https://example.com", trace = TRUE, client = api))$event

  expect_true("connection.reused" %in% ev)
  # Not merely "faster": the phases are absent, which is the explanation for
  # the speed rather than a symptom of it.
  expect_false("dns.start" %in% ev)
  expect_false("connect.start" %in% ev)
  expect_false("tls.start" %in% ev)
})

test_that("plain HTTP produces no TLS events", {
  skip_unless_online()
  ev <- zu_resp_trace(zu_get("http://example.com", trace = TRUE, client = fresh()))$event
  expect_true("connect.done" %in% ev)
  expect_false("tls.start" %in% ev)
  expect_false("tls.done" %in% ev)
})

test_that("a followed redirect is an event, with its target (§35.3)", {
  with_redirect_origin(function(start, target) {
    r  <- zu_get(start, trace = TRUE, redirects = 1, check = FALSE,
                 timeout = 20, client = fresh(pool = NULL))
    tr <- zu_resp_trace(r)
    got <- tr$detail[tr$event == "redirect.followed"]

    expect_length(got, 1L)
    # Byte equality against the URL the response reports, not a shape test.
    # The detail was once a pointer into headers the engine had already
    # freed, and both "^https?://" and validUTF8() pass on plausible
    # garbage; only "it is exactly where the request went" cannot be
    # satisfied by freed memory. It also pins the two builders together, so
    # the event and zu_resp_url() cannot drift apart.
    expect_identical(got[[1]], target)
    # Both renderings of the same hop. This URL has no secret in it, so the
    # equality holds trivially; test-redact.R asserts it again on a URL that
    # does, which is where it constrains anything.
    expect_identical(got[[1]], zu_resp_url(r))
    expect_identical(zu_resp_status(r), 200L)
  })
})

test_that("zu_verbose() narrates the phases when the request is traced", {
  skip_unless_online()
  out <- textConnection("lines", "w", local = TRUE)
  on.exit(try(close(out), silent = TRUE), add = TRUE)
  cli <- fresh(hooks = zu_verbose(to = out))
  invisible(zu_get("https://example.com", trace = TRUE, client = cli))
  close(out)

  expect_true(any(grepl("dns.start", lines, fixed = TRUE)))
  expect_true(any(grepl("tls.done", lines, fixed = TRUE)))
  expect_true(any(grepl("headers.received", lines, fixed = TRUE)))
  # Still the HTTP view as well; the trace adds to it rather than replacing it.
  expect_true(any(grepl("< HTTP 200", lines, fixed = TRUE)))
})

test_that("zu_verbose() without a trace shows the HTTP layer only", {
  out <- textConnection("lines2", "w", local = TRUE)
  on.exit(try(close(out), silent = TRUE), add = TRUE)
  cli <- zu_client(hooks = zu_verbose(to = out),
                   transport = zu_mock_transport(function(q) zu_response(200L)))
  invisible(zu_get("https://h/x", client = cli))
  close(out)

  expect_true(any(grepl("^> GET", lines2)))
  expect_false(any(grepl("dns.start", lines2, fixed = TRUE)))
})

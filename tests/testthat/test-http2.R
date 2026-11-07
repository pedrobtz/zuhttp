# §65 HTTP/2 (W20): the http2 option, how a response reports its version, and
# HTTP/2 against real servers.
#
# The C suite (ctest/test_h2.c) drives the whole engine against an in-process
# nghttp2 server; these tests cover what only R sees, and the live paths: a
# public h2 host on every backend, and a local server whose HTTP/2 is not
# nghttp2's (tools/h2-test-server.py) on the legs that start it.

test_that("http2 is a §31.9 policy: the client sets it, the default is auto", {
  api <- zu_client(http2 = "required")
  r <- resolved(zu_request("GET", "https://x/"), api)
  expect_identical(r$resolved$http2, "required")
  r <- resolved(zu_request("GET", "https://x/"), zu_client())
  expect_identical(r$resolved$http2, "auto")
})

test_that("an http2 setting that is not one of the three words is refused", {
  # A mock transport, so the refusal is shown to happen while the request is
  # resolved, before any transport is asked.
  called <- FALSE
  api <- zu_client(
    http2 = "sometimes",
    transport = zu_mock_transport(function(req) {
      called <<- TRUE
      zu_response(200L)
    })
  )
  expect_error(zu_get("https://x.test/", client = api), "http2")
  expect_false(called)
  api <- zu_client_update(api, http2 = TRUE)
  expect_error(zu_get("https://x.test/", client = api), "http2")
})

test_that("zu_resp_connection() says HTTP/2 for an h2 response, HTTP/1.x otherwise", {
  h2 <- structure(list(http_major = 2L, http_minor = 0L), class = "zu_response")
  h1 <- structure(list(http_major = 1L, http_minor = 1L), class = "zu_response")
  old <- structure(list(http_minor = 0L), class = "zu_response")
  expect_identical(zu_resp_connection(h2)$http_version, "HTTP/2")
  expect_identical(zu_resp_connection(h1)$http_version, "HTTP/1.1")
  # A response recorded before http_major existed (a cassette) is HTTP/1.x.
  expect_identical(zu_resp_connection(old)$http_version, "HTTP/1.0")
})

# --- a public HTTP/2 host, on every backend -----------------------------------
#

test_that("§65.1: TLS negotiates h2 by ALPN by default, and the response says so", {
  skip_unless_online()
  r <- zu_get_badssl(paste0(h2_host, "/get"), client = zu_client(pool = NULL))
  expect_identical(zu_resp_status(r), 200L)
  expect_identical(zu_resp_connection(r)$http_version, "HTTP/2")
  expect_identical(zu_resp_json(r)$url, paste0(h2_host, "/get"))
})

test_that("§65.1: http2 = \"off\" offers http/1.1 alone, to the same host", {
  skip_unless_online()
  api <- zu_client(http2 = "off", pool = NULL)
  r <- zu_get_badssl(paste0(h2_host, "/get"), client = api)
  expect_identical(zu_resp_status(r), 200L)
  expect_identical(zu_resp_connection(r)$http_version, "HTTP/1.1")
})

test_that("§65.2: a POST over h2 reaches the server whole", {
  skip_unless_online()
  payload <- "a body sent over HTTP/2"
  r <- zu_post(
    paste0(h2_host, "/post"),
    body = payload,
    headers = c(`Content-Type` = "text/plain"),
    client = zu_client(pool = NULL)
  )
  expect_identical(zu_resp_connection(r)$http_version, "HTTP/2")
  expect_identical(zu_resp_json(r)$data, payload)
})

test_that("§65.2: a pooled h2 connection carries the next request", {
  skip_unless_online()
  api <- zu_client()
  a <- zu_get_badssl(paste0(h2_host, "/get"), client = api)
  b <- zu_get_badssl(paste0(h2_host, "/get"), client = api)
  expect_identical(zu_resp_connection(b)$http_version, "HTTP/2")
  expect_true(zu_resp_connection(b)$reused_connection)
})

test_that("§65.1: http2 = \"required\" refuses a server that only speaks HTTP/1.1", {
  skip_unless_online()
  # badssl.com offers only http/1.1 by ALPN (checked 2026-11-04).
  api <- zu_client(http2 = "required", pool = NULL)
  e <- tryCatch(
    zu_get_badssl("https://badssl.com/", client = api),
    error = function(e) e
  )
  # Skipped only when the host has really moved to h2. A response over
  # HTTP/1.1 is the very failure this test exists for, and fails it (#138).
  if (
    inherits(e, "zu_response") &&
      identical(zu_resp_connection(e)$http_version, "HTTP/2")
  ) {
    skip(
      "badssl.com now negotiates h2; the refusal needs an HTTP/1.1-only host"
    )
  }
  expect_s3_class(e, "zu_connect_error")
  expect_match(conditionMessage(e), "HTTP/2 is required")
})

test_that("§65.1: http2 = \"required\" refuses a TLS server without h2, offline (#138)", {
  skip_unless_local_tls()
  # openssl s_server -www negotiates no ALPN at all, so the handshake
  # completes and selects nothing: the refusal comes after TLS, before any
  # request byte, and is the same on every backend that offers ALPN.
  fx <- tls_fixture()
  with_tls_server("good", function(url) {
    api <- zu_client(
      http2 = "required",
      tls = zu_tls(ca_file = fx$ca),
      pool = NULL,
      timeout = 10
    )
    expect_error(
      zu_get(url, client = api),
      class = "zu_connect_error",
      regexp = "HTTP/2 is required"
    )
    # The same server answers over HTTP/1.1 when HTTP/2 is not required, so
    # the refusal is the policy, not a broken server.
    r <- zu_get(url, tls = zu_tls(ca_file = fx$ca), timeout = 10)
    expect_identical(zu_resp_status(r), 200L)
  })
})

# --- a local server whose HTTP/2 is not nghttp2's ------------------------------

test_that("§65.1: h2c by prior knowledge: a GET and a POST over cleartext HTTP/2", {
  skip_unless_h2_server()
  base <- Sys.getenv("ZU_H2_TEST_SERVER")
  api <- zu_client(http2 = "required", proxy = FALSE)
  r <- zu_get(paste0(base, "/get?x=1"), client = api)
  j <- zu_resp_json(r)
  expect_identical(j$http_version, "2")
  expect_identical(j$path, "/get")
  expect_identical(j$query, "x=1")
  expect_identical(zu_resp_connection(r)$http_version, "HTTP/2")
  # §65.2: no connection headers on a stream, and no Upgrade dance.
  expect_null(j$headers$connection)
  expect_null(j$headers$upgrade)

  payload <- as.raw(sample(0:255, 70000, replace = TRUE))
  r <- zu_post(paste0(base, "/post"), body = payload, client = api)
  expect_identical(zu_resp_raw(r), payload)
})

test_that("§65.1: with http2 = \"auto\", http:// is HTTP/1.1 to the same server", {
  skip_unless_h2_server()
  base <- Sys.getenv("ZU_H2_TEST_SERVER")
  r <- zu_get(paste0(base, "/get"), client = zu_client(proxy = FALSE))
  expect_identical(zu_resp_json(r)$http_version, "1.1")
  expect_identical(zu_resp_connection(r)$http_version, "HTTP/1.1")
})

test_that("§65.1: h2 over TLS to a local server, GET and POST", {
  skip_unless_h2_server()
  base <- Sys.getenv("ZU_H2_TEST_TLS")
  ca <- Sys.getenv("ZU_H2_TEST_CA")
  if (!nzchar(base) || !nzchar(ca)) {
    skip("ZU_H2_TEST_TLS and ZU_H2_TEST_CA unset")
  }
  skip_unless_tls_supports("ca_file")
  api <- zu_client(tls = zu_tls(ca_file = ca), proxy = FALSE)
  r <- zu_get(paste0(base, "/get"), client = api)
  expect_identical(zu_resp_json(r)$http_version, "2")
  expect_identical(zu_resp_connection(r)$http_version, "HTTP/2")
  payload <- charToRaw("over TLS and HTTP/2")
  r <- zu_post(paste0(base, "/post"), body = payload, client = api)
  expect_identical(zu_resp_raw(r), payload)
  off <- zu_client_update(api, http2 = "off")
  r <- zu_get(paste0(base, "/get"), client = off)
  expect_identical(zu_resp_json(r)$http_version, "1.1")
})

# --- W21: the pulled body, trailers, abort (§65.3-§65.5) ---------------------

test_that("§65.3: trailers from an HTTP/2 server, after a streamed body ends", {
  skip_unless_h2_server()
  base <- Sys.getenv("ZU_H2_TEST_SERVER")
  # A server sends trailers to a client that says it takes them; gRPC
  # clients always do (§65.3).
  api <- zu_client(
    http2 = "required",
    proxy = FALSE,
    headers = c(TE = "trailers")
  )
  r <- zu_get(paste0(base, "/trailers"), client = api)
  expect_identical(zu_resp_trailers(r, "grpc-status"), "0")
  expect_identical(zu_resp_trailers(r, "Grpc-Message"), "ok")
  expect_length(zu_resp_header(r, "grpc-status"), 0L)

  s <- zu_perform(
    zu_request("GET", paste0(base, "/trailers")),
    client = api,
    stream = TRUE
  )
  expect_null(zu_resp_trailers(s)) # not known until the body has ended
  expect_identical(rawToChar(zu_resp_read(s)), "x")
  expect_length(zu_resp_read(s), 0L)
  expect_identical(zu_resp_trailers(s, "grpc-status"), "0")
})

test_that("§65.4: a streamed body is read in the caller's pieces, then reused", {
  skip_unless_h2_server()
  base <- Sys.getenv("ZU_H2_TEST_SERVER")
  api <- zu_client(http2 = "required", proxy = FALSE)
  n <- 3e6
  r <- zu_perform(
    zu_request("GET", paste0(base, "/bytes?n=", sprintf("%.0f", n))),
    client = api,
    stream = TRUE
  )
  # No body is held: the accessors refuse rather than return nothing (#144).
  expect_error(zu_resp_raw(r), "zu_resp_read")
  total <- 0
  pieces <- 0L
  repeat {
    b <- zu_resp_read(r, 65536)
    if (!length(b)) {
      break
    }
    expect_lte(length(b), 65536)
    if (total == 0) {
      expect_identical(b[1:4], as.raw(0:3))
    }
    total <- total + length(b)
    pieces <- pieces + 1L
  }
  expect_identical(total, n)
  expect_gt(pieces, 40L)
  hits <- zu_pool_stats(api)[["hits"]]
  zu_get(paste0(base, "/get"), client = api)
  expect_identical(zu_pool_stats(api)[["hits"]], hits + 1L)
})

test_that("§65.4: an unread stream holds the server at one window", {
  skip_unless_h2_server()
  base <- Sys.getenv("ZU_H2_TEST_SERVER")
  ctl <- zu_client(proxy = FALSE, pool = NULL)
  sent <- function() {
    zu_resp_json(zu_get(paste0(base, "/sent"), client = ctl))$sent
  }
  zu_get(paste0(base, "/sent?reset=1"), client = ctl)
  api <- zu_client(http2 = "required", proxy = FALSE, max_body = Inf)
  r <- zu_perform(
    zu_request("GET", paste0(base, "/bytes?n=", sprintf("%.0f", 200 * 1024^2))),
    client = api,
    stream = TRUE
  )
  Sys.sleep(1)
  a <- sent()
  Sys.sleep(1)
  b <- sent()
  # The server's own count stays put, and well short of the 200 MiB body:
  # one stream window plus what the transport buffers, not the body.
  expect_identical(a, b)
  expect_lt(b, 16 * 1024^2)
  # Reading lets it go on.
  for (i in 1:64) {
    zu_resp_read(r, 1024^2)
  }
  Sys.sleep(0.5)
  expect_gt(sent(), b)
  zu_resp_abort(r)
})

test_that("§65.5: abort over HTTP/2 keeps the connection for the next request", {
  skip_unless_h2_server()
  base <- Sys.getenv("ZU_H2_TEST_SERVER")
  api <- zu_client(http2 = "required", proxy = FALSE)
  r <- zu_perform(
    zu_request("GET", paste0(base, "/bytes?n=", sprintf("%.0f", 50e6))),
    client = api,
    stream = TRUE
  )
  expect_gt(length(zu_resp_read(r, 1000)), 0L)
  zu_resp_abort(r)
  zu_resp_abort(r) # a no-op
  expect_error(zu_resp_read(r), class = "zu_cancelled_error")
  hits <- zu_pool_stats(api)[["hits"]]
  expect_identical(
    zu_resp_status(zu_get(paste0(base, "/get"), client = api)),
    200L
  )
  expect_identical(zu_pool_stats(api)[["hits"]], hits + 1L)
})

test_that("§65.5: a callback returning FALSE over HTTP/2 also keeps the connection", {
  skip_unless_h2_server()
  base <- Sys.getenv("ZU_H2_TEST_SERVER")
  api <- zu_client(http2 = "required", proxy = FALSE)
  calls <- 0L
  r <- zu_get(
    paste0(base, "/bytes?n=", sprintf("%.0f", 50e6)),
    client = api,
    callback = function(x) {
      calls <<- calls + 1L
      FALSE
    }
  )
  expect_identical(zu_resp_status(r), 200L)
  expect_identical(calls, 1L) # stopped at the first chunk, not after
  hits <- zu_pool_stats(api)[["hits"]]
  zu_get(paste0(base, "/get"), client = api)
  expect_identical(zu_pool_stats(api)[["hits"]], hits + 1L)
})

test_that("§65.4: max_body holds across a streamed body", {
  skip_unless_h2_server()
  base <- Sys.getenv("ZU_H2_TEST_SERVER")
  api <- zu_client(http2 = "required", proxy = FALSE, max_body = 1e6)
  r <- zu_perform(
    zu_request("GET", paste0(base, "/bytes?n=", sprintf("%.0f", 3e6))),
    client = api,
    stream = TRUE
  )
  got <- 0
  e <- tryCatch(
    repeat {
      b <- zu_resp_read(r, 65536)
      if (!length(b)) {
        break
      }
      got <- got + length(b)
    },
    error = function(e) e
  )
  expect_s3_class(e, "zu_body_limit_error")
  expect_lte(got, 1e6)
})

test_that("§65.4: an interrupt inside zu_resp_read() returns within the bound", {
  skip_unless_h2_server()
  skip_on_cran()
  skip_on_os("windows")
  skip_under_gctorture()
  base <- Sys.getenv("ZU_H2_TEST_SERVER")
  api <- zu_client(http2 = "required", proxy = FALSE, timeout = 60)
  r <- zu_perform(
    zu_request("GET", paste0(base, "/slow")),
    client = api,
    stream = TRUE
  )
  expect_identical(rawToChar(zu_resp_read(r)), "slow")
  before <- open_fds()
  system(sprintf(
    "sh -c 'sleep 0.5; kill -INT %d' >/dev/null 2>&1 &",
    Sys.getpid()
  ))
  t0 <- Sys.time()
  e <- tryCatch(
    zu_resp_read(r),
    interrupt = function(e) e,
    error = function(e) e
  )
  elapsed <- as.numeric(difftime(Sys.time(), t0, units = "secs"))
  expect_s3_class(e, "zu_interrupted_error")
  # The signal lands at 0.5 s; §25.1's tick is 100 ms; 0.15 s of slack for
  # the shell and a loaded runner. It was 0.5 + 0.2 + 0.3 before #163.
  expect_lt(elapsed, 0.5 + 0.1 + 0.15)
  # The interrupted body closed its connection: one descriptor fewer.
  if (!is.na(before)) expect_lt(open_fds(), before)
})

test_that("§51.3, §65.4: 1 GiB streamed in 1 MiB pieces stays under 16 MB of RSS", {
  skip_unless_h2_server()
  skip_on_cran()
  skip_under_gctorture()
  if (!file.exists("/proc/self/status")) {
    skip("needs Linux's VmHWM")
  }
  # covr instruments every R expression, so a 65,000-read loop runs for many
  # minutes, and this test measures memory, not lines.
  if (identical(Sys.getenv("R_COVR"), "true")) {
    skip("under covr")
  }
  hwm <- function() {
    l <- grep("^VmHWM:", readLines("/proc/self/status"), value = TRUE)
    as.numeric(gsub("[^0-9]", "", l)) * 1024
  }
  base <- Sys.getenv("ZU_H2_TEST_SERVER")
  # max_body holds across a stream (§65.4), so a 1 GiB body raises it.
  api <- zu_client(
    http2 = "required",
    proxy = FALSE,
    timeout = 120,
    max_body = Inf
  )
  # A warm-up so the baseline includes what the first request allocates.
  r <- zu_perform(
    zu_request("GET", paste0(base, "/bytes?n=", sprintf("%.0f", 4 * 1024^2))),
    client = api,
    stream = TRUE
  )
  while (length(zu_resp_read(r, 1024^2))) {
    NULL
  }
  invisible(gc())
  base_hwm <- hwm()
  r <- zu_perform(
    zu_request("GET", paste0(base, "/bytes?n=", sprintf("%.0f", 1024^3))),
    client = api,
    stream = TRUE
  )
  total <- 0
  i <- 0L
  repeat {
    b <- zu_resp_read(r, 1024^2)
    if (!length(b)) {
      break
    }
    total <- total + length(b)
    rm(b)
    # Each piece is a new raw vector, and R keeps dead ones until its
    # collector runs: that is the caller's loop, not zuhttp holding the body,
    # and on Linux it alone added ~25 MB (2026-11-04). Collecting now and
    # then measures what the client holds.
    i <- i + 1L
    if (i %% 64L == 0L) invisible(gc())
  }
  expect_identical(total, 1024^3)
  delta <- hwm() - base_hwm
  cat(sprintf("\n  1 GiB streamed; peak RSS grew by %.1f MB\n", delta / 1024^2))
  expect_lt(delta, 16 * 1024^2)
})

# --- §65.8: gRPC against grpc-go's interop server, through zuhttp's own API --
#
# What zugrpc will do, by hand: a gRPC message is a 5-byte prefix (a
# compressed flag and a big-endian length) and protobuf bytes; the status is
# in the trailers. Requests are encoded here by hand, which keeps the test
# free of a protobuf dependency and shows exactly what goes on the wire.

test_that("§65.8: a unary gRPC call; the status is in the trailers", {
  skip_unless_grpc_server()
  r <- zu_post(
    "/grpc.testing.TestService/EmptyCall",
    body = grpc_frame(),
    client = grpc_client()
  )
  expect_identical(zu_resp_status(r), 200L)
  expect_identical(zu_resp_connection(r)$http_version, "HTTP/2")
  expect_identical(zu_resp_raw(r), grpc_frame())
  expect_identical(zu_resp_trailers(r, "grpc-status"), "0")
})

test_that("§65.8: an unknown method is a Trailers-Only response, not an error", {
  skip_unless_grpc_server()
  r <- zu_post(
    "/grpc.testing.TestService/NoSuchMethod",
    body = grpc_frame(),
    client = grpc_client()
  )
  expect_identical(zu_resp_status(r), 200L)
  expect_length(zu_resp_raw(r), 0L)
  # Trailers-Only: the status arrives in the one header block (§65.3).
  expect_identical(zu_resp_header(r, "grpc-status"), "12")
})

test_that("§65.8: a server-streaming gRPC call, pulled with zu_resp_read()", {
  skip_unless_grpc_server()
  # StreamingOutputCallRequest { response_parameters: [{size: 1000},
  # {size: 2000}, {size: 3000}] }: field 2, length 3, then field 1 varint.
  req <- as.raw(c(
    0x12,
    0x03,
    0x08,
    0xe8,
    0x07,
    0x12,
    0x03,
    0x08,
    0xd0,
    0x0f,
    0x12,
    0x03,
    0x08,
    0xb8,
    0x17
  ))
  r <- zu_perform(
    zu_body_raw(
      zu_request("POST", "/grpc.testing.TestService/StreamingOutputCall"),
      grpc_frame(req)
    ),
    client = grpc_client(),
    stream = TRUE
  )
  got <- raw()
  repeat {
    b <- zu_resp_read(r, 512)
    if (!length(b)) {
      break
    }
    got <- c(got, b)
  }
  msgs <- grpc_messages(got)
  expect_length(msgs, 3L)
  # Each reply carries a payload of the requested size, plus a few bytes of
  # protobuf framing around it.
  sizes <- vapply(msgs, length, integer(1))
  expect_true(all(
    sizes >= c(1000, 2000, 3000) & sizes < c(1000, 2000, 3000) + 16
  ))
  expect_identical(zu_resp_trailers(r, "grpc-status"), "0")
})

# --- W22: a streamed request body (§65.7) -------------------------------------

test_that("§65.7: a streamed body arrives whole and in order, over h2c, TLS and HTTP/1.1", {
  skip_unless_h2_server()
  base <- Sys.getenv("ZU_H2_TEST_SERVER")
  tls <- Sys.getenv("ZU_H2_TEST_TLS")
  ca <- Sys.getenv("ZU_H2_TEST_CA")
  check <- function(url, client, version) {
    req <- zu_body_stream(zu_request("POST", url), pattern_body(5e6, 65536))
    j <- zu_resp_json(zu_perform(req, client = client))
    expect_equal(j$bytes, 5e6)
    expect_true(j$ordered)
    expect_identical(j$http_version, version)
  }
  check(
    paste0(base, "/check"),
    zu_client(http2 = "required", proxy = FALSE),
    "2"
  )
  # HTTP/1.1: the one request zuhttp sends chunked (D-95).
  check(paste0(base, "/check"), zu_client(proxy = FALSE), "1.1")
  if (nzchar(tls) && nzchar(ca) && tls_supports("ca_file")) {
    check(
      paste0(tls, "/check"),
      zu_client(tls = zu_tls(ca_file = ca), proxy = FALSE),
      "2"
    )
  }
})

test_that("§65.7: an error inside the body function is re-raised, and the connection is not kept", {
  skip_unless_h2_server()
  base <- Sys.getenv("ZU_H2_TEST_SERVER")
  api <- zu_client(http2 = "required", proxy = FALSE)
  zu_get(paste0(base, "/get"), client = api) # one pooled connection
  i <- 0L
  f <- function() {
    i <<- i + 1L
    if (i == 3L) {
      stop("the generator gave up")
    }
    as.raw(rep(1, 10000))
  }
  e <- tryCatch(
    zu_perform(
      zu_body_stream(zu_request("POST", paste0(base, "/check")), f),
      client = api
    ),
    error = function(e) e
  )
  expect_false(inherits(e, "zu_error")) # the user's own condition, unchanged
  expect_match(conditionMessage(e), "the generator gave up")
  # D-47: that connection was closed, so the next request opens another.
  misses <- zu_pool_stats(api)[["misses"]]
  zu_get(paste0(base, "/get"), client = api)
  expect_identical(zu_pool_stats(api)[["misses"]], misses + 1L)
})

test_that("§28.2: a retry with a streamed body is refused before the first attempt", {
  api <- zu_client(retry = zu_retry(attempts = 3), proxy = FALSE)
  f <- pattern_body(10, 10)
  req <- zu_body_stream(
    # PUT, which is idempotent and so would be retried; a POST never is.
    zu_request("PUT", "http://127.0.0.1:9/x"),
    f
  )
  expect_error(zu_perform(req, client = api), class = "zu_body_not_replayable")
  # Before the first attempt: the function was never asked for a piece.
  expect_identical(attr(f, "calls")(), 0L)
})

test_that("§65.7: a 100 MB body from a 1 MB generator stays under 16 MB of RSS", {
  skip_unless_h2_server()
  skip_on_cran()
  skip_under_gctorture()
  if (!file.exists("/proc/self/status")) {
    skip("needs Linux's VmHWM")
  }
  if (identical(Sys.getenv("R_COVR"), "true")) {
    skip("under covr")
  }
  hwm <- function() {
    l <- grep("^VmHWM:", readLines("/proc/self/status"), value = TRUE)
    as.numeric(gsub("[^0-9]", "", l)) * 1024
  }
  base <- Sys.getenv("ZU_H2_TEST_SERVER")
  api <- zu_client(http2 = "required", proxy = FALSE, timeout = 120)
  url <- paste0(base, "/check")
  zu_perform(
    zu_body_stream(zu_request("POST", url), pattern_body(4e6, 1e6)),
    client = api
  )
  invisible(gc())
  base_hwm <- hwm()
  # Each piece is a new raw vector; collecting now and then measures what
  # the client holds rather than the caller's dead pieces (as for W21).
  inner <- pattern_body(100e6, 1e6)
  k <- 0L
  f <- function() {
    k <<- k + 1L
    if (k %% 16L == 0L) {
      invisible(gc())
    }
    inner()
  }
  j <- zu_resp_json(zu_perform(
    zu_body_stream(zu_request("POST", url), f),
    client = api
  ))
  expect_equal(j$bytes, 100e6)
  expect_true(j$ordered)
  delta <- hwm() - base_hwm
  cat(sprintf(
    "\n  100 MB uploaded; peak RSS grew by %.1f MB\n",
    delta / 1024^2
  ))
  expect_lt(delta, 16 * 1024^2)
})

test_that("§65.7: a body function cannot read or abort its own response (#155)", {
  skip_unless_grpc_server()
  # Full duplex: the function runs inside nghttp2's data provider while the
  # response is read, and nghttp2 is not re-entrant. Reading the same
  # response from inside it is refused, and the refusal reaches the caller.
  # 200 messages of 32 KiB, past the server's window, so the function is
  # still being called once the response is being read.
  # StreamingOutputCallRequest { response_parameters: [{size: 1000}],
  #   payload: Payload { body: 32 KiB } }: the server answers each message
  # as it arrives, so the response headers come before the body ends.
  msg <- grpc_frame(c(
    as.raw(c(0x12, 0x03, 0x08, 0xe8, 0x07)),
    as.raw(c(0x1a, 0x84, 0x80, 0x02, 0x12, 0x80, 0x80, 0x02)),
    as.raw(rep(7, 32768))
  ))
  st <- new.env()
  st$n <- 0L
  f <- function() {
    st$n <- st$n + 1L
    if (!is.null(st$r)) {
      zu_resp_read(st$r)
    }
    if (st$n > 200L) NULL else msg
  }
  st$r <- zu_perform(
    zu_body_stream(
      zu_request("POST", "/grpc.testing.TestService/FullDuplexCall"),
      f
    ),
    client = grpc_client(),
    stream = TRUE
  )
  expect_error(
    while (length(zu_resp_read(st$r)) > 0) {
      NULL
    },
    class = "zu_io_error",
    regexp = "inside its own request body function"
  )
})

test_that("§65.7: a body function that raises mid-stream is raised once; later reads report the failed body (#175)", {
  skip_unless_grpc_server()
  # Full duplex, as the #155 case: the function runs inside nghttp2's data
  # provider while the response is read. On its 20th call it raises. The
  # error reaches the caller from the zu_resp_read() that ran it, once; a
  # second zu_resp_read() on the same response is the failed-body error, not
  # the same continuation resumed again, which R cannot survive.
  msg <- grpc_frame(c(
    as.raw(c(0x12, 0x03, 0x08, 0xe8, 0x07)),
    as.raw(c(0x1a, 0x84, 0x80, 0x02, 0x12, 0x80, 0x80, 0x02)),
    as.raw(rep(7, 32768))
  ))
  n <- 0L
  f <- function() {
    n <<- n + 1L
    if (n == 20L) {
      stop("the body function gave up", call. = FALSE)
    }
    if (n > 200L) NULL else msg
  }
  r <- zu_perform(
    zu_body_stream(
      zu_request("POST", "/grpc.testing.TestService/FullDuplexCall"),
      f
    ),
    client = grpc_client(),
    stream = TRUE
  )
  expect_error(
    while (length(zu_resp_read(r)) > 0) {
      NULL
    },
    "the body function gave up",
    fixed = TRUE
  )
  expect_identical(n, 20L)
  # The second read, in a fresh frame: a classed error about the body.
  expect_error(zu_resp_read(r), class = "zu_io_error")
  expect_error(zu_resp_read(r), class = "zu_io_error")
})

test_that("§65.7: full duplex: the response is read while the body is still being sent", {
  skip_unless_grpc_server()
  # FullDuplexCall answers each request message as it arrives. 200 requests
  # each carry a 32 KiB payload, 6.4 MB in all, well past the server's
  # window, so the body cannot all go out before replies have to be read:
  # it goes out as zu_resp_read() pumps the connection.
  varint <- function(n) {
    out <- raw()
    repeat {
      b <- n %% 128
      n <- n %/% 128
      out <- c(out, as.raw(if (n > 0) b + 128 else b))
      if (n == 0) break
    }
    out
  }
  ld <- function(field, bytes) {
    c(as.raw(field * 8 + 2), varint(length(bytes)), bytes)
  }
  one <- function() {
    # StreamingOutputCallRequest { response_parameters: [{size: 1000}],
    #   payload: Payload { body: 32 KiB } }
    msg <- c(
      ld(2, as.raw(c(0x08, 0xe8, 0x07))),
      ld(3, ld(2, as.raw(rep(7, 32768))))
    )
    grpc_frame(msg)
  }
  sent <- 0L
  f <- function() {
    if (sent == 200L) {
      return(NULL)
    }
    sent <<- sent + 1L
    one()
  }
  r <- zu_perform(
    zu_body_stream(
      zu_request("POST", "/grpc.testing.TestService/FullDuplexCall"),
      f
    ),
    client = grpc_client(),
    stream = TRUE
  )
  expect_lt(sent, 200L) # the body is not finished when the headers are in
  got <- raw()
  repeat {
    b <- zu_resp_read(r, 65536)
    if (!length(b)) {
      break
    }
    got <- c(got, b)
  }
  expect_identical(sent, 200L)
  expect_length(grpc_messages(got), 200L)
  expect_identical(zu_resp_trailers(r, "grpc-status"), "0")
})

# The engine end to end, offline, against local servers.
#
# Written from a coverage map (2026-09-26): every behaviour below was reached
# by no suite at all — not the 1,541 ctest checks, which do not compile
# zu_engine.c or init.c, and not the R suite, where the only tests reaching
# them needed the internet. The same method, run while writing the pkgdown
# articles, found a credential leak on cross-origin redirects and four other
# engine defects (#55, #56).
#
# Two kinds of server: webfakes for well-formed HTTP, and with_raw_server()
# (helper-rawserver.R) for bytes a well-behaved server would never send.

# --- responses a real server should not send, but some do ---------------

test_that("a 1xx informational response is skipped, and its headers do not leak", {
  skip_unless_forkable()
  resp <- crlf("HTTP/1.1 103 Early Hints", "Link: </style.css>; rel=preload", "",
               "HTTP/1.1 200 OK", "Content-Length: 5", "Connection: close", "", "hello")
  with_raw_server(resp, function(base) {
    r <- zu_get(paste0(base, "/"))
    expect_identical(zu_resp_status(r), 200L)
    expect_identical(zu_resp_text(r), "hello")
    expect_length(zu_resp_header(r, "link"), 0L)
  })
})

test_that("an HTTP/1.0 response without framing is read to the close", {
  skip_unless_forkable()
  body <- strrep("x", 3000)
  with_raw_server(crlf("HTTP/1.0 200 OK", "Content-Type: text/plain", "", body),
                  function(base) {
    r <- zu_get(paste0(base, "/"))
    expect_identical(zu_resp_text(r), body)
    expect_identical(zu_resp_connection(r)$http_version, "HTTP/1.0")
  })
})

test_that("a status line that is not HTTP/1.x is a parse error", {
  skip_unless_forkable()
  with_raw_server(crlf("HTTP/2.0 200 OK", "Content-Length: 0", "", ""), function(base) {
    expect_error(zu_get(paste0(base, "/")), class = "zu_http_parse_error")
  })
})

test_that("a body shorter than its Content-Length is an error, not a short body", {
  skip_unless_forkable()
  # The server declares 100 bytes, sends 10, and closes. Returning the 10
  # would hand the caller a truncated file that looks complete.
  with_raw_server(crlf("HTTP/1.1 200 OK", "Content-Length: 100", "Connection: close",
                       "", "0123456789"), function(base) {
    e <- tryCatch(zu_get(paste0(base, "/")), error = function(e) e)
    expect_s3_class(e, "zu_http_parse_error")
    expect_identical(e$phase, "read")
  })
})

test_that("a truncated download leaves nothing at the destination (§27.1)", {
  skip_unless_forkable()
  dest <- tempfile(fileext = ".bin")
  with_raw_server(crlf("HTTP/1.1 200 OK", "Content-Length: 100", "Connection: close",
                       "", "0123456789"), function(base) {
    expect_error(zu_get(paste0(base, "/"), path = dest), class = "zu_http_parse_error")
  })
  expect_false(file.exists(dest))
  expect_length(list.files(dirname(dest), pattern = basename(dest)), 0L)
})

test_that("an unsupported Content-Encoding is a decode error; decode = FALSE keeps it", {
  skip_unless_forkable()
  resp <- crlf("HTTP/1.1 200 OK", "Content-Encoding: br", "Content-Length: 4",
               "Connection: close", "", "\x01\x02\x03\x04")
  with_raw_server(resp, function(base) {
    expect_error(zu_get(paste0(base, "/")), class = "zu_body_decode_error")
  })
  with_raw_server(resp, function(base) {
    r <- zu_get(paste0(base, "/"), decode = FALSE)
    expect_identical(zu_resp_raw(r), as.raw(1:4))
    expect_identical(zu_resp_header(r, "content-encoding"), "br")
  })
})

test_that("a chunked body larger than one read arrives whole", {
  skip_unless_forkable()
  # 300 chunks of 1,000 bytes: far more than one socket read, so the chunked
  # decoder is fed across many reads, with chunk boundaries landing mid-read.
  chunk <- strrep("abcdefghij", 100)
  body <- paste0(paste0(rep(paste0("3e8\r\n", chunk, "\r\n"), 300), collapse = ""), "0\r\n\r\n")
  resp <- paste0(crlf("HTTP/1.1 200 OK", "Transfer-Encoding: chunked",
                      "Connection: close", "", ""), body)
  with_raw_server(resp, function(base) {
    r <- zu_get(paste0(base, "/"))
    expect_identical(nchar(zu_resp_text(r)), 300000L)
    expect_identical(substr(zu_resp_text(r), 299991, 300000), "abcdefghij")
  })
})

test_that("a redirect to an unusable Location is a URL error, not a followed hop", {
  skip_unless_forkable()
  with_raw_server(crlf("HTTP/1.1 302 Found", "Location: ftp://files.example/x",
                       "Content-Length: 0", "Connection: close", "", ""), function(base) {
    expect_error(zu_get(paste0(base, "/")), class = "zu_url_error")
  })
})

test_that("with redirects = 0 the 3xx body goes to the caller's file", {
  skip_unless_forkable()
  dest <- tempfile()
  with_raw_server(crlf("HTTP/1.1 302 Found", "Location: /elsewhere",
                       "Content-Length: 5", "Connection: close", "", "moved"), function(base) {
    r <- zu_get(paste0(base, "/"), redirects = 0, path = dest)
    expect_identical(zu_resp_status(r), 302L)
    expect_identical(zu_resp_path(r), dest)
  })
  expect_identical(readLines(dest, warn = FALSE), "moved")
})

# --- against a well-behaved server ----------------------------------------

skip_if_not_installed("webfakes")
web <- webfakes::local_app_process(
  webfakes::httpbin_app(),
  opts = webfakes::server_opts(remote = TRUE, enable_keep_alive = TRUE, num_threads = 4),
  .local_envir = testthat::teardown_env()
)

test_that("a pooled connection is reused, offline, and says so", {
  api <- zu_client(base_url = web$url())
  first <- zu_get("get", client = api)
  second <- zu_get("get", client = api)
  third <- zu_get("get", client = api)
  st <- zu_pool_stats(api)
  expect_identical(st[["misses"]], 1)
  expect_identical(st[["hits"]], 2)
  expect_false(zu_resp_connection(first)$reused_connection)
  expect_true(zu_resp_connection(third)$reused_connection)
  # A reused connection had no DNS or connect phase: NA, not zero (§35.1).
  expect_true(is.na(zu_resp_timings(second)[["dns"]]))
  expect_false(is.na(zu_resp_timings(first)[["dns"]]))
})

test_that("a reused connection reads slow chunked bodies, before and after a callback", {
  # A pooled stream keeps the zu_net_opts of the request that opened it, so
  # anything per-request stored there is stale on reuse. /stream sends its
  # chunks with pauses, which makes every read wait on the poll tick — the
  # path where a stale tick context was read (a regression caught while
  # writing this file, 2026-09-26).
  api <- zu_client(base_url = web$url())
  expect_identical(zu_resp_status(zu_get("stream/3", client = api)), 200L)
  expect_identical(zu_resp_status(zu_get("stream/3", client = api)), 200L)
  r <- zu_get("stream/3", client = api, callback = function(chunk) TRUE)
  expect_identical(zu_resp_status(r), 200L)
  r <- zu_get("stream/3", client = api)
  expect_length(strsplit(zu_resp_text(r), "\n")[[1]], 3L)
  expect_gte(zu_pool_stats(api)[["hits"]], 3)
})

test_that("a callback sees every chunk, in order", {
  got <- raw()
  calls <- 0L
  r <- zu_get(web$url("/drip?numbytes=5&duration=0.5"), callback = function(chunk) {
    calls <<- calls + 1L
    got <<- c(got, chunk)
    TRUE
  })
  expect_identical(zu_resp_status(r), 200L)
  expect_gte(calls, 2L)
  expect_identical(length(got), 5L)
  expect_length(zu_resp_raw(r), 0L)   # delivered, not kept
})

test_that("a callback returning FALSE stops early, and the connection is not reused", {
  api <- zu_client(base_url = web$url())
  calls <- 0L
  r <- zu_get("drip?numbytes=10&duration=1", client = api, callback = function(chunk) {
    calls <<- calls + 1L
    FALSE
  })
  expect_identical(calls, 1L)
  expect_identical(zu_resp_status(r), 200L)
  # The body was not read to its end, so the framing position is unknown and
  # the connection must be discarded rather than pooled (§26.3).
  invisible(zu_get("get", client = api))
  expect_identical(zu_pool_stats(api)[["hits"]], 0)
})

test_that("an error in a callback reaches the caller as that error", {
  # §27.3: the user's condition, with its own class, not a zuhttp one that
  # has swallowed it.
  api <- zu_client(base_url = web$url())
  e <- tryCatch(
    zu_get("stream/5", client = api, callback = function(chunk) {
      stop(structure(class = c("my_parse_error", "error", "condition"),
                     list(message = "bad record", call = NULL)))
    }),
    error = function(e) e)
  expect_s3_class(e, "my_parse_error")
  expect_false(inherits(e, "zu_error"))
  expect_identical(conditionMessage(e), "bad record")
  # The session is fine and the pool did not keep the half-read connection.
  expect_identical(zu_resp_status(zu_get("get", client = api)), 200L)
  expect_identical(zu_pool_stats(api)[["hits"]], 0)
})

test_that("a warning inside a callback does not abort the transfer (D-47)", {
  n <- 0L
  r <- withCallingHandlers(
    zu_get(web$url("/stream/3"), callback = function(chunk) {
      warning("just saying"); TRUE
    }),
    warning = function(w) { n <<- n + 1L; invokeRestart("muffleWarning") })
  expect_identical(zu_resp_status(r), 200L)
  expect_gte(n, 1L)
})

test_that("proxy = FALSE ignores a proxy in the environment, offline", {
  withr_local_env <- function(...) {
    old <- Sys.getenv(names(list(...)), unset = NA)
    do.call(Sys.setenv, list(...))
    old
  }
  old <- withr_local_env(http_proxy = "http://127.0.0.1:9")   # refuses
  on.exit(if (is.na(old)) Sys.unsetenv("http_proxy") else Sys.setenv(http_proxy = old))
  expect_error(zu_get(web$url("/get")), class = "zu_connect_error")
  r <- zu_get(web$url("/get"), proxy = FALSE)
  expect_identical(zu_resp_status(r), 200L)
  expect_false(zu_resp_connection(r)$proxy_used)
})

test_that("a name that does not resolve is a DNS error", {
  e <- tryCatch(zu_get("http://zuhttp-test.invalid/"), error = function(e) e)
  expect_s3_class(e, "zu_dns_error")
  expect_identical(e$phase, "dns")
})

test_that("a time limit during a request surfaces as itself (§25.2)", {
  # setTimeLimit() -- and R.utils::withTimeout(), built on it -- raises its
  # error from inside R_CheckUserInterrupt(), the checkpoint the engine calls
  # every poll tick. Until 2026-09-26 that checkpoint ran under
  # R_ToplevelExec, which printed the error, dropped it, and reported
  # "request interrupted by the user"; withTimeout() never saw its error.
  api <- zu_client(base_url = web$url())
  t0 <- Sys.time()
  e <- tryCatch({
    setTimeLimit(elapsed = 1, transient = TRUE)
    zu_get("delay/5", client = api)
  }, error = function(e) e)
  setTimeLimit(elapsed = Inf)
  expect_false(inherits(e, "zu_error"))
  expect_match(conditionMessage(e), "elapsed time limit")
  expect_lt(as.numeric(difftime(Sys.time(), t0, units = "secs")), 3)
  # The engine unwound through its own cleanup: the client still works.
  expect_identical(zu_resp_status(zu_get("get", client = api)), 200L)
})

test_that("Ctrl-C (SIGINT) cancels within the 200 ms bound (§25, #7)", {
  # A deterministic Ctrl-C: a background shell sends SIGINT to this R process
  # while a request waits on a server that will not answer for five seconds.
  # This measures the Rscript front end; Rgui and RStudio deliver interrupts
  # differently and stay a manual measurement (W11).
  skip_on_os("windows")
  u <- web$url("/delay/5")
  system(sprintf("sh -c 'sleep 0.5; kill -INT %d' >/dev/null 2>&1 &", Sys.getpid()))
  t0 <- Sys.time()
  e <- tryCatch(zu_get(u), interrupt = function(e) e, error = function(e) e)
  elapsed <- as.numeric(difftime(Sys.time(), t0, units = "secs"))
  expect_s3_class(e, "zu_interrupted_error")
  expect_lt(elapsed, 0.5 + 0.2 + 0.3)   # the signal, the bound, scheduling slack
  expect_identical(zu_resp_status(zu_get(web$url("/get"))), 200L)
})

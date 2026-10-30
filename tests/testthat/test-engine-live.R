# The engine end to end, offline, against local servers.
#
# Written from a coverage map (2026-09-26): every behaviour below was reached
# by no suite at all — not the 1,541 ctest checks, which do not compile
# zuh_engine.c or init.c, and not the R suite, where the only tests reaching
# them needed the internet. The same method, run while writing the pkgdown
# articles, found a credential leak on cross-origin redirects and four other
# engine defects (#55, #56).
#
# Two kinds of server: webfakes for well-formed HTTP, and with_raw_server()
# (helper-rawserver.R) for bytes a well-behaved server would never send.

# --- responses a real server should not send, but some do ---------------

test_that("a 1xx informational response is skipped, and its headers do not leak", {
  skip_unless_forkable()
  resp <- crlf(
    "HTTP/1.1 103 Early Hints",
    "Link: </style.css>; rel=preload",
    "",
    "HTTP/1.1 200 OK",
    "Content-Length: 5",
    "Connection: close",
    "",
    "hello"
  )
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
  with_raw_server(
    crlf("HTTP/1.0 200 OK", "Content-Type: text/plain", "", body),
    function(base) {
      r <- zu_get(paste0(base, "/"))
      expect_identical(zu_resp_text(r), body)
      expect_identical(zu_resp_connection(r)$http_version, "HTTP/1.0")
    }
  )
})

test_that("a truncated gzip body is an error, and a download keeps the old file (D-76)", {
  skip_unless_forkable()
  # 30 bytes of a gzip stream that decodes to 10,000: the header and a little
  # deflate data, under an accurate Content-Length. This returned a complete,
  # empty 200 and replaced the destination with an empty file.
  gz <- memCompress(charToRaw(strrep("abcdefghij", 1000)), "gzip")
  gz <- c(
    as.raw(c(0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0x03)),
    gz[-c(1:2, length(gz) - 0:3)],
    as.raw(rep(0, 8))
  ) # zlib -> gzip
  head <- charToRaw(crlf(
    "HTTP/1.1 200 OK",
    "Content-Encoding: gzip",
    "Content-Length: 30",
    "Connection: close",
    "",
    ""
  ))
  dest <- tempfile()
  writeLines("PRECIOUS", dest)
  on.exit(unlink(dest), add = TRUE)
  with_raw_server(c(head, gz[1:30]), function(base) {
    expect_error(
      zu_get(paste0(base, "/"), path = dest),
      class = "zu_body_decode_error"
    )
  })
  expect_identical(readLines(dest), "PRECIOUS")
})

test_that("a status line that is not HTTP/1.x is a parse error", {
  skip_unless_forkable()
  with_raw_server(
    crlf("HTTP/2.0 200 OK", "Content-Length: 0", "", ""),
    function(base) {
      expect_error(zu_get(paste0(base, "/")), class = "zu_http_parse_error")
    }
  )
})

test_that("a header value that is not UTF-8 arrives as Latin-1, not as broken UTF-8 (D-84)", {
  skip_unless_forkable()
  # "café" with a Latin-1 é (0xE9), the common case of a Content-Disposition
  # filename. Marked UTF-8, it made nchar(), grepl() and print() fail.
  resp <- c(
    charToRaw("HTTP/1.1 200 OK\r\nX-Name: caf"),
    as.raw(0xE9),
    charToRaw(
      "\r\nX-Utf8: caf\u00e9\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
    )
  )
  with_raw_server(resp, function(base) {
    r <- zu_get(paste0(base, "/"))
    latin <- zu_resp_header(r, "x-name")
    expect_identical(Encoding(latin), "latin1")
    expect_identical(nchar(latin), 4L)
    expect_identical(enc2utf8(latin), "caf\u00e9")
    expect_true(grepl("caf", latin))
    # valid UTF-8 is still marked UTF-8
    utf <- zu_resp_header(r, "x-utf8")
    expect_identical(Encoding(utf), "UTF-8")
    expect_identical(utf, "caf\u00e9")
    expect_no_warning(capture.output(print(r)))
  })
})

test_that("the default User-Agent carries the package version, and Connection follows the pool (§17.2)", {
  skip_unless_forkable()
  ok <- crlf(
    "HTTP/1.1 200 OK",
    "Content-Length: 2",
    "Connection: close",
    "",
    "ok"
  )
  seen <- with_raw_server(ok, function(base) {
    zu_get(paste0(base, "/"), client = zu_client(pool = NULL))
  })
  skip_if(is.null(seen), "the raw test server recorded nothing")
  expect_match(
    seen,
    paste0("User-Agent: zuhttp/", packageVersion("zuhttp"), "\r\n"),
    fixed = TRUE
  )
  # no pool: the connection is closed after the response, and the request says so
  expect_match(seen, "Connection: close\r\n", fixed = TRUE)

  seen <- with_raw_server(ok, function(base) {
    zu_get(paste0(base, "/"), user_agent = "mine/1", client = zu_client())
  })
  skip_if(is.null(seen), "the raw test server recorded nothing")
  expect_match(seen, "User-Agent: mine/1\r\n", fixed = TRUE)
  expect_match(seen, "Connection: keep-alive\r\n", fixed = TRUE)
})

test_that("a body shorter than its Content-Length is an error, not a short body", {
  skip_unless_forkable()
  # The server declares 100 bytes, sends 10, and closes. Returning the 10
  # would hand the caller a truncated file that looks complete.
  with_raw_server(
    crlf(
      "HTTP/1.1 200 OK",
      "Content-Length: 100",
      "Connection: close",
      "",
      "0123456789"
    ),
    function(base) {
      e <- tryCatch(zu_get(paste0(base, "/")), error = function(e) e)
      expect_s3_class(e, "zu_http_parse_error")
      expect_identical(e$phase, "read")
    }
  )
})

test_that("a truncated download leaves nothing at the destination (§27.1)", {
  skip_unless_forkable()
  dest <- tempfile(fileext = ".bin")
  with_raw_server(
    crlf(
      "HTTP/1.1 200 OK",
      "Content-Length: 100",
      "Connection: close",
      "",
      "0123456789"
    ),
    function(base) {
      expect_error(
        zu_get(paste0(base, "/"), path = dest),
        class = "zu_http_parse_error"
      )
    }
  )
  expect_false(file.exists(dest))
  expect_length(list.files(dirname(dest), pattern = basename(dest)), 0L)
})

test_that("an unsupported Content-Encoding is a decode error; decode = FALSE keeps it", {
  skip_unless_forkable()
  resp <- crlf(
    "HTTP/1.1 200 OK",
    "Content-Encoding: br",
    "Content-Length: 4",
    "Connection: close",
    "",
    "\x01\x02\x03\x04"
  )
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
  body <- paste0(
    paste0(rep(paste0("3e8\r\n", chunk, "\r\n"), 300), collapse = ""),
    "0\r\n\r\n"
  )
  resp <- paste0(
    crlf(
      "HTTP/1.1 200 OK",
      "Transfer-Encoding: chunked",
      "Connection: close",
      "",
      ""
    ),
    body
  )
  with_raw_server(resp, function(base) {
    r <- zu_get(paste0(base, "/"))
    expect_identical(nchar(zu_resp_text(r)), 300000L)
    expect_identical(substr(zu_resp_text(r), 299991, 300000), "abcdefghij")
  })
})

test_that("a redirect to an unusable Location is a URL error, not a followed hop", {
  skip_unless_forkable()
  with_raw_server(
    crlf(
      "HTTP/1.1 302 Found",
      "Location: ftp://files.example/x",
      "Content-Length: 0",
      "Connection: close",
      "",
      ""
    ),
    function(base) {
      expect_error(zu_get(paste0(base, "/")), class = "zu_url_error")
    }
  )
})

test_that("with redirects = 0 the 3xx body goes to the caller's file", {
  skip_unless_forkable()
  dest <- tempfile()
  with_raw_server(
    crlf(
      "HTTP/1.1 302 Found",
      "Location: /elsewhere",
      "Content-Length: 5",
      "Connection: close",
      "",
      "moved"
    ),
    function(base) {
      r <- zu_get(paste0(base, "/"), redirects = 0, path = dest)
      expect_identical(zu_resp_status(r), 302L)
      expect_identical(zu_resp_path(r), dest)
    }
  )
  expect_identical(readLines(dest, warn = FALSE), "moved")
})

# --- against a well-behaved server ----------------------------------------

# local_httpbin() (helper-origin.R) starts one keep-alive httpbin for these,
# on first use, and skips under gctorture or without webfakes.

test_that("a pooled connection is reused, offline, and says so", {
  web <- local_httpbin("keep-alive", keep_alive = TRUE)
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
  web <- local_httpbin("keep-alive", keep_alive = TRUE)
  # A pooled stream keeps the zuh_net_opts of the request that opened it, so
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
  web <- local_httpbin("keep-alive", keep_alive = TRUE)
  got <- raw()
  calls <- 0L
  r <- zu_get(
    web$url("/drip?numbytes=5&duration=0.5"),
    callback = function(chunk) {
      calls <<- calls + 1L
      got <<- c(got, chunk)
      TRUE
    }
  )
  expect_identical(zu_resp_status(r), 200L)
  expect_gte(calls, 2L)
  expect_identical(length(got), 5L)
  expect_length(zu_resp_raw(r), 0L) # delivered, not kept
})

test_that("a callback returning FALSE stops early, and the connection is not reused", {
  web <- local_httpbin("keep-alive", keep_alive = TRUE)
  api <- zu_client(base_url = web$url())
  calls <- 0L
  r <- zu_get(
    "drip?numbytes=10&duration=1",
    client = api,
    callback = function(chunk) {
      calls <<- calls + 1L
      FALSE
    }
  )
  expect_identical(calls, 1L)
  expect_identical(zu_resp_status(r), 200L)
  # The body was not read to its end, so the framing position is unknown and
  # the connection must be discarded rather than pooled (§26.3).
  invisible(zu_get("get", client = api))
  expect_identical(zu_pool_stats(api)[["hits"]], 0)
})

test_that("an error in a callback reaches the caller as that error", {
  web <- local_httpbin("keep-alive", keep_alive = TRUE)
  # §27.3: the user's condition, with its own class, not a zuhttp one that
  # has swallowed it.
  api <- zu_client(base_url = web$url())
  e <- tryCatch(
    zu_get("stream/5", client = api, callback = function(chunk) {
      stop(structure(
        class = c("my_parse_error", "error", "condition"),
        list(message = "bad record", call = NULL)
      ))
    }),
    error = function(e) e
  )
  expect_s3_class(e, "my_parse_error")
  expect_false(inherits(e, "zu_error"))
  expect_identical(conditionMessage(e), "bad record")
  # The session is fine and the pool did not keep the half-read connection.
  expect_identical(zu_resp_status(zu_get("get", client = api)), 200L)
  expect_identical(zu_pool_stats(api)[["hits"]], 0)
})

test_that("a warning inside a callback does not abort the transfer (D-47)", {
  web <- local_httpbin("keep-alive", keep_alive = TRUE)
  n <- 0L
  r <- withCallingHandlers(
    zu_get(web$url("/stream/3"), callback = function(chunk) {
      warning("just saying")
      TRUE
    }),
    warning = function(w) {
      n <<- n + 1L
      invokeRestart("muffleWarning")
    }
  )
  expect_identical(zu_resp_status(r), 200L)
  expect_gte(n, 1L)
})

test_that("proxy = FALSE ignores a proxy in the environment, offline", {
  web <- local_httpbin("keep-alive", keep_alive = TRUE)
  withr_local_env <- function(...) {
    old <- Sys.getenv(names(list(...)), unset = NA)
    do.call(Sys.setenv, list(...))
    old
  }
  old <- withr_local_env(http_proxy = "http://127.0.0.1:9") # refuses
  on.exit(
    if (is.na(old)) Sys.unsetenv("http_proxy") else Sys.setenv(http_proxy = old)
  )
  expect_error(zu_get(web$url("/get")), class = "zu_connect_error")
  r <- zu_get(web$url("/get"), proxy = FALSE)
  expect_identical(zu_resp_status(r), 200L)
  expect_false(zu_resp_connection(r)$proxy_used)
})

test_that("a name that does not resolve is a DNS error", {
  # A resolver lookup, which on a CRAN machine may be slow or intercepted.
  skip_on_cran()
  e <- tryCatch(zu_get("http://zuhttp-test.invalid/"), error = function(e) e)
  expect_s3_class(e, "zu_dns_error")
  expect_identical(e$phase, "dns")
})

test_that("a time limit during a request surfaces as itself (§25.2)", {
  skip_on_cran() # a wall-clock bound, on a machine CRAN shares
  web <- local_httpbin("keep-alive", keep_alive = TRUE)
  # setTimeLimit() -- and R.utils::withTimeout(), built on it -- raises its
  # error from inside R_CheckUserInterrupt(), the checkpoint the engine calls
  # every poll tick. Until 2026-09-26 that checkpoint ran under
  # R_ToplevelExec, which printed the error, dropped it, and reported
  # "request interrupted by the user"; withTimeout() never saw its error.
  api <- zu_client(base_url = web$url())
  t0 <- Sys.time()
  e <- tryCatch(
    {
      setTimeLimit(elapsed = 1, transient = TRUE)
      zu_get("delay/5", client = api)
    },
    error = function(e) e
  )
  setTimeLimit(elapsed = Inf)
  expect_false(inherits(e, "zu_error"))
  expect_match(conditionMessage(e), "elapsed time limit")
  expect_lt(as.numeric(difftime(Sys.time(), t0, units = "secs")), 3)
  # The engine unwound through its own cleanup: the client still works.
  expect_identical(zu_resp_status(zu_get("get", client = api)), 200L)
})

test_that("Ctrl-C (SIGINT) cancels within the 200 ms bound (§25, #7)", {
  # Off CRAN: it signals the checking R process itself, and a kill that lands
  # outside the request would abort the whole run rather than one test.
  skip_on_cran()
  web <- local_httpbin("keep-alive", keep_alive = TRUE)
  # A deterministic Ctrl-C: a background shell sends SIGINT to this R process
  # while a request waits on a server that will not answer for five seconds.
  # This measures the Rscript front end; Rgui and RStudio deliver interrupts
  # differently and stay a manual measurement (W11).
  skip_on_os("windows")
  u <- web$url("/delay/5")
  system(sprintf(
    "sh -c 'sleep 0.5; kill -INT %d' >/dev/null 2>&1 &",
    Sys.getpid()
  ))
  t0 <- Sys.time()
  e <- tryCatch(zu_get(u), interrupt = function(e) e, error = function(e) e)
  elapsed <- as.numeric(difftime(Sys.time(), t0, units = "secs"))
  expect_s3_class(e, "zu_interrupted_error")
  expect_lt(elapsed, 0.5 + 0.2 + 0.3) # the signal, the bound, scheduling slack
  expect_identical(zu_resp_status(zu_get(web$url("/get"))), 200L)
})

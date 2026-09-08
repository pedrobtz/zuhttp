# S10 — §20 proxy support, from R.
#
# The §20.1 and §20.2 rules are table-tested in C (ctest/test_proxy.c, 36
# cases). What could not be tested there is whether the ENGINE actually
# routes through a proxy: absolute-form for plain HTTP, CONNECT for HTTPS,
# and the §20.4 rule that a credential never reaches an origin.
#
# So this file runs a real, minimal proxy in a helper process. Offline, on
# loopback, one connection, then it exits. That is enough to observe the exact
# bytes the engine sent to the proxy — which is the only way to assert
# "absolute-form" or "Proxy-Authorization was present" rather than to infer it
# from the fact that a request succeeded.

skip_unless_forkable <- function() {
  testthat::skip_on_cran()
  if (.Platform$OS.type != "unix") skip("the helper proxy uses POSIX shell")
  if (!nzchar(Sys.which("Rscript"))) skip("Rscript not on PATH")
}

# Starts the proxy, runs `code`, and returns the request bytes it received.
# `mode` is what the proxy replies: "ok", "407" or "502".
with_fake_proxy <- function(mode, code) {
  d <- tempfile("zu-proxy-"); dir.create(d)
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  script <- file.path(d, "proxy.R")
  logf   <- file.path(d, "seen.bin")
  readyf <- file.path(d, "ready")
  port   <- sample(20000:59000, 1L)

  writeLines(c(
    "args <- commandArgs(TRUE)",
    "port <- as.integer(args[1]); mode <- args[2]; logf <- args[3]; readyf <- args[4]",
    "srv <- serverSocket(port)",
    "cat('ready\\n', file = readyf)",
    "con <- socketAccept(srv, open = 'r+b', timeout = 20)",
    # Read to the end of the header block. Byte at a time is slow and fine:
    # the request is a few hundred bytes and the alternative is guessing how
    # much has arrived.
    "buf <- raw()",
    "repeat {",
    "  b <- readBin(con, 'raw', 1L)",
    "  if (length(b) == 0L) break",
    "  buf <- c(buf, b); n <- length(buf)",
    "  if (n >= 4L && identical(buf[(n-3L):n], charToRaw('\\r\\n\\r\\n'))) break",
    "}",
    "f <- file(logf, 'wb'); writeBin(buf, f); close(f)",
    "resp <- switch(mode,",
    "  ok  = 'HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nhi',",
    "  `407` = 'HTTP/1.1 407 Proxy Authentication Required\\r\\nContent-Length: 0\\r\\nConnection: close\\r\\n\\r\\n',",
    "  'HTTP/1.1 502 Bad Gateway\\r\\nContent-Length: 0\\r\\nConnection: close\\r\\n\\r\\n')",
    "writeBin(charToRaw(resp), con); flush(con)",
    "close(con); close(srv)"
  ), script)

  system2("sh", c("-c", shQuote(sprintf("exec Rscript %s %d %s %s %s",
                                        script, port, mode, logf, readyf))),
          wait = FALSE, stdout = NULL, stderr = NULL)

  deadline <- Sys.time() + 20
  while (!file.exists(readyf) && Sys.time() < deadline) Sys.sleep(0.05)
  if (!file.exists(readyf)) skip("the helper proxy did not start")
  Sys.sleep(0.2)

  code(sprintf("http://127.0.0.1:%d", port))

  deadline <- Sys.time() + 10
  while (!file.exists(logf) && Sys.time() < deadline) Sys.sleep(0.05)
  if (!file.exists(logf)) return(NULL)
  rawToChar(readBin(logf, "raw", file.size(logf)))
}

# --- §20.1 / §20.2 resolution (offline, no proxy needed) -----------------

test_that("proxy = FALSE forces a direct connection, NULL consults the env", {
  # The three states are genuinely three (D-48). NULL cannot mean "disabled",
  # because §31.9 already gives NULL the meaning "reset to the package
  # default" for every other policy argument.
  expect_null(zu_client()$proxy)
  expect_false(zu_client(proxy = FALSE)$proxy)
  expect_identical(zu_client(proxy = "http://p:3128")$proxy, "http://p:3128")
})

test_that("a bogus proxy in the environment is actually used, and FALSE escapes it", {
  testthat::skip_on_cran()
  testthat::skip_if_offline()
  old <- Sys.getenv("http_proxy", unset = NA)
  on.exit(if (is.na(old)) Sys.unsetenv("http_proxy") else
            Sys.setenv(http_proxy = old), add = TRUE)

  # Port 9 (discard) refuses, so reaching it proves the request went to the
  # proxy rather than to the origin.
  Sys.setenv(http_proxy = "http://127.0.0.1:9")
  expect_error(zu_get("http://example.com", timeout = 5),
               class = "zu_connect_error")
  expect_identical(zu_resp_status(zu_get("http://example.com", proxy = FALSE)), 200L)
})

test_that("NO_PROXY takes a host out of the proxy's path", {
  testthat::skip_on_cran()
  testthat::skip_if_offline()
  old_p <- Sys.getenv("http_proxy", unset = NA)
  old_n <- Sys.getenv("no_proxy", unset = NA)
  on.exit({
    if (is.na(old_p)) Sys.unsetenv("http_proxy") else Sys.setenv(http_proxy = old_p)
    if (is.na(old_n)) Sys.unsetenv("no_proxy") else Sys.setenv(no_proxy = old_n)
  }, add = TRUE)

  Sys.setenv(http_proxy = "http://127.0.0.1:9", no_proxy = "example.com")
  expect_identical(zu_resp_status(zu_get("http://example.com")), 200L)
})

# --- §20.3 request forms, observed at the proxy --------------------------

test_that("plain HTTP through a proxy uses absolute-form (§20.3)", {
  skip_unless_forkable()
  seen <- with_fake_proxy("ok", function(px) {
    r <- zu_get("http://target.example/some/path?q=1", proxy = px, timeout = 15,
                check = FALSE)
    expect_identical(zu_resp_status(r), 200L)
  })
  skip_if(is.null(seen), "the helper proxy recorded nothing")

  # The request line carries the whole origin, which is how the proxy knows
  # where to forward. Origin-form here would be a request the proxy cannot
  # route.
  expect_match(seen, "^GET http://target\\.example/some/path\\?q=1 HTTP/1\\.1\r\n")
  expect_match(seen, "Host: target\\.example")
})

test_that("proxy credentials go to the proxy and are not in the URL (§20.4)", {
  skip_unless_forkable()
  seen <- with_fake_proxy("ok", function(px) {
    # Credentials in the proxy URL, percent-encoded, as a corporate proxy
    # config usually supplies them.
    auth_px <- sub("^http://", "http://user:p%40ss@", px)
    r <- zu_get("http://target.example/x", proxy = auth_px, timeout = 15,
                check = FALSE)
    expect_identical(zu_resp_status(r), 200L)
  })
  skip_if(is.null(seen), "the helper proxy recorded nothing")

  # base64("user:p@ss") — the %40 must have been decoded before encoding, or
  # the proxy authenticates as the literal "p%40ss".
  expect_match(seen, "Proxy-Authorization: Basic dXNlcjpwQHNz", fixed = TRUE)
  # ...and the credential is nowhere in the request line.
  expect_false(grepl("user:", strsplit(seen, "\r\n")[[1]][1], fixed = TRUE))
})

test_that("the request line never carries proxy credentials or origin userinfo", {
  skip_unless_forkable()
  seen <- with_fake_proxy("ok", function(px) {
    auth_px <- sub("^http://", "http://user:secret@", px)
    invisible(zu_get("http://u:pw@target.example/x", proxy = auth_px,
                     timeout = 15, check = FALSE))
  })
  skip_if(is.null(seen), "the helper proxy recorded nothing")

  line <- strsplit(seen, "\r\n")[[1]][1]
  # §20.3: absolute-form "never includes userinfo" — neither the origin's nor
  # the proxy's. An '@' in the request line would mean one of them leaked.
  expect_false(grepl("@", line, fixed = TRUE))
  expect_false(grepl("secret", seen, fixed = TRUE))
  expect_false(grepl("pw", line, fixed = TRUE))
})

# --- §20.3 CONNECT failures ----------------------------------------------

test_that("a 407 CONNECT is zu_proxy_auth_error, not a generic failure", {
  skip_unless_forkable()
  seen <- with_fake_proxy("407", function(px) {
    e <- tryCatch(zu_get("https://target.example/x", proxy = px, timeout = 15),
                  condition = function(e) e)
    expect_s3_class(e, "zu_proxy_auth_error")
    expect_s3_class(e, "zu_proxy_error")
    expect_match(conditionMessage(e), "407")
  })
  skip_if(is.null(seen), "the helper proxy recorded nothing")
  # HTTPS tunnels: the proxy sees CONNECT with an authority, not a path, and
  # emphatically not the TLS bytes.
  expect_match(seen, "^CONNECT target\\.example:443 HTTP/1\\.1\r\n")
})

test_that("a non-2xx CONNECT surfaces the proxy's own status (§20.3)", {
  skip_unless_forkable()
  invisible(with_fake_proxy("502", function(px) {
    e <- tryCatch(zu_get("https://target.example/x", proxy = px, timeout = 15),
                  condition = function(e) e)
    expect_s3_class(e, "zu_proxy_error")
    expect_false(inherits(e, "zu_proxy_auth_error"))
    # In a corporate environment the proxy's status is frequently the only
    # diagnostic the user gets, so flattening it into "connection failed"
    # would remove the one useful piece of information.
    expect_match(conditionMessage(e), "502")
  }))
})

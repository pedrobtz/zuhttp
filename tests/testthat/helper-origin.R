# A loopback origin that redirects once, for §35.3's redirect.followed event.
#
# The engine is not in ctest's offline source list, so its redirect path is
# only reachable through a real socket. That is an argument for a local
# server, not for a network test: pointing the assertion at github.com made it
# conditional on a third party choosing to redirect, and the
# skip("github did not redirect") arm turned an unexercised path into a green
# tick — which is exactly the shape §50 warns about.
#
# Accepts exactly twice: 302 to `target`, then 200. Both replies close the
# connection, so each hop opens its own whatever the pool is doing.

with_redirect_origin <- function(code, target_query = "") {
  skip_unless_forkable()          # defined in helper-proxy.R; same constraints
  d <- tempfile("zu-origin-"); dir.create(d)
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  script <- file.path(d, "origin.R")
  readyf <- file.path(d, "ready")
  port   <- sample(20000:59000, 1L)
  target <- sprintf("http://127.0.0.1:%d/final%s", port, target_query)

  writeLines(c(
    "args <- commandArgs(TRUE)",
    "port <- as.integer(args[1]); target <- args[2]; readyf <- args[3]",
    "srv <- serverSocket(port)",
    "cat('ready\\n', file = readyf)",
    "for (hop in 1:2) {",
    "  con <- socketAccept(srv, blocking = TRUE, open = 'r+b', timeout = 20)",
    # Byte at a time to the end of the header block: slow and fine for a few
    # hundred bytes, and the alternative is guessing how much has arrived.
    "  buf <- raw()",
    "  repeat {",
    "    b <- readBin(con, 'raw', 1L)",
    "    if (length(b) == 0L) break",
    "    buf <- c(buf, b); n <- length(buf)",
    "    if (n >= 4L && identical(buf[(n-3L):n], charToRaw('\\r\\n\\r\\n'))) break",
    "  }",
    "  resp <- if (hop == 1L)",
    "    paste0('HTTP/1.1 302 Found\\r\\nLocation: ', target,",
    "           '\\r\\nContent-Length: 0\\r\\nConnection: close\\r\\n\\r\\n')",
    "  else 'HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nhi'",
    "  writeBin(charToRaw(resp), con); flush(con)",
    "  close(con)",
    "}",
    "close(srv)"
  ), script)

  system2("sh", c("-c", shQuote(sprintf("exec Rscript %s %d %s %s",
                                        script, port, shQuote(target), readyf))),
          wait = FALSE, stdout = NULL, stderr = NULL)

  deadline <- Sys.time() + 20
  while (!file.exists(readyf) && Sys.time() < deadline) Sys.sleep(0.05)
  if (!file.exists(readyf)) skip("the loopback origin did not start")
  Sys.sleep(0.2)

  code(sprintf("http://127.0.0.1:%d/start", port), target)
}

# A webfakes httpbin in a background process, started on first use and then
# shared by every test that asks for the same `name` — one per session, not
# one per file. A function rather than a file-level object so the tests that
# use it run in any order (devtools::test(shuffle = TRUE)), and so the skips
# that belong to it travel with it: a top-level skip in a shuffled file skips
# whatever happens to come after it.
#
# A server that fails to start is a skip that says so. It is not what any
# test here exists to detect, and under load callr's "Could not start R
# session, timed out" surfaced as an error in whichever test came first.
local_httpbin <- local({
  servers <- list()
  function(name = "plain", keep_alive = FALSE) {
    skip_under_gctorture()   # local servers: timing, not memory
    testthat::skip_if_not_installed("webfakes")
    srv <- servers[[name]]
    if (is.null(srv) || !identical(srv$get_state(), "live")) {
      opts <- if (keep_alive)
        webfakes::server_opts(remote = TRUE, enable_keep_alive = TRUE, num_threads = 4)
      else webfakes::server_opts()
      srv <- tryCatch(
        webfakes::local_app_process(webfakes::httpbin_app(), opts = opts,
                                    .local_envir = testthat::teardown_env()),
        error = function(e)
          testthat::skip(paste("the local httpbin did not start:", conditionMessage(e))))
      servers[[name]] <<- srv
    }
    srv
  }
})

# For test-redirect-live.R: a URL on `from` that redirects to `to`. The target
# is percent-encoded by hand: webfakes' url(query = ) does not encode, and a
# nested ?url= would otherwise be split at the wrong '='.
redirect_to <- function(from, to, status_code = NULL) {
  paste0(from$url("/redirect-to"), "?url=", utils::URLencode(to, reserved = TRUE, repeated = TRUE),
         if (!is.null(status_code)) paste0("&status_code=", status_code))
}

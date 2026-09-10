# A minimal HTTP proxy in a helper process, for §20.3.
#
# Shared between test-proxy.R and test-info.R rather than defined in one and
# copied into the other. It exists because the only way to assert "the request
# line was absolute-form" or "Proxy-Authorization was present and confined to
# the proxy" is to look at the bytes the engine actually sent — inferring it
# from a request having succeeded proves nothing about either.

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


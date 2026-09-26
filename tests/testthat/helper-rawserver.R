# A one-connection HTTP server that replies with exact bytes.
#
# webfakes (helper-free in the tests that use it) can only send well-formed
# HTTP. The engine's framing, status-line and informational-response paths
# are about what happens when a server sends something else — a body shorter
# than its Content-Length, an HTTP/2.0 status line, a 103 before the 200 —
# and the only way to test those end to end is a server that writes exactly
# what the test says. Same shape as helper-proxy.R: Rscript in a child
# process, loopback, one connection, then it exits.

# `response` is a character string (sent as its UTF-8 bytes) or a raw vector.
# `code` receives the server's base URL; the request bytes the server saw are
# returned, or NULL if it recorded nothing.
with_raw_server <- function(response, code) {
  skip_unless_forkable()
  d <- tempfile("zu-raw-"); dir.create(d)
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  script <- file.path(d, "server.R")
  respf  <- file.path(d, "response.bin")
  logf   <- file.path(d, "seen.bin")
  readyf <- file.path(d, "ready")
  if (is.character(response)) response <- charToRaw(enc2utf8(response))
  writeBin(response, respf)

  writeLines(c(
    "args <- commandArgs(TRUE)",
    "port <- as.integer(args[1]); respf <- args[2]; logf <- args[3]; readyf <- args[4]",
    "srv <- serverSocket(port)",
    "cat('ready\\n', file = readyf)",
    "con <- socketAccept(srv, open = 'r+b', timeout = 20)",
    "buf <- raw()",
    "repeat {",
    "  b <- readBin(con, 'raw', 1L)",
    "  if (length(b) == 0L) break",
    "  buf <- c(buf, b); n <- length(buf)",
    "  if (n >= 4L && identical(buf[(n-3L):n], charToRaw('\\r\\n\\r\\n'))) break",
    "}",
    "f <- file(logf, 'wb'); writeBin(buf, f); close(f)",
    "writeBin(readBin(respf, 'raw', file.size(respf)), con); flush(con)",
    "close(con); close(srv)"
  ), script)

  port <- sample(20000:59000, 1L)
  system2("sh", c("-c", shQuote(sprintf("exec Rscript %s %d %s %s %s",
                                        script, port, respf, logf, readyf))),
          wait = FALSE, stdout = NULL, stderr = NULL)
  deadline <- Sys.time() + 20
  while (!file.exists(readyf) && Sys.time() < deadline) Sys.sleep(0.05)
  if (!file.exists(readyf)) skip("the raw test server did not start")
  Sys.sleep(0.2)

  code(sprintf("http://127.0.0.1:%d", port))

  deadline <- Sys.time() + 10
  while (!file.exists(logf) && Sys.time() < deadline) Sys.sleep(0.05)
  if (!file.exists(logf)) return(NULL)
  rawToChar(readBin(logf, "raw", file.size(logf)))
}

crlf <- function(...) paste0(paste(c(...), collapse = "\r\n"))

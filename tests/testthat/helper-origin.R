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
    "  con <- socketAccept(srv, open = 'r+b', timeout = 20)",
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

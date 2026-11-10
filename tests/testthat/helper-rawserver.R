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
  d <- tempfile("zu-raw-")
  dir.create(d)
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  script <- file.path(d, "server.R")
  respf <- file.path(d, "response.bin")
  logf <- file.path(d, "seen.bin")
  readyf <- file.path(d, "ready")
  if (is.character(response)) {
    response <- charToRaw(enc2utf8(response))
  }
  writeBin(response, respf)

  writeLines(
    c(
      "args <- commandArgs(TRUE)",
      "port <- as.integer(args[1]); respf <- args[2]; logf <- args[3]; readyf <- args[4]",
      "srv <- serverSocket(port)",
      "cat('ready\\n', file = readyf)",
      "con <- socketAccept(srv, blocking = TRUE, open = 'r+b', timeout = 20)",
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
    ),
    script
  )

  port <- free_port()
  outf <- spawn_helper_r(script, c(port, respf, logf, readyf), d)
  wait_helper_ready(function() file.exists(readyf), outf, "the raw test server")
  Sys.sleep(0.2)

  code(sprintf("http://127.0.0.1:%d", port))

  deadline <- Sys.time() + 10
  while (!file.exists(logf) && Sys.time() < deadline) {
    Sys.sleep(0.05)
  }
  if (!file.exists(logf)) {
    return(NULL)
  }
  rawToChar(readBin(logf, "raw", file.size(logf)))
}

crlf <- function(...) paste0(paste(c(...), collapse = "\r\n"))

# A raw server that answers many connections, one after another, and reads
# each request's BODY as well as its head (#240, #241, #244). The wire is
# the oracle (CLAUDE.md, #208): a comparison of two clients' uploads needs
# the body bytes that arrived, framing included, which with_raw_server()
# above does not read.
#
# Connection i is answered with responses[[i]], cycling when there are
# fewer responses than connections, and closed after the response. A body
# is read by its Content-Length, or as chunked to the end of the trailers,
# and an `Expect: 100-continue` is answered with a 100 first. Anything that
# arrives within about 0.1 s after the framed end is recorded too, so a
# client that sends more than it declared is seen doing it. `code`
# receives a list: `url`, the server's base URL, and `seen()`, the requests
# recorded so far, each a raw vector of exactly the bytes that arrived. A
# request is recorded before its response is written, so once a client has
# a response, or an error that followed one, seen() includes it.
with_raw_server_seq <- function(responses, code) {
  skip_unless_forkable()
  d <- tempfile("zu-rawseq-")
  dir.create(d)
  readyf <- file.path(d, "ready")
  pidf <- file.path(d, "pid")
  if (!is.list(responses)) {
    responses <- list(responses)
  }
  for (i in seq_along(responses)) {
    r <- responses[[i]]
    if (is.character(r)) {
      r <- charToRaw(enc2utf8(r))
    }
    writeBin(r, file.path(d, sprintf("resp-%d.bin", i)))
  }
  script <- file.path(d, "server.R")
  writeLines(
    c(
      "args <- commandArgs(TRUE)",
      "port <- as.integer(args[1]); d <- args[2]; readyf <- args[3]; n <- as.integer(args[4])",
      "resp <- lapply(seq_len(n), function(i) {",
      "  f <- file.path(d, sprintf('resp-%d.bin', i)); readBin(f, 'raw', file.size(f))",
      "})",
      "crlf <- charToRaw('\\r\\n')",
      # Non-blocking, polled: a read that finds nothing yet returns raw(0),
      # so each read waits up to 10 s for its bytes, and drain() below can
      # ask what else arrived without blocking.
      "read_some <- function(con, k) {",
      "  deadline <- Sys.time() + 10",
      "  repeat {",
      "    b <- readBin(con, 'raw', k)",
      "    if (length(b) || Sys.time() > deadline) return(b)",
      "    Sys.sleep(0.002)",
      "  }",
      "}",
      "read_line <- function(con) {",
      "  buf <- raw()",
      "  repeat {",
      "    b <- read_some(con, 1L)",
      "    if (length(b) == 0L) break",
      "    buf <- c(buf, b); m <- length(buf)",
      "    if (m >= 2L && identical(buf[(m - 1L):m], crlf)) break",
      "  }",
      "  buf",
      "}",
      "read_n <- function(con, k) {",
      "  out <- raw()",
      "  while (length(out) < k) {",
      "    b <- read_some(con, k - length(out))",
      "    if (length(b) == 0L) break",
      "    out <- c(out, b)",
      "  }",
      "  out",
      "}",
      # Whatever the client sent past the framed end of its request. It
      # should be nothing: a body sent twice (#208) shows up here, where a
      # server that stops at Content-Length would never see it.
      "drain <- function(con) {",
      "  out <- raw(); quiet <- 0L",
      "  while (quiet < 50L) {",
      "    b <- readBin(con, 'raw', 65536L)",
      "    if (length(b)) { out <- c(out, b); quiet <- 0L } else { quiet <- quiet + 1L; Sys.sleep(0.002) }",
      "  }",
      "  out",
      "}",
      "srv <- serverSocket(port)",
      "cat('ready\\n', file = readyf)",
      "i <- 0L",
      "repeat {",
      "  con <- tryCatch(",
      "    socketAccept(srv, blocking = FALSE, open = 'r+b', timeout = 60),",
      "    error = function(e) NULL",
      "  )",
      "  if (is.null(con)) break",
      "  i <- i + 1L",
      "  head <- raw()",
      "  repeat {",
      "    l <- read_line(con); head <- c(head, l)",
      "    if (length(l) == 0L || identical(l, crlf)) break",
      "  }",
      "  txt <- rawToChar(head[head != as.raw(0)])",
      "  hl <- tolower(strsplit(txt, '\\r\\n', fixed = TRUE)[[1]])",
      "  body <- raw()",
      "  if (any(grepl('^expect:[ \\t]*100-continue', hl))) {",
      "    writeBin(charToRaw('HTTP/1.1 100 Continue\\r\\n\\r\\n'), con); flush(con)",
      "  }",
      "  cl <- sub('^content-length:[ \\t]*', '', grep('^content-length:', hl, value = TRUE))",
      "  if (any(grepl('^transfer-encoding:.*chunked', hl))) {",
      "    repeat {",
      "      l <- read_line(con); body <- c(body, l)",
      "      sz <- strtoi(sub(';.*', '', trimws(rawToChar(l))), 16L)",
      "      if (length(l) == 0L || is.na(sz)) break",
      "      if (sz == 0L) {",
      "        repeat {",
      "          t <- read_line(con); body <- c(body, t)",
      "          if (length(t) == 0L || identical(t, crlf)) break",
      "        }",
      "        break",
      "      }",
      "      body <- c(body, read_n(con, sz + 2L))",
      "    }",
      "  } else if (length(cl) == 1L && !is.na(as.numeric(cl))) {",
      "    body <- read_n(con, as.numeric(cl))",
      "  }",
      "  extra <- drain(con)",
      "  tmp <- file.path(d, sprintf('seen-%d.tmp', i))",
      "  writeBin(c(head, body, extra), tmp)",
      "  file.rename(tmp, file.path(d, sprintf('seen-%d.bin', i)))",
      "  try(writeBin(resp[[(i - 1L) %% n + 1L]], con), silent = TRUE)",
      "  try(flush(con), silent = TRUE)",
      "  close(con)",
      "}",
      "close(srv)"
    ),
    script
  )

  port <- free_port()
  outf <- spawn_helper_r(
    script,
    c(port, shQuote(d), shQuote(readyf), length(responses)),
    d,
    pid_file = pidf
  )
  on.exit(
    {
      if (file.exists(pidf)) {
        pid <- suppressWarnings(as.integer(readLines(pidf, warn = FALSE)))
        if (length(pid) == 1L && !is.na(pid)) {
          tools::pskill(pid)
        }
      }
      unlink(d, recursive = TRUE)
    },
    add = TRUE
  )
  wait_helper_ready(
    function() file.exists(readyf),
    outf,
    "the sequential raw server"
  )
  Sys.sleep(0.2)

  seen <- function() {
    f <- list.files(d, "^seen-[0-9]+\\.bin$", full.names = TRUE)
    f <- f[order(as.integer(gsub("\\D", "", basename(f))))]
    lapply(f, function(x) readBin(x, "raw", file.size(x)))
  }
  code(list(url = sprintf("http://127.0.0.1:%d", port), seen = seen))
}

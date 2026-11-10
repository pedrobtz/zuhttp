# libcurl, through the `curl` package, as a reference client (#241, #244).
# Optional: every test that uses these calls skip_if_not_installed("curl")
# first. Both clients are given the same User-Agent and Accept-Encoding, so
# a header that differs is one zuhttp chose, not a default of either.

DIFF_UA <- "zuhttp-differential"

# One request with libcurl, on a fresh handle (no connection reuse, no
# proxy). `body` is a raw vector for a sized upload, or a function for a
# chunked one (it returns raw(0) at the end, libcurl's convention).
curl_request <- function(
  url,
  method = "GET",
  headers = NULL,
  body = NULL
) {
  h <- curl::new_handle(
    proxy = "",
    useragent = DIFF_UA,
    accept_encoding = "gzip",
    timeout = 10
  )
  if (method == "HEAD") {
    curl::handle_setopt(h, nobody = TRUE)
  } else if (method != "GET") {
    curl::handle_setopt(h, customrequest = method)
  }
  if (is.raw(body)) {
    curl::handle_setopt(
      h,
      post = TRUE,
      postfieldsize = length(body),
      copypostfields = body
    )
  } else if (is.function(body)) {
    curl::handle_setopt(h, post = TRUE, readfunction = body)
    headers <- c(headers, `Transfer-Encoding` = "chunked")
  }
  # libcurl adds `Expect: 100-continue` to a large upload, and a default
  # Content-Type to a POST; both are libcurl's choices, so they are turned
  # off rather than compared.
  headers <- c(headers, Expect = "")
  if (!is.null(body) && !any(tolower(names(headers)) == "content-type")) {
    headers <- c(headers, `Content-Type` = "")
  }
  do.call(curl::handle_setheaders, c(list(h), as.list(headers)))
  curl::curl_fetch_memory(url, handle = h)
}

# A libcurl result split the way zuhttp reports a response: status, the
# final response's header fields, its trailer fields, and the body. libcurl
# passes every header block to one callback, so the 1xx blocks come first
# and the trailers, which have no status line, come last.
curl_response_parts <- function(res) {
  lines <- strsplit(rawToChar(res$headers), "\r\n", fixed = TRUE)[[1]]
  blocks <- list()
  cur <- character()
  for (l in c(lines, "")) {
    if (nzchar(l)) {
      cur <- c(cur, l)
    } else if (length(cur)) {
      blocks[[length(blocks) + 1L]] <- cur
      cur <- character()
    }
  }
  is_status <- vapply(blocks, function(b) grepl("^HTTP/", b[[1]]), NA)
  last <- max(which(is_status))
  fields <- function(b) {
    b <- b[!grepl("^HTTP/", b)]
    stats::setNames(
      sub("^[^:]*:[ \t]*", "", sub("[ \t]+$", "", b)),
      sub(":.*$", "", b)
    )
  }
  trailers <- if (last < length(blocks)) {
    fields(unlist(blocks[(last + 1L):length(blocks)]))
  } else {
    fields(character())
  }
  list(
    status = res$status_code,
    headers = fields(blocks[[last]]),
    trailers = trailers,
    body = res$content
  )
}

# The same four parts from a zuhttp response.
zu_response_parts <- function(r) {
  t <- zu_resp_trailers(r)
  list(
    status = zu_resp_status(r),
    headers = zu_resp_headers(r),
    trailers = if (is.null(t)) {
      stats::setNames(character(), character())
    } else {
      t
    },
    body = zu_resp_raw(r)
  )
}

# Field names compared case-insensitively (RFC 9110 §5.1), values as sent,
# order kept: the order of same-named fields is significant (§5.3).
norm_fields <- function(x) {
  if (!length(x)) {
    return(stats::setNames(character(), character()))
  }
  stats::setNames(unname(x), tolower(names(x)))
}

# A recorded HTTP/1.1 request, parsed: method, target, header fields (names
# lowercased, in the order sent), the body as its framing delimits it
# (dechunked where chunked), and whatever followed.
parse_recorded_request <- function(bytes) {
  sep <- grepRaw(charToRaw("\r\n\r\n"), bytes, fixed = TRUE)
  head <- rawToChar(bytes[seq_len(sep - 1L)])
  wire <- if (sep + 3L < length(bytes)) {
    bytes[(sep + 4L):length(bytes)]
  } else {
    raw()
  }
  lines <- strsplit(head, "\r\n", fixed = TRUE)[[1]]
  rl <- strsplit(lines[[1]], " ", fixed = TRUE)[[1]]
  f <- lines[-1]
  fields <- stats::setNames(
    sub("^[^:]*:[ \t]*", "", f),
    tolower(sub(":.*$", "", f))
  )
  chunked <- any(grepl("chunked", fields[names(fields) == "transfer-encoding"]))
  cl <- as.numeric(fields[names(fields) == "content-length"])
  framed <- if (chunked) {
    dechunk(wire)
  } else {
    n <- if (length(cl) == 1L) min(cl, length(wire)) else 0
    list(body = wire[seq_len(n)], rest = wire[-seq_len(n)])
  }
  list(
    method = rl[[1]],
    target = rl[[2]],
    version = rl[[3]],
    fields = fields,
    body = framed$body,
    # Bytes after the framed end: a client that sends a body twice (#208)
    # has some, and a server reading by the framing never sees them.
    excess = framed$rest
  )
}

# RFC 9112 §7.1, for a body a test server recorded. Strict: a malformed
# chunk is an error, since the bytes came from the client under test.
dechunk <- function(wire) {
  out <- raw()
  pos <- 1L
  repeat {
    rest <- wire[pos:length(wire)]
    eol <- grepRaw(charToRaw("\r\n"), rest, fixed = TRUE)
    stopifnot(length(eol) == 1L)
    size <- strtoi(sub(";.*", "", rawToChar(rest[seq_len(eol - 1L)])), 16L)
    stopifnot(!is.na(size))
    pos <- pos + eol + 1L
    if (size == 0L) {
      # The trailer section, then the final CRLF.
      rest <- wire[pos:length(wire)]
      end <- if (identical(rest[1:2], charToRaw("\r\n"))) {
        2L
      } else {
        grepRaw(charToRaw("\r\n\r\n"), rest, fixed = TRUE) + 3L
      }
      pos <- pos + end
      break
    }
    out <- c(out, wire[pos:(pos + size - 1L)])
    stopifnot(identical(wire[pos + size + 0:1], charToRaw("\r\n")))
    pos <- pos + size + 2L
  }
  list(
    body = out,
    rest = if (pos <= length(wire)) wire[pos:length(wire)] else raw()
  )
}

# A real gzip stream (RFC 1952). memCompress(type = "gzip") writes zlib's
# format, which §21.1 refuses under a gzip label.
gzip_bytes <- function(x) {
  f <- tempfile(fileext = ".gz")
  on.exit(unlink(f), add = TRUE)
  con <- gzfile(f, "wb")
  writeBin(x, con)
  close(con)
  readBin(f, "raw", file.size(f))
}

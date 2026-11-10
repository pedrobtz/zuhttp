# #241: zuhttp beside libcurl, on the same loopback server, both ways.
#
# Emit: the same request sent by each client, and the bytes the server
# received compared: method, target, header fields and body. Decode: the
# same scripted response bytes read by each client, and status, header
# fields, trailers and body compared. The wire is the oracle (CLAUDE.md,
# #208): a server that reads Content-Length and discards the rest cannot
# see a doubled body, and the client's own view of a response proves
# nothing about how another reader would take the same bytes.

test_that("zuhttp sends what libcurl sends, byte for byte (#241)", {
  skip_if_not_installed("curl")
  pattern <- function(n) as.raw(seq_len(n) %% 251L)
  # The upload sizes straddle the 64 KiB head-plus-body combine (#208) and
  # the 32 KiB in-memory window that hid it; 40000 is #208's own size.
  sizes <- c(0, 1, 32767, 32768, 40000, 65000, 65535, 65536, 65537)
  cases <- c(
    list(
      list(method = "GET", path = "/q?a=1&b=%20x&c=%E2%82%AC"),
      list(
        method = "GET",
        path = "/h",
        headers = c(`X-One` = "1", `X-Two` = "a, b", Accept = "text/plain")
      ),
      list(method = "DELETE", path = "/d"),
      list(method = "HEAD", path = "/head"),
      list(method = "POST", path = "/stream", stream = 70000)
    ),
    lapply(sizes, function(n) {
      list(method = "POST", path = paste0("/up", n), body = pattern(n))
    })
  )
  ok <- crlf(
    "HTTP/1.1 200 OK",
    "Content-Length: 2",
    "Connection: close",
    "",
    "ok"
  )
  seen <- with_raw_server_seq(ok, function(srv) {
    cl <- zu_client(pool = NULL, proxy = FALSE, user_agent = DIFF_UA)
    for (cs in cases) {
      url <- paste0(srv$url, cs$path)
      req <- zu_request(cs$method, url)
      if (!is.null(cs$headers)) {
        req <- zu_headers(req, cs$headers)
      }
      if (!is.null(cs$body)) {
        req <- zu_body_raw(req, cs$body, type = "application/octet-stream")
      }
      cbody <- cs$body
      if (!is.null(cs$stream)) {
        req <- zu_body_stream(req, pattern_body(cs$stream, 16384))
        req <- zu_headers(req, `Content-Type` = "application/octet-stream")
        f <- pattern_body(cs$stream, 16384)
        cbody <- function(n) {
          x <- f()
          if (is.null(x)) raw() else x
        }
      }
      zu_perform(req, client = cl)
      ch <- cs$headers
      if (!is.null(cbody)) {
        ch <- c(ch, `Content-Type` = "application/octet-stream")
      }
      curl_request(url, cs$method, ch, cbody)
    }
    srv$seen()
  })
  expect_length(seen, 2L * length(cases))
  for (i in seq_along(cases)) {
    zu <- parse_recorded_request(seen[[2L * i - 1L]])
    lc <- parse_recorded_request(seen[[2L * i]])
    label <- paste(cases[[i]]$method, cases[[i]]$path)
    expect_identical(zu$method, lc$method, label = label)
    expect_identical(zu$target, lc$target, label = label)
    expect_identical(zu$version, lc$version, label = label)
    # Body bytes as they arrived, decoded from chunked where it was used:
    # one copy, the whole of it, nothing after.
    expect_identical(zu$body, lc$body, label = label)
    expect_identical(zu$excess, raw(), label = paste("zuhttp", label))
    expect_identical(lc$excess, raw(), label = paste("libcurl", label))
    if (!is.null(cases[[i]]$body)) {
      expect_identical(zu$body, cases[[i]]$body, label = label)
    }
    # Field order across different names is not significant (RFC 9110
    # §5.3), so the fields are compared sorted by name. One deliberate
    # difference: with `pool = NULL` zuhttp will not reuse the connection
    # and says so with `Connection: close` (RFC 9112 §9.6; design §26),
    # which libcurl, keeping its connection cache, does not.
    zf <- zu$fields[names(zu$fields) != "connection"]
    expect_identical(
      unname(zu$fields[names(zu$fields) == "connection"]),
      "close"
    )
    expect_identical(
      zf[order(names(zf))],
      lc$fields[order(names(lc$fields))],
      label = label
    )
  }
})

test_that("zuhttp reads a response as libcurl reads it (#241)", {
  skip_if_not_installed("curl")
  # Compressible, but not to under the 100 bytes gzip_chunked splits at.
  gz <- gzip_bytes(charToRaw(paste(seq_len(3000), collapse = ",")))
  hexlen <- function(x) sprintf("%x", length(x))
  cases <- list(
    content_length = crlf("HTTP/1.1 200 OK", "Content-Length: 5", "", "hello"),
    chunked_trailers = crlf(
      "HTTP/1.1 200 OK",
      "Transfer-Encoding: chunked",
      "",
      "5;ext=1",
      "hello",
      "A",
      " world++++",
      "0",
      "X-Checksum: abc",
      "X-Other: 2",
      "",
      ""
    ),
    close_delimited = crlf(
      "HTTP/1.1 200 OK",
      "Connection: close",
      "",
      "to the end"
    ),
    http10 = crlf("HTTP/1.0 200 OK", "X-A: 1", "", "ten"),
    gzip = c(
      charToRaw(crlf(
        "HTTP/1.1 200 OK",
        "Content-Encoding: gzip",
        paste0("Content-Length: ", length(gz)),
        "",
        ""
      )),
      gz
    ),
    gzip_chunked = c(
      charToRaw(crlf(
        "HTTP/1.1 200 OK",
        "Content-Encoding: gzip",
        "Transfer-Encoding: chunked",
        "",
        hexlen(gz[1:100]),
        ""
      )),
      gz[1:100],
      charToRaw(crlf("", hexlen(gz[-(1:100)]), "")),
      gz[-(1:100)],
      charToRaw(crlf("", "0", "", ""))
    ),
    informational = crlf(
      "HTTP/1.1 100 Continue",
      "",
      "HTTP/1.1 103 Early Hints",
      "Link: </a.css>; rel=preload",
      "",
      "HTTP/1.1 200 OK",
      "Content-Length: 2",
      "",
      "ok"
    ),
    no_content = crlf("HTTP/1.1 204 No Content", "X-A: 1", "", ""),
    not_modified = crlf(
      "HTTP/1.1 304 Not Modified",
      "ETag: \"x\"",
      "Content-Length: 5",
      "",
      ""
    ),
    repeated_fields = crlf(
      "HTTP/1.1 200 OK",
      "Set-Cookie: a=1",
      "X-A: 1",
      "Set-Cookie: b=2",
      "x-a: 2",
      "Content-Length: 0",
      "",
      ""
    ),
    whitespace = crlf(
      "HTTP/1.1 200 OK",
      "X-Pad:   padded \t",
      "X-Empty:",
      "Content-Length: 0",
      "",
      ""
    ),
    error_status = crlf(
      "HTTP/1.1 404 Not Found",
      "Content-Length: 4",
      "",
      "gone"
    ),
    empty_reason = crlf("HTTP/1.1 200 ", "Content-Length: 1", "", "x"),
    excess_after_length = crlf(
      "HTTP/1.1 200 OK",
      "Content-Length: 3",
      "",
      "abcdef"
    )
  )
  heads <- list(
    head = crlf("HTTP/1.1 200 OK", "Content-Length: 5", "X-A: 1", "", "")
  )
  all <- c(cases, heads)
  method <- ifelse(names(all) %in% names(heads), "HEAD", "GET")
  got <- with_raw_server_seq(rep(unname(all), each = 2L), function(srv) {
    cl <- zu_client(
      pool = NULL,
      proxy = FALSE,
      check = FALSE,
      user_agent = DIFF_UA
    )
    lapply(seq_along(all), function(i) {
      url <- paste0(srv$url, "/", names(all)[[i]])
      # A refusal is an outcome to compare, not a test error.
      refused <- function(e) list(refused = TRUE, why = conditionMessage(e))
      list(
        zu = tryCatch(
          zu_response_parts(zu_perform(
            zu_request(method[[i]], url),
            client = cl
          )),
          error = refused
        ),
        curl = tryCatch(
          curl_response_parts(curl_request(url, method[[i]])),
          error = refused
        )
      )
    })
  })
  for (i in seq_along(all)) {
    label <- names(all)[[i]]
    zu <- got[[i]]$zu
    lc <- got[[i]]$curl
    expect_identical(
      isTRUE(zu$refused),
      isTRUE(lc$refused),
      label = paste(label, zu$why, lc$why)
    )
    expect_identical(zu$status, lc$status, label = label)
    # One deliberate difference: zuhttp reports a decoded body's fields,
    # and Content-Encoding and Content-Length described the bytes it
    # decoded, not the body it returns (design §21.2, D-9; decode = FALSE
    # keeps them). libcurl decodes and reports the wire's fields.
    lh <- norm_fields(lc$headers)
    if (any(names(lh) == "content-encoding") && length(zu$body) > 0L) {
      lh <- lh[!names(lh) %in% c("content-encoding", "content-length")]
    }
    expect_identical(norm_fields(zu$headers), lh, label = label)
    expect_identical(
      norm_fields(zu$trailers),
      norm_fields(lc$trailers),
      label = label
    )
    expect_identical(zu$body, lc$body, label = label)
  }
})

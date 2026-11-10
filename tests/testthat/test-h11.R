# #240: zuhttp's HTTP/1.1 response parsing beside h11's.
#
# h11 (python-hyper) is a sans-I/O RFC 9112 implementation, so it reads
# exactly the bytes it is given, as zuhttp reads them from a loopback
# server. For each input the two must agree on accept or refuse, and on
# what was accepted: status, header fields, trailers and body. Hand-written
# cases know the answer only for the cases someone thought of; this is
# where the specification's second case (repeated fields, obs-fold, bare
# LF, chunk extensions, trailers) shows a disagreement.
#
# The inputs are fuzz/seed-corpus.py's `response` and `chunked` seeds,
# copied here because fuzz/ is not part of the package, then cases that
# seed list does not have. A row where zuhttp is deliberately stricter
# than h11, or h11 than zuhttp, carries `expect` with the reason; every
# other row must agree.

test_that("zuhttp parses responses as h11 does (#240)", {
  skip_unless_python("h11")
  chunked_head <- "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
  ch <- function(x) paste0(chunked_head, x)
  rows <- list(
    # fuzz/seed-corpus.py, response/*
    ok = list(bytes = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"),
    no_headers = list(bytes = "HTTP/1.1 204 No Content\r\n\r\n"),
    chunked = list(bytes = ch("5\r\nhello\r\n0\r\n\r\n")),
    cl_te_conflict = list(
      bytes = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"
    ),
    dup_cl = list(
      bytes = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n"
    ),
    # Expected difference. RFC 9112 §5.2 has a user agent replace obs-fold
    # with SP, which h11 does; zuhttp refuses it, by D-15 and design §18.1
    # ("strict, not permissive"): a folded line is the shape of a header
    # injection, and no server has a reason to send one.
    obs_fold = list(
      bytes = "HTTP/1.1 200 OK\r\nX-A: one\r\n  two\r\n\r\n",
      expect = c(zu = TRUE, h11 = FALSE)
    ),
    cl_negative = list(bytes = "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n"),
    cl_overflow = list(
      bytes = "HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999\r\n\r\n"
    ),
    te_not_chunked = list(
      bytes = "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n"
    ),
    informational = list(
      bytes = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    ),
    space_before_colon = list(bytes = "HTTP/1.1 200 OK\r\nX-A : v\r\n\r\n"),
    nul_in_value = list(
      bytes = as.raw(c(
        charToRaw("HTTP/1.1 200 OK\r\nX-A: a"),
        0x00,
        charToRaw("b\r\n\r\n")
      ))
    ),
    bare_lf = list(bytes = "HTTP/1.1 200 OK\nContent-Length: 0\n\n"),
    huge_status = list(bytes = "HTTP/1.1 999999 X\r\n\r\n"),
    partial = list(bytes = "HTTP/1.1 200 OK\r\nContent-Len"),
    # fuzz/seed-corpus.py, chunked/*, behind a chunked response head
    ch_simple = list(bytes = ch("5\r\nhello\r\n0\r\n\r\n")),
    ch_trailer = list(bytes = ch("5\r\nhello\r\n0\r\nX-T: v\r\n\r\n")),
    ch_ext = list(bytes = ch("5;name=value\r\nhello\r\n0\r\n\r\n")),
    ch_bad_size = list(bytes = ch("zz\r\nhello\r\n0\r\n\r\n")),
    ch_size_overflow = list(bytes = ch("FFFFFFFFFFFFFFFFFF\r\nx\r\n")),
    ch_negative = list(bytes = ch("-5\r\nhello\r\n")),
    ch_empty_final = list(bytes = ch("0\r\n\r\n")),
    ch_no_terminator = list(bytes = ch("5\r\nhello")),
    # The second cases the seeds do not cover.
    repeated_fields = list(
      bytes = "HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nX-A: 1\r\nSet-Cookie: b=2\r\nContent-Length: 0\r\n\r\n"
    ),
    # Expected differences. RFC 9110 §8.6 lets a recipient either reject
    # a repeated, equal Content-Length or collapse it to one value; h11
    # collapses, and zuhttp rejects both spellings (design §18.1, "more
    # than one Content-Length, equal or not"; D-15), since two framing
    # headers are a request-smuggling shape.
    same_cl_twice = list(
      bytes = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok",
      expect = c(zu = TRUE, h11 = FALSE)
    ),
    cl_list = list(
      bytes = "HTTP/1.1 200 OK\r\nContent-Length: 2, 2\r\n\r\nok",
      expect = c(zu = TRUE, h11 = FALSE)
    ),
    cl_plus = list(bytes = "HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\nok"),
    ows = list(
      bytes = "HTTP/1.1 200 OK\r\nX-A: \t padded \t\r\nX-Empty:\r\nContent-Length: 0\r\n\r\n"
    ),
    no_reason = list(bytes = "HTTP/1.1 200 \r\nContent-Length: 0\r\n\r\n"),
    no_reason_no_sp = list(bytes = "HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n"),
    http10_close = list(bytes = "HTTP/1.0 200 OK\r\n\r\nto the close"),
    http11_close = list(
      bytes = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nto the close"
    ),
    bad_name = list(
      bytes = "HTTP/1.1 200 OK\r\nX A: v\r\nContent-Length: 0\r\n\r\n"
    ),
    leading_ws_field = list(
      bytes = "HTTP/1.1 200 OK\r\n X-A: v\r\nContent-Length: 0\r\n\r\n"
    ),
    cl_short_body = list(
      bytes = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort"
    ),
    excess_after_cl = list(
      bytes = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokEXTRA"
    ),
    te_upper = list(
      bytes = "HTTP/1.1 200 OK\r\nTransfer-Encoding: CHUNKED\r\n\r\n2\r\nok\r\n0\r\n\r\n"
    ),
    te_gzip_chunked = list(
      bytes = "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"
    ),
    ch_upper_hex = list(bytes = ch("A\r\n0123456789\r\n0\r\n\r\n")),
    ch_leading_zeros = list(bytes = ch("0002\r\nok\r\n000\r\n\r\n")),
    ch_quoted_ext = list(bytes = ch("2;a=\"x;y\"\r\nok\r\n0\r\n\r\n")),
    # Expected difference, h11 the stricter: RFC 9112 §7.1.1 allows BWS
    # before a chunk extension's ";", and h11 0.16 refuses it. zuhttp
    # follows the RFC (picohttpparser, D-10).
    ch_ext_ows = list(
      bytes = ch("2 ;a=b\r\nok\r\n0\r\n\r\n"),
      expect = c(zu = FALSE, h11 = TRUE)
    ),
    ch_repeated_trailers = list(
      bytes = ch("2\r\nok\r\n0\r\nX-T: 1\r\nX-T: 2\r\nX-U: 3\r\n\r\n")
    ),
    ch_bare_lf = list(bytes = ch("2\nok\n0\n\n")),
    ch_missing_crlf = list(bytes = ch("2\r\nokX0\r\n\r\n")),
    ch_no_final_crlf = list(bytes = ch("2\r\nok\r\n0\r\n")),
    informational_103 = list(
      bytes = "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    ),
    not_modified_cl = list(
      bytes = "HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\n"
    ),
    head_cl = list(
      method = "HEAD",
      bytes = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
    )
  )
  bytes <- lapply(rows, function(r) {
    if (is.character(r$bytes)) charToRaw(r$bytes) else r$bytes
  })
  method <- vapply(rows, function(r) r$method %||% "GET", "")

  ref <- run_python_json(
    "h11_parse.py",
    charToRaw(zujson::json_write(
      unname(lapply(seq_along(rows), function(i) {
        list(
          method = method[[i]],
          hex = paste(format(bytes[[i]]), collapse = "")
        )
      })),
      auto_unbox = TRUE
    ))
  )

  got <- with_raw_server_seq(unname(bytes), function(srv) {
    # decode = FALSE: h11 does not decode content codings, and none of
    # these rows is about them.
    cl <- zu_client(pool = NULL, proxy = FALSE, check = FALSE, decode = FALSE)
    lapply(seq_along(rows), function(i) {
      tryCatch(
        {
          r <- zu_perform(zu_request(method[[i]], srv$url), client = cl)
          p <- zu_response_parts(r)
          p$refused <- FALSE
          p
        },
        error = function(e) list(refused = TRUE, why = conditionMessage(e))
      )
    })
  })

  pairs <- function(x) {
    if (!length(x)) {
      return(stats::setNames(character(), character()))
    }
    stats::setNames(
      vapply(x, `[[`, "", 2L),
      vapply(x, `[[`, "", 1L)
    )
  }
  hex_raw <- function(h) {
    if (!nzchar(h)) {
      return(raw())
    }
    as.raw(strtoi(substring(h, seq(1, nchar(h), 2), seq(2, nchar(h), 2)), 16L))
  }
  for (i in seq_along(rows)) {
    nm <- names(rows)[[i]]
    zu <- got[[i]]
    h1 <- ref[[i]]
    expect <- rows[[i]]$expect
    label <- paste0(
      nm,
      " (zuhttp: ",
      zu$why %||% "ok",
      "; h11: ",
      h1$why %||% "ok",
      ")"
    )
    if (!is.null(expect)) {
      expect_identical(
        c(zu = zu$refused, h11 = isTRUE(h1$refused)),
        expect,
        label = label
      )
      next
    }
    expect_identical(zu$refused, isTRUE(h1$refused), label = label)
    if (zu$refused || isTRUE(h1$refused)) {
      next
    }
    expect_identical(zu$status, as.integer(h1$status), label = label)
    # h11 lowercases a Transfer-Encoding value as it parses it; zuhttp
    # reports fields as received (design §18.3). Coding names are
    # case-insensitive (RFC 9112 §7), so the two are compared folded.
    fold_te <- function(f) {
      te <- names(f) == "transfer-encoding"
      f[te] <- tolower(f[te])
      f
    }
    expect_identical(
      fold_te(norm_fields(zu$headers)),
      fold_te(norm_fields(pairs(h1$headers))),
      label = label
    )
    expect_identical(
      norm_fields(zu$trailers),
      norm_fields(pairs(h1$trailers)),
      label = label
    )
    expect_identical(zu$body, hex_raw(h1$body), label = label)
  }
})

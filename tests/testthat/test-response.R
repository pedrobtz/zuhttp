# §31.7 — response accessors, the charset chain, and the status-error policy.

resp <- function(...) zu_response(...)

test_that("header lookup is case-insensitive and keeps repeats (§18.3)", {
  r <- resp(200L, c("Set-Cookie" = "a=1", "Set-Cookie" = "b=2",
                    "Content-Type" = "text/plain"))
  expect_identical(zu_resp_header(r, "set-cookie"), c("a=1", "b=2"))
  expect_identical(zu_resp_header(r, "SET-COOKIE"), c("a=1", "b=2"))
  # Absent is length 0, not NULL and not NA: it composes with length() and
  # seq_along() without a special case.
  expect_identical(zu_resp_header(r, "etag"), character())
  expect_identical(length(zu_resp_header(r, "content-type")), 1L)
})

test_that("zu_resp_ok() draws the line at 400", {
  expect_true(zu_resp_ok(resp(200L)))
  expect_true(zu_resp_ok(resp(304L)))
  expect_false(zu_resp_ok(resp(400L)))
  expect_false(zu_resp_ok(resp(500L)))
})

test_that("the charset chain follows §31.7 in order", {
  bytes <- as.raw(c(0x63, 0x61, 0x66, 0xE9))          # café, ISO-8859-1

  # 1. an explicit encoding wins over everything
  r <- resp(200L, c("Content-Type" = "text/plain; charset=utf-8"), bytes)
  expect_identical(zu_resp_text(r, encoding = "ISO-8859-1"), "café")

  # 2. the charset parameter, including the quoted form servers really send
  r <- resp(200L, c("Content-Type" = "text/plain; charset=\"ISO-8859-1\""), bytes)
  expect_identical(zu_resp_text(r), "café")

  # 3. a BOM, which is then stripped
  utf16 <- c(as.raw(c(0xFF, 0xFE)), as.raw(c(0x68, 0x00, 0x69, 0x00)))
  r <- resp(200L, c("Content-Type" = "text/plain"), utf16)
  expect_identical(zu_resp_text(r), "hi")

  bom8 <- c(as.raw(c(0xEF, 0xBB, 0xBF)), charToRaw("hi"))
  r <- resp(200L, c("Content-Type" = "text/plain"), bom8)
  expect_identical(zu_resp_text(r), "hi")

  # 4. otherwise UTF-8, not the ISO-8859-1 of RFC 7231
  r <- resp(200L, c("Content-Type" = "text/plain"), charToRaw(enc2utf8("café")))
  expect_identical(zu_resp_text(r), "café")

  # 5. application/json is UTF-8 by RFC 8259 whatever the charset says
  r <- resp(200L, c("Content-Type" = "application/json; charset=ISO-8859-1"),
            charToRaw(enc2utf8('{"a":"é"}')))
  expect_identical(zu_resp_text(r), '{"a":"é"}')
})

test_that("an unrecognised charset falls through instead of failing", {
  r <- resp(200L, c("Content-Type" = "text/plain; charset=x-not-a-charset"),
            charToRaw(enc2utf8("café")))
  expect_identical(zu_resp_text(r), "café")
})

test_that("undecodable bytes raise rather than corrupt", {
  r <- resp(200L, c("Content-Type" = "text/plain"), as.raw(c(0x61, 0xFF)))
  expect_error(zu_resp_text(r), class = "zu_body_decode_error")
  expect_match(zu_resp_text(r, on_invalid = "substitute"), "^a")
})

test_that("the result is marked UTF-8", {
  r <- resp(200L, c("Content-Type" = "text/plain; charset=ISO-8859-1"),
            as.raw(c(0x63, 0x61, 0x66, 0xE9)))
  expect_identical(Encoding(zu_resp_text(r)), "UTF-8")
})

test_that("an empty body is an empty string, not an error", {
  expect_identical(zu_resp_text(resp(204L)), "")
})

test_that("zu_resp_check() maps status ranges to the §34.1 classes", {
  e <- tryCatch(zu_resp_check(resp(404L, url = "https://x/y")),
                zu_error = function(e) e)
  expect_s3_class(e, "zu_http_client_error")
  expect_s3_class(e, "zu_http_status_error")
  expect_s3_class(e, "zu_error")
  expect_s3_class(e, "error")

  e <- tryCatch(zu_resp_check(resp(502L)), zu_error = function(e) e)
  expect_s3_class(e, "zu_http_server_error")
  expect_false(inherits(e, "zu_http_client_error"))

  # Catching the parent catches both children, which is the point of §34.1.
  expect_error(zu_resp_check(resp(404L)), class = "zu_http_status_error")
  expect_error(zu_resp_check(resp(500L)), class = "zu_http_status_error")

  expect_identical(zu_resp_check(resp(200L)), resp(200L))
})

test_that("a status error message says what to do about it (§34.4)", {
  e <- tryCatch(zu_resp_check(resp(401L, url = "https://api.example.com/x")),
                zu_error = function(e) e)
  msg <- conditionMessage(e)
  expect_match(msg, "401")
  expect_match(msg, "Unauthorized")
  expect_match(msg, "credential")
})

test_that("credentials do not reach a condition's payload (§42.4)", {
  api <- zu_client(headers = c(Authorization = "Bearer SUPERSECRET"),
                   transport = zu_mock_transport(function(req) zu_response(403L)))
  e <- tryCatch(zu_get("https://api.example.com/x?api_key=SUPERSECRET", client = api),
                zu_error = function(e) e)

  flat <- paste(capture.output(str(e)), collapse = " ")
  expect_false(grepl("SUPERSECRET", flat, fixed = TRUE))
  expect_false(grepl("SUPERSECRET", conditionMessage(e), fixed = TRUE))
  # And the request the CALLER still holds is untouched: redaction is a
  # property of the display, not of the object (§42.3).
  expect_identical(unname(api$headers[["Authorization"]]), "Bearer SUPERSECRET")
})

test_that("printing a response redacts credential headers (§42.2)", {
  r <- resp(200L, c(Authorization = "Bearer SECRET", Accept = "*/*"),
            url = "https://h/")
  out <- paste(capture.output(print(r)), collapse = "\n")
  expect_false(grepl("SECRET", out, fixed = TRUE))
  expect_match(out, "<redacted>", fixed = TRUE)
})

test_that("printing a request redacts too", {
  req <- zu_headers(zu_request("GET", "https://x/?api_key=SECRET"),
                    Authorization = "Bearer SECRET")
  out <- paste(capture.output(print(req)), collapse = "\n")
  expect_false(grepl("SECRET", out, fixed = TRUE))
})

test_that("zu_resp_raw() returns decoded bytes", {
  r <- resp(200L, body = charToRaw("plain"))
  expect_identical(rawToChar(zu_resp_raw(r)), "plain")
})

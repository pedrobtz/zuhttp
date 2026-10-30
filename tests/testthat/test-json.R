# §31.7's JSON decision (D-88): zujson in Imports, swappable through
# zu_set_json_backend(). JSON works with nothing else installed.

test_that("zu_body_json() encodes and sets the content type", {
  req <- zu_body_json(
    zu_request("POST", "https://x/"),
    list(name = "Alice", n = 2)
  )
  expect_identical(rawToChar(req$body), '{"name":"Alice","n":2}')
  expect_identical(req$content_type, "application/json")
  expect_identical(req$body_kind, "JSON")
})

test_that("auto_unbox = FALSE is honoured", {
  req <- zu_body_json(
    zu_request("POST", "https://x/"),
    list(n = 2),
    auto_unbox = FALSE
  )
  expect_identical(rawToChar(req$body), '{"n":[2]}')
})

test_that("a body and its response round-trip through the default backend", {
  api <- zu_client(
    transport = zu_mock_transport(function(req) {
      zu_response(200L, c("Content-Type" = "application/json"), req$body)
    })
  )
  sent <- list(name = "Alice", tags = c("a", "b"), n = 2L, ok = TRUE)
  got <- zu_resp_json(zu_post("https://x/", json = sent, client = api))
  expect_identical(got, sent)
})

test_that("arguments reach the parser: an array of objects as a data frame", {
  r <- zu_response(200L, body = '[{"id":1,"v":"a"},{"id":2,"v":"b"}]')
  expect_type(zu_resp_json(r), "list")
  df <- zu_resp_json(r, data_frame = TRUE)
  expect_s3_class(df, "data.frame")
  expect_identical(df$v, c("a", "b"))
})

test_that("a custom backend replaces zujson entirely", {
  old <- zu_set_json_backend(
    encode = function(x, ...) "ENCODED",
    decode = function(txt, ...) list(decoded = txt)
  )
  on.exit(zu_set_json_backend(old$encode, old$decode), add = TRUE)

  req <- zu_body_json(zu_request("POST", "https://x/"), list(a = 1))
  expect_identical(rawToChar(req$body), "ENCODED")
  expect_identical(
    zu_resp_json(zu_response(200L, body = "raw text"))$decoded,
    "raw text"
  )
})

test_that("a backend that returns the wrong shape is caught", {
  old <- zu_set_json_backend(encode = function(x, ...) c("a", "b"))
  on.exit(zu_set_json_backend(old$encode, old$decode), add = TRUE)
  expect_error(
    zu_body_json(zu_request("POST", "https://x/"), list(a = 1)),
    "single string"
  )
})

test_that("an empty or invalid JSON body is a decode error, naming JSON", {
  e <- expect_error(
    zu_resp_json(zu_response(204L)),
    class = "zu_body_decode_error"
  )
  expect_match(conditionMessage(e), "no JSON to parse", fixed = TRUE)
  e <- expect_error(
    zu_resp_json(zu_response(200L, body = "{not json")),
    class = "zu_body_decode_error"
  )
  expect_match(conditionMessage(e), "not valid JSON", fixed = TRUE)
})

# --- XML and HTML: suggested packages ------------------------------------

test_that("zu_resp_xml() parses the body, honouring the HTTP charset", {
  skip_if_not_installed("zuxml")
  # Latin-1 bytes under a declaration that says UTF-8: the HTTP charset wins,
  # as zuxml's own documentation says it should.
  body <- c(
    charToRaw('<?xml version="1.0" encoding="UTF-8"?><t>caf'),
    as.raw(0xE9),
    charToRaw("</t>")
  )
  r <- zu_response(
    200L,
    c("Content-Type" = "application/xml; charset=ISO-8859-1"),
    body
  )
  x <- zu_resp_xml(r)
  expect_identical(zuxml::xml_text(zuxml::xml_root(x)), "café")
})

test_that("zu_resp_html() parses the body and resolves links against the URL", {
  skip_if_not_installed("zuhtml")
  r <- zu_response(
    200L,
    c("Content-Type" = "text/html; charset=utf-8"),
    '<title>Hi</title><a href="/next">n</a>',
    url = "https://example.test/dir/page"
  )
  h <- zu_resp_html(r)
  expect_identical(zuhtml::html_title(h), "Hi")
  # Resolved against the response's URL, which zuhttp passes as base_url;
  # parsed without one, the same link resolves to NA.
  expect_identical(
    zuhtml::html_links(h, absolute = TRUE)$url,
    "https://example.test/next"
  )
})

test_that("an empty or invalid XML or HTML body is a decode error, naming it", {
  skip_if_not_installed("zuxml")
  e <- expect_error(
    zu_resp_xml(zu_response(200L, body = "  \n")),
    class = "zu_body_decode_error"
  )
  expect_match(conditionMessage(e), "no XML to parse", fixed = TRUE)
  e <- expect_error(
    zu_resp_xml(zu_response(200L, body = "<a><b></a>")),
    class = "zu_body_decode_error"
  )
  expect_match(conditionMessage(e), "not valid XML", fixed = TRUE)
  skip_if_not_installed("zuhtml")
  expect_error(zu_resp_html(zu_response(204L)), class = "zu_body_decode_error")
})

test_that("without the suggested package, the accessor names it and the fix", {
  local_mocked_bindings(has_package = function(pkg) FALSE, .package = "zuhttp")
  e <- tryCatch(
    zu_resp_xml(zu_response(200L, body = "<a/>")),
    error = function(e) e
  )
  expect_match(conditionMessage(e), "zuxml", fixed = TRUE)
  expect_match(conditionMessage(e), "install.packages", fixed = TRUE)
  expect_error(zu_resp_html(zu_response(200L, body = "<p>")), "zuhtml")
})

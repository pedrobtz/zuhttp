# §31.7's JSON decision: jsonlite in Suggests, not Imports. The exit criterion
# is two-sided — the helpers must fail clearly without it, and everything else
# must keep working.

test_that("zu_body_json() encodes and sets the content type", {
  skip_if_not_installed("jsonlite")
  req <- zu_body_json(zu_request("POST", "https://x/"), list(name = "Alice", n = 2))
  expect_identical(rawToChar(req$body), '{"name":"Alice","n":2}')
  expect_identical(req$content_type, "application/json")
  expect_identical(req$body_kind, "JSON")
})

test_that("auto_unbox = FALSE is honoured", {
  skip_if_not_installed("jsonlite")
  req <- zu_body_json(zu_request("POST", "https://x/"), list(n = 2), auto_unbox = FALSE)
  expect_identical(rawToChar(req$body), '{"n":[2]}')
})

test_that("without jsonlite the JSON helpers name the package and the fix", {
  local_mocked_bindings(has_jsonlite = function() FALSE)

  e <- tryCatch(zu_body_json(zu_request("POST", "https://x/"), list(a = 1)),
                error = function(e) e)
  msg <- conditionMessage(e)
  expect_match(msg, "jsonlite", fixed = TRUE)
  expect_match(msg, "install.packages", fixed = TRUE)
  expect_match(msg, "zu_set_json_backend", fixed = TRUE)
  # It also has to say what still works, or the reader concludes the package
  # is unusable without jsonlite.
  expect_match(msg, "zu_body_raw", fixed = TRUE)

  expect_error(zu_resp_json(zu_response(200L, body = "{}")), "jsonlite")
})

test_that("everything except the JSON helpers works without jsonlite", {
  local_mocked_bindings(has_jsonlite = function() FALSE)

  api <- zu_client(transport = zu_mock_transport(function(req) {
    zu_response(200L, c("Content-Type" = "application/json"), rawToChar(req$body))
  }))
  # A JSON body the caller serialised themselves: no jsonlite anywhere.
  r <- zu_post("https://x/", body = '{"name":"Alice"}',
               headers = c("Content-Type" = "application/json"), client = api)

  expect_identical(zu_resp_status(r), 200L)
  expect_identical(zu_resp_text(r), '{"name":"Alice"}')
  expect_identical(unname(r$request$headers[["Content-Type"]]), "application/json")
})

test_that("a custom backend replaces jsonlite entirely", {
  old <- zu_set_json_backend(
    encode = function(x, ...) "ENCODED",
    decode = function(txt, ...) list(decoded = txt)
  )
  on.exit(zu_set_json_backend(old$encode, old$decode), add = TRUE)
  local_mocked_bindings(has_jsonlite = function() FALSE)

  req <- zu_body_json(zu_request("POST", "https://x/"), list(a = 1))
  expect_identical(rawToChar(req$body), "ENCODED")
  expect_identical(zu_resp_json(zu_response(200L, body = "raw text"))$decoded,
                   "raw text")
})

test_that("a backend that returns the wrong shape is caught", {
  old <- zu_set_json_backend(encode = function(x, ...) c("a", "b"))
  on.exit(zu_set_json_backend(old$encode, old$decode), add = TRUE)
  expect_error(zu_body_json(zu_request("POST", "https://x/"), list(a = 1)),
               "single string")
})

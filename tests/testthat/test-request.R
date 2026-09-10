# §31.4/§31.6 — request composition. Building a request is a pure operation;
# these tests never reach a transport.

test_that("method and URL are request identity (§31.5)", {
  req <- zu_request("post", "https://x/")
  expect_identical(req$method, "POST")
  expect_identical(req$url, "https://x/")
  # Arbitrary methods stay possible.
  expect_identical(zu_request("PROPFIND", "https://x/")$method, "PROPFIND")
  expect_error(zu_request("BAD METHOD", "https://x/"), "valid HTTP method")
})

test_that("transformers return a new request and leave the original alone", {
  a <- zu_request("GET", "https://x/")
  b <- zu_headers(a, Accept = "text/plain")
  expect_null(a$headers)
  expect_identical(unname(b$headers[["Accept"]]), "text/plain")
})

test_that("zu_headers() accepts a named vector as well as named arguments", {
  a <- zu_headers(zu_request("GET", "https://x/"),
                  c(Accept = "text/plain", "X-A" = "1"))
  b <- zu_headers(zu_request("GET", "https://x/"), Accept = "text/plain", "X-A" = "1")
  expect_identical(a$headers, b$headers)
})

test_that("the body helpers set bytes and an implied content type", {
  expect_identical(rawToChar(zu_body_raw(zu_request("POST", "https://x/"), "hi")$body), "hi")
  expect_identical(zu_body_raw(zu_request("POST", "https://x/"), "hi")$content_type,
                   "text/plain; charset=UTF-8")

  f <- zu_body_form(zu_request("POST", "https://x/"), list(a = "1 2", b = TRUE))
  expect_identical(rawToChar(f$body), "a=1%202&b=true")
  expect_identical(f$content_type, "application/x-www-form-urlencoded")

  path <- tempfile(); on.exit(unlink(path), add = TRUE)
  writeBin(charToRaw("filebytes"), path)
  expect_identical(rawToChar(zu_body_file(zu_request("PUT", "https://x/"), path)$body),
                   "filebytes")
})

test_that("body arguments are mutually exclusive", {
  expect_error(
    zu_post("https://x/", body = "a", json = list(b = 1),
            client = zu_client(transport = zu_mock_transport(function(req) zu_response()))),
    "mutually exclusive"
  )
})

test_that("a request prints its method, URL, headers and body (§31.4)", {
  skip_if_not_installed("jsonlite")
  req <- zu_request("POST", "https://api.example.com/users")
  req <- zu_query(req, verbose = TRUE)
  req <- zu_headers(req, Accept = "application/json")
  req <- zu_body_json(req, list(name = "Alice"))
  req <- zu_req_timeout(req, total = 10)

  out <- paste(capture.output(print(req)), collapse = "\n")
  expect_match(out, "POST https://api.example.com/users?verbose=true", fixed = TRUE)
  expect_match(out, "Accept: application/json", fixed = TRUE)
  expect_match(out, "Content-Type: application/json", fixed = TRUE)
  expect_match(out, "Body: JSON, 16 bytes", fixed = TRUE)
  expect_match(out, "timeout: 10", fixed = TRUE)
})

test_that("the one-shot helpers lower to the same request (§31.1 principle 3)", {
  skip_if_not_installed("jsonlite")
  seen <- NULL
  api <- zu_client(transport = zu_mock_transport(function(req) {
    seen <<- req; zu_response(200L)
  }))

  zu_post("https://x/users", json = list(name = "Alice"), timeout = 10, client = api)
  one_shot <- seen

  req <- zu_request("POST", "https://x/users")
  req <- zu_body_json(req, list(name = "Alice"))
  req <- zu_req_timeout(req, total = 10)
  zu_perform(req, client = api)
  composed <- seen

  # Same wire request, same resolved policy, whichever way it was written.
  expect_identical(one_shot$method, composed$method)
  expect_identical(one_shot$url, composed$url)
  expect_identical(one_shot$headers, composed$headers)
  expect_identical(one_shot$body, composed$body)
  expect_identical(one_shot$resolved, composed$resolved)
})

test_that("every method helper sends its own method", {
  seen <- NULL
  api <- zu_client(transport = zu_mock_transport(function(req) {
    seen <<- req$method; zu_response(200L)
  }))
  for (m in c("get", "head", "post", "put", "patch", "delete")) {
    do.call(paste0("zu_", m), list("https://x/", client = api))
    expect_identical(seen, toupper(m))
  }
})

test_that("the client-first wrappers are wrappers, not overloads (§31.3)", {
  api <- zu_client(base_url = "https://api.example.com",
                   transport = zu_mock_transport(function(req) {
                     zu_response(200L, body = req$url)
                   }))
  expect_identical(zu_resp_text(zu_client_get(api, "/users")),
                   "https://api.example.com/users")
  # And the plain form still refuses a client in argument one, with a message
  # that says what to do rather than failing somewhere in the URL parser.
  expect_error(zu_get(api), "url")
})

test_that("zu_perform() rejects a non-client and a non-request", {
  expect_error(zu_perform(zu_request("GET", "https://x/"), client = list()),
               "must be a zu_client")
  expect_error(zu_perform("https://x/"), "zu_request")
})

test_that("a transport must return a response", {
  api <- zu_client(transport = zu_mock_transport(function(req) "not a response"))
  expect_error(zu_get("https://x/", client = api), "must return a zu_response")
})

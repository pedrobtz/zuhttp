# §31.9's merge rules, stated as tests. The table in the design has three
# rules and two erasers; each gets its own test, because "how do I turn this
# off" is the first question the rules provoke and the answer must not drift.

null_transport <- function(record = NULL) {
  zu_mock_transport(function(req) {
    if (!is.null(record)) record$req <- req
    zu_response(200L)
  })
}

resolved <- function(req, client) zuhttp:::resolve_request(req, client)

test_that("collection-like options combine (headers)", {
  api <- zu_client(headers = c(Accept = "application/json",
                               Authorization = "Bearer xxx"))
  r <- resolved(zu_headers(zu_request("GET", "https://x/"), "X-Debug" = "1"), api)

  expect_setequal(names(r$headers), c("Accept", "Authorization", "X-Debug"))
})

test_that("a request header replaces a same-name client header, case-insensitively", {
  api <- zu_client(headers = c(accept = "text/html"))
  r <- resolved(zu_headers(zu_request("GET", "https://x/"), Accept = "application/json"), api)

  expect_identical(unname(r$headers), "application/json")
  expect_identical(length(r$headers), 1L)   # not two Accept headers on the wire
})

test_that("NA removes an inherited header", {
  api <- zu_client(headers = c(Accept = "application/json",
                               Authorization = "Bearer xxx"))
  r <- resolved(zu_headers(zu_request("GET", "https://x/"), Authorization = NA), api)

  expect_identical(names(r$headers), "Accept")
})

test_that("query parameters combine, and NULL or NA removes one", {
  api <- zu_client(query = list(api_version = "2", trace = "on"))
  req <- zu_query(zu_request("GET", "https://x/"), q = "HTTP", trace = NULL)
  r <- resolved(req, api)

  expect_match(r$url, "api_version=2")
  expect_match(r$url, "q=HTTP")
  expect_false(grepl("trace", r$url, fixed = TRUE))
})

test_that("scalar policy: the request replaces the client's value", {
  api <- zu_client(timeout = 30, redirects = 9L)
  r <- resolved(zu_req_timeout(zu_request("GET", "https://x/"), total = 5), api)

  expect_identical(r$resolved$timeout, 5)
  expect_identical(r$resolved$redirects, 9L)   # untouched fields still inherit
})

test_that("NULL for a policy resets to the package default, not the client's", {
  # The client's value is deliberately NOT the package default here: if it
  # were, this test would pass without the rule being implemented at all.
  api <- zu_client(timeout = 90)
  r <- resolved(zu_req_timeout(zu_request("GET", "https://x/"), NULL), api)

  expect_identical(r$resolved$timeout, zuhttp:::zu_defaults()$timeout)
  expect_false(identical(r$resolved$timeout, 90))
})

test_that("a client with nothing set produces the package defaults", {
  r <- resolved(zu_request("GET", "https://x/"), zu_client())
  expect_identical(r$resolved[names(zuhttp:::zu_defaults())],
                   zuhttp:::zu_defaults())
})

test_that("zu_client_update() does not mutate its argument (§31.10)", {
  api <- zu_client(base_url = "https://api.example.com",
                   headers = c(Accept = "application/json"))
  admin <- zu_client_update(api, headers = c(Authorization = "Bearer admin"))

  expect_identical(names(api$headers), "Accept")
  expect_setequal(names(admin$headers), c("Accept", "Authorization"))
  expect_identical(admin$base_url, api$base_url)
})

test_that("zu_client_update() rejects a setting that does not exist", {
  expect_error(zu_client_update(zu_client(), timout = 5), "not a client setting")
})

test_that("base_url is joined, not resolved", {
  api <- zu_client(base_url = "https://api.example.com/v1")
  # RFC 3986 resolution would drop /v1 here. That surprise is the reason the
  # join is textual (§31.3).
  expect_identical(resolved(zu_request("GET", "/users"), api)$url,
                   "https://api.example.com/v1/users")
  expect_identical(resolved(zu_request("GET", "users"), api)$url,
                   "https://api.example.com/v1/users")
  # An absolute URL ignores base_url entirely.
  expect_identical(resolved(zu_request("GET", "https://other.example/x"), api)$url,
                   "https://other.example/x")
})

test_that("a relative URL with no base_url is a clear error, not a bad request", {
  e <- tryCatch(resolved(zu_request("GET", "/users"), zu_client()),
                zu_url_error = function(e) e)
  expect_s3_class(e, "zu_url_error")
  expect_match(conditionMessage(e), "base_url")
})

test_that("the body's content type loses to an explicit header (§31.2)", {
  skip_if_not_installed("jsonlite")
  req <- zu_body_json(zu_request("POST", "https://x/"), list(a = 1))
  req <- zu_headers(req, "Content-Type" = "application/vnd.api+json")
  r <- resolved(req, zu_client())

  expect_identical(unname(r$headers[["Content-Type"]]), "application/vnd.api+json")
  expect_identical(sum(tolower(names(r$headers)) == "content-type"), 1L)
})

test_that("verify = FALSE warns, wherever it is set", {
  expect_warning(resolved(zu_request("GET", "https://x/"), zu_client(verify = FALSE)),
                 "disables certificate AND hostname")
})

test_that("query values are encoded, and a vector repeats the key", {
  r <- resolved(zu_query(zu_request("GET", "https://x/"),
                         q = "a b&c", ok = TRUE, id = c(1, 2)), zu_client())
  expect_match(r$url, "q=a%20b%26c", fixed = TRUE)
  expect_match(r$url, "ok=true", fixed = TRUE)
  expect_match(r$url, "id=1&id=2", fixed = TRUE)
})

test_that("a URL that already has a query keeps it", {
  r <- resolved(zu_query(zu_request("GET", "https://x/?a=1"), b = "2"), zu_client())
  expect_identical(r$url, "https://x/?a=1&b=2")
})

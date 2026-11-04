# §65 HTTP/2 (W20): the http2 option, how a response reports its version, and
# HTTP/2 against real servers.
#
# The C suite (ctest/test_h2.c) drives the whole engine against an in-process
# nghttp2 server; these tests cover what only R sees, and the live paths: a
# public h2 host on every backend, and a local server whose HTTP/2 is not
# nghttp2's (tools/h2-test-server.py) on the legs that start it.

test_that("http2 is a §31.9 policy: the client sets it, the default is auto", {
  api <- zu_client(http2 = "required")
  r <- resolved(zu_request("GET", "https://x/"), api)
  expect_identical(r$resolved$http2, "required")
  r <- resolved(zu_request("GET", "https://x/"), zu_client())
  expect_identical(r$resolved$http2, "auto")
})

test_that("an http2 setting that is not one of the three words is refused", {
  # A mock transport, so the refusal is shown to happen while the request is
  # resolved, before any transport is asked.
  called <- FALSE
  api <- zu_client(
    http2 = "sometimes",
    transport = zu_mock_transport(function(req) {
      called <<- TRUE
      zu_response(200L)
    })
  )
  expect_error(zu_get("https://x.test/", client = api), "http2")
  expect_false(called)
  api <- zu_client_update(api, http2 = TRUE)
  expect_error(zu_get("https://x.test/", client = api), "http2")
})

test_that("zu_resp_connection() says HTTP/2 for an h2 response, HTTP/1.x otherwise", {
  h2 <- structure(list(http_major = 2L, http_minor = 0L), class = "zu_response")
  h1 <- structure(list(http_major = 1L, http_minor = 1L), class = "zu_response")
  old <- structure(list(http_minor = 0L), class = "zu_response")
  expect_identical(zu_resp_connection(h2)$http_version, "HTTP/2")
  expect_identical(zu_resp_connection(h1)$http_version, "HTTP/1.1")
  # A response recorded before http_major existed (a cassette) is HTTP/1.x.
  expect_identical(zu_resp_connection(old)$http_version, "HTTP/1.0")
})

# --- a public HTTP/2 host, on every backend -----------------------------------
#
# httpbingo.org speaks h2 and echoes the request, so one host answers "which
# protocol?" and "did the body arrive?" for all three TLS stacks.
# (nghttp2.org/httpbin was the first choice and answered 502 on 2026-11-04.)

h2_host <- "https://httpbingo.org"

test_that("§65.1: TLS negotiates h2 by ALPN by default, and the response says so", {
  skip_unless_online()
  r <- zu_get_badssl(paste0(h2_host, "/get"), client = zu_client(pool = NULL))
  expect_identical(zu_resp_status(r), 200L)
  expect_identical(zu_resp_connection(r)$http_version, "HTTP/2")
  expect_identical(zu_resp_json(r)$url, paste0(h2_host, "/get"))
})

test_that("§65.1: http2 = \"off\" offers http/1.1 alone, to the same host", {
  skip_unless_online()
  api <- zu_client(http2 = "off", pool = NULL)
  r <- zu_get_badssl(paste0(h2_host, "/get"), client = api)
  expect_identical(zu_resp_status(r), 200L)
  expect_identical(zu_resp_connection(r)$http_version, "HTTP/1.1")
})

test_that("§65.2: a POST over h2 reaches the server whole", {
  skip_unless_online()
  payload <- "a body sent over HTTP/2"
  r <- zu_post(
    paste0(h2_host, "/post"),
    body = payload,
    headers = c(`Content-Type` = "text/plain"),
    client = zu_client(pool = NULL)
  )
  expect_identical(zu_resp_connection(r)$http_version, "HTTP/2")
  expect_identical(zu_resp_json(r)$data, payload)
})

test_that("§65.2: a pooled h2 connection carries the next request", {
  skip_unless_online()
  api <- zu_client()
  a <- zu_get_badssl(paste0(h2_host, "/get"), client = api)
  b <- zu_get_badssl(paste0(h2_host, "/get"), client = api)
  expect_identical(zu_resp_connection(b)$http_version, "HTTP/2")
  expect_true(zu_resp_connection(b)$reused_connection)
})

test_that("§65.1: http2 = \"required\" refuses a server that only speaks HTTP/1.1", {
  skip_unless_online()
  # badssl.com offers only http/1.1 by ALPN (checked 2026-11-04).
  api <- zu_client(http2 = "required", pool = NULL)
  e <- tryCatch(
    zu_get_badssl("https://badssl.com/", client = api),
    error = function(e) e
  )
  if (inherits(e, "zu_response")) {
    skip(
      "badssl.com now negotiates h2; the refusal needs an HTTP/1.1-only host"
    )
  }
  expect_s3_class(e, "zu_connect_error")
  expect_match(conditionMessage(e), "HTTP/2 is required")
})

# --- a local server whose HTTP/2 is not nghttp2's ------------------------------

skip_unless_h2_server <- function() {
  if (!nzchar(Sys.getenv("ZU_H2_TEST_SERVER"))) {
    skip("set ZU_H2_TEST_SERVER to a tools/h2-test-server.py h2c URL")
  }
}

test_that("§65.1: h2c by prior knowledge: a GET and a POST over cleartext HTTP/2", {
  skip_unless_h2_server()
  base <- Sys.getenv("ZU_H2_TEST_SERVER")
  api <- zu_client(http2 = "required", proxy = FALSE)
  r <- zu_get(paste0(base, "/get?x=1"), client = api)
  j <- zu_resp_json(r)
  expect_identical(j$http_version, "2")
  expect_identical(j$path, "/get")
  expect_identical(j$query, "x=1")
  expect_identical(zu_resp_connection(r)$http_version, "HTTP/2")
  # §65.2: no connection headers on a stream, and no Upgrade dance.
  expect_null(j$headers$connection)
  expect_null(j$headers$upgrade)

  payload <- as.raw(sample(0:255, 70000, replace = TRUE))
  r <- zu_post(paste0(base, "/post"), body = payload, client = api)
  expect_identical(zu_resp_raw(r), payload)
})

test_that("§65.1: with http2 = \"auto\", http:// is HTTP/1.1 to the same server", {
  skip_unless_h2_server()
  base <- Sys.getenv("ZU_H2_TEST_SERVER")
  r <- zu_get(paste0(base, "/get"), client = zu_client(proxy = FALSE))
  expect_identical(zu_resp_json(r)$http_version, "1.1")
  expect_identical(zu_resp_connection(r)$http_version, "HTTP/1.1")
})

test_that("§65.1: h2 over TLS to a local server, GET and POST", {
  skip_unless_h2_server()
  base <- Sys.getenv("ZU_H2_TEST_TLS")
  ca <- Sys.getenv("ZU_H2_TEST_CA")
  if (!nzchar(base) || !nzchar(ca)) {
    skip("ZU_H2_TEST_TLS and ZU_H2_TEST_CA unset")
  }
  skip_unless_tls_supports("ca_file")
  api <- zu_client(tls = zu_tls(ca_file = ca), proxy = FALSE)
  r <- zu_get(paste0(base, "/get"), client = api)
  expect_identical(zu_resp_json(r)$http_version, "2")
  expect_identical(zu_resp_connection(r)$http_version, "HTTP/2")
  payload <- charToRaw("over TLS and HTTP/2")
  r <- zu_post(paste0(base, "/post"), body = payload, client = api)
  expect_identical(zu_resp_raw(r), payload)
  off <- zu_client_update(api, http2 = "off")
  r <- zu_get(paste0(base, "/get"), client = off)
  expect_identical(zu_resp_json(r)$http_version, "1.1")
})

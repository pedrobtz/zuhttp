# §63.2 vertical slice, from R.
#
# Every test here needs the network, so every test skips on CRAN and when
# offline. CRAN policy forbids network access in checks, and a test that
# depends on a third-party host is a flake waiting to happen — these exist to
# prove the stack composes, and the deterministic coverage lives in ctest/.

# Gated on an explicit opt-in, not merely on NOT_CRAN.
#
# rcmdcheck sets NOT_CRAN=true, so skip_on_cran() alone would make every
# R-CMD-check run depend on example.com, github.com and badssl.com. That is
# the same mistake as the DNS lookup inside the "offline" C suite: the
# deterministic job must stay deterministic. The network-enabled job in
# tls-spike.yaml sets ZU_TEST_NETWORK=1.
skip_unless_online <- function() {
  testthat::skip_on_cran()
  if (!identical(Sys.getenv("ZU_TEST_NETWORK"), "1"))
    testthat::skip("set ZU_TEST_NETWORK=1 to run network tests")
  testthat::skip_if_offline()
}

test_that("a plain HTTPS GET returns a usable response", {
  skip_unless_online()
  r <- zu_get("https://example.com")

  expect_s3_class(r, "zu_response")
  expect_identical(zu_resp_status(r), 200L)
  expect_true(is.raw(zu_resp_raw(r)))
  expect_gt(length(zu_resp_raw(r)), 0)
  expect_match(zu_resp_text(r), "Example Domain", fixed = TRUE)
  expect_identical(zu_resp_url(r), "https://example.com/")
})

test_that("TLS is actually used and reported", {
  skip_unless_online()
  r <- zu_get("https://example.com")
  # If this is NULL the request silently went out in the clear.
  expect_true(!is.null(r$tls_version))
  expect_match(r$tls_version, "^TLSv1\\.[23]$")
})

test_that("headers are addressable and keep duplicates (§18.3)", {
  skip_unless_online()
  r <- zu_get("https://example.com")
  h <- zu_resp_headers(r)
  expect_true(is.character(h))
  expect_true(!is.null(names(h)))
  expect_true("Content-Type" %in% names(h))
})

test_that("one redirect is followed and the final URL is reported", {
  skip_unless_online()
  r <- zu_get("http://github.com/")
  expect_identical(zu_resp_status(r), 200L)
  expect_identical(r$redirects, 1L)
  expect_match(zu_resp_url(r), "^https://")
})

test_that("the redirect budget is respected", {
  skip_unless_online()
  r <- zu_get("http://github.com/", redirects = 0L, check = FALSE)
  expect_gte(zu_resp_status(r), 300L)
  expect_lt(zu_resp_status(r), 400L)
  expect_identical(r$redirects, 0L)
})

test_that("certificate verification is on and raises a catchable condition", {
  skip_unless_online()
  e <- tryCatch(zu_get("https://expired.badssl.com/"),
                zu_tls_error = function(e) e)

  # The whole §34.1 point: a caller can catch "any TLS problem" without
  # enumerating the leaves.
  expect_s3_class(e, "zu_tls_certificate_error")
  expect_s3_class(e, "zu_tls_error")
  expect_s3_class(e, "zu_error")
  expect_identical(e$phase, "tls")
  expect_false(e$retryable)
  expect_match(conditionMessage(e), "expired")
})

test_that("a hostname mismatch is a distinct class from a bad chain", {
  skip_unless_online()
  e <- tryCatch(zu_get("https://wrong.host.badssl.com/"),
                zu_tls_error = function(e) e)
  expect_s3_class(e, "zu_tls_hostname_error")
  # Distinct, not merely "some TLS error": a user can tell these apart.
  expect_false(inherits(e, "zu_tls_certificate_error"))
})

test_that("a non-HTTP scheme is refused before any connection is made", {
  # No network needed: this fails in the URL policy layer (§8.2).
  e <- tryCatch(zu_get("ftp://example.com/"), zu_url_error = function(e) e)
  expect_s3_class(e, "zu_url_error")
  expect_s3_class(e, "zu_error")
})

test_that("verify = FALSE warns loudly", {
  expect_warning(
    tryCatch(zu_get("https://expired.badssl.com/", verify = FALSE, timeout = 5),
             zu_error = function(e) NULL),
    "disables certificate AND hostname"
  )
})

test_that("the total timeout is enforced", {
  skip_unless_online()
  e <- tryCatch(zu_get("https://example.com", timeout = 0.001),
                zu_error = function(e) e)
  expect_s3_class(e, "zu_error")
})

test_that("an error status raises by default and is inspectable with check = FALSE", {
  skip_unless_online()
  expect_error(zu_get("https://httpbin.org/status/404", timeout = 30),
               class = "zu_http_client_error")
  r <- zu_get("https://httpbin.org/status/404", check = FALSE, timeout = 30)
  expect_identical(zu_resp_status(r), 404L)
})

test_that("a JSON POST reaches the server as JSON", {
  skip_unless_online()
  skip_if_not_installed("jsonlite")
  r <- zu_post("https://httpbin.org/post", json = list(name = "Alice", active = TRUE),
               timeout = 30)
  echo <- zu_resp_json(r)
  expect_identical(echo$data, '{"name":"Alice","active":true}')
  expect_identical(echo$headers$`Content-Type`, "application/json")
})

test_that("decode = FALSE returns the wire bytes (§21.2)", {
  skip_unless_online()
  decoded <- zu_get("https://httpbin.org/gzip", timeout = 30)
  wire    <- zu_get("https://httpbin.org/gzip", decode = FALSE, timeout = 30)

  expect_identical(zu_resp_header(decoded, "content-encoding"), character())
  expect_identical(zu_resp_header(wire, "content-encoding"), "gzip")
  # The gzip magic number: these really are the bytes the server sent.
  expect_identical(head(zu_resp_raw(wire), 2), as.raw(c(0x1f, 0x8b)))
})

test_that("a client's base_url and headers reach the server", {
  skip_unless_online()
  skip_if_not_installed("jsonlite")
  api <- zu_client(base_url = "https://httpbin.org",
                   headers = c("X-Zu-Test" = "1"), timeout = 30)
  echo <- zu_resp_json(zu_get("/get", query = list(q = "a b"), client = api))
  expect_identical(echo$headers$`X-Zu-Test`, "1")
  expect_identical(echo$args$q, "a b")
})

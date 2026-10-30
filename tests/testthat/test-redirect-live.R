# §19 against real servers: two local httpbin apps (webfakes), so "another
# origin" is a different port on 127.0.0.1 — which §19.2 counts as a
# different origin, exactly like a different host.
#
# Every test here failed before 2026-09-26: the engine computed
# dec.strip_credentials and never read it, so Authorization followed a
# redirect anywhere; Host dropped a non-default port; and an exhausted
# redirect chain returned its last 3xx as a normal response.

# Two origins from local_httpbin() (helper-origin.R), started on first use and
# shared across these tests; redirect_to() is there too.

test_that("a cross-origin redirect drops credentials and keeps the rest (§19.2)", {
  a <- local_httpbin("a")
  b <- local_httpbin("b")
  # Every §42.1 default, not only the two everyone remembers (#76 finding 3).
  secrets <- c(Authorization = "Bearer s3cret", Cookie = "session=abc",
               "X-Api-Key" = "k", "X-Auth-Token" = "t", "X-Keep" = "1")
  r <- zu_get(redirect_to(a, b$url("/headers")), headers = secrets, redirects = 1)
  expect_identical(zu_resp_url(r), b$url("/headers"))
  h <- zu_resp_json(r)$headers
  names(h) <- tolower(names(h))
  for (nm in c("authorization", "cookie", "x-api-key", "x-auth-token"))
    expect_null(h[[nm]], label = nm)
  expect_identical(h[["x-keep"]], "1")
})

test_that("a same-origin redirect keeps credentials", {
  a <- local_httpbin("a")
  secrets <- c(Authorization = "Bearer s3cret", Cookie = "session=abc", "X-Keep" = "1")
  # The control: without it, a client that dropped Authorization on EVERY
  # redirect would pass the test above.
  r <- zu_get(redirect_to(a, a$url("/headers")), headers = secrets, redirects = 1)
  h <- zu_resp_json(r)$headers
  expect_identical(h$Authorization, "Bearer s3cret")
  expect_identical(h$Cookie, "session=abc")
})

test_that("credentials do not come back when the chain returns to the first origin", {
  a <- local_httpbin("a")
  b <- local_httpbin("b")
  secrets <- c(Authorization = "Bearer s3cret", Cookie = "session=abc", "X-Keep" = "1")
  back_to_a <- redirect_to(b, a$url("/headers"))
  r <- zu_get(redirect_to(a, back_to_a), headers = secrets, redirects = 2)
  expect_identical(zu_resp_url(r), a$url("/headers"))
  expect_null(zu_resp_json(r)$headers$Authorization)
})

test_that("Host carries a non-default port (RFC 9112 §3.2)", {
  a <- local_httpbin("a")
  r <- zu_get(a$url("/headers"))
  port <- sub("^http://127\\.0\\.0\\.1:([0-9]+)/.*$", "\\1", a$url("/"))
  expect_identical(zu_resp_json(r)$headers$Host, paste0("127.0.0.1:", port))
})

test_that("an exhausted redirect chain raises; redirects = 0 returns the 3xx (§19.4)", {
  a <- local_httpbin("a")
  expect_error(zu_get(a$url("/redirect/3"), redirects = 2),
               class = "zu_too_many_redirects")
  expect_identical(zu_resp_status(zu_get(a$url("/redirect/2"), redirects = 2)), 200L)
  r <- zu_get(a$url("/redirect/1"), redirects = 0)
  expect_identical(zu_resp_status(r), 302L)
})

test_that("303 turns POST into a bodiless GET; 307 keeps method and body (§19.1)", {
  a <- local_httpbin("a")
  r <- zu_post(redirect_to(a, a$url("/anything"), status_code = 303),
               body = "payload", redirects = 1)
  expect_identical(toupper(zu_resp_json(r)$method), "GET")
  expect_length(zu_resp_json(r)$data, 0)   # httpbin echoes no body as list()
  r <- zu_post(redirect_to(a, a$url("/anything"), status_code = 307),
               body = "payload", redirects = 1)
  expect_identical(toupper(zu_resp_json(r)$method), "POST")
  expect_identical(zu_resp_json(r)$data, "payload")
})

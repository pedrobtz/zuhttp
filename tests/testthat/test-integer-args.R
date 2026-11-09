# Every argument that reaches as.integer() against one boundary table (#232).
#
# #221 and #222 were one bug twice: zu_pool() bounded its counts by
# .Machine$integer.max, and `redirects` and zu_retry(attempts =) did not, so
# 1e10 became NA and failed far from the call. A fraction was truncated
# without a word everywhere. This table is the class, not the instances: a
# new integer argument belongs in it.

test_that("every integer argument refuses what as.integer() would mangle (#232)", {
  mock <- zu_client(transport = zu_mock_transport(function(req) zu_response()))
  args <- list(
    max_idle = list(min = 1, max = .Machine$integer.max, f = function(x) {
      zu_pool(max_idle = x)$max_idle
    }),
    max_per_host = list(min = 1, max = .Machine$integer.max, f = function(x) {
      zu_pool(max_per_host = x)$max_per_host
    }),
    attempts = list(min = 1, max = .Machine$integer.max, f = function(x) {
      zu_retry(attempts = x)$attempts
    }),
    req_attempts = list(min = 1, max = .Machine$integer.max, f = function(x) {
      zu_req_retry(
        zu_request("GET", "http://h.test/"),
        attempts = x
      )$policy$retry$attempts
    }),
    redirects = list(min = 0, max = .Machine$integer.max, f = function(x) {
      zu_get("http://h.test/", redirects = x, client = mock)
      as.integer(x)
    }),
    response_redirects = list(
      min = 0,
      max = .Machine$integer.max,
      f = function(x) {
        zu_response(redirects = x)$redirects
      }
    ),
    status = list(min = 100, max = 599, f = function(x) {
      zu_response(status = x)$status
    }),
    retry_on = list(min = 100, max = 599, f = function(x) {
      zu_retry(on = x)$on
    })
  )
  for (nm in names(args)) {
    a <- args[[nm]]
    bad <- list(
      NA,
      NA_real_,
      a$min - 1,
      a$max + 1,
      Inf,
      -Inf,
      NaN,
      1e10,
      a$min + 0.5,
      "3",
      TRUE
    )
    for (b in bad) {
      expect_error(a$f(b), "whole number", info = paste(nm, format(b)))
    }
    expect_identical(a$f(a$min), as.integer(a$min), info = nm)
    expect_identical(a$f(a$max), as.integer(a$max), info = nm)
  }
})

test_that("a vector argument is checked element by element (#232)", {
  expect_identical(zu_retry(on = c(418, 425))$on, c(418L, 425L))
  expect_identical(zu_retry(on = integer())$on, integer())
  expect_error(zu_retry(on = c(418, 1e10)), "whole number")
  expect_error(zu_retry(on = c(418, NA)), "whole number")
  # Scalars stay scalars.
  expect_error(zu_pool(max_idle = c(1, 2)), "whole number")
})

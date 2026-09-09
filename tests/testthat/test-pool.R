# §26 from R. Most of this needs no network: a pool can be created, keyed,
# serialized and re-created without a single connection existing, and those
# are the parts §26.5 is actually about. The reuse tests at the bottom need a
# server and are gated like the rest of the network suite.

# Internals, reached the way the rest of this suite reaches them.
client_pool <- function(...) zuhttp:::client_pool(...)
pool_valid  <- function(ptr) .Call(zuhttp:::C_zu_pool_valid, ptr)

# --- configuration -------------------------------------------------------

test_that("zu_pool() validates its arguments and carries §26.2's defaults", {
  p <- zu_pool()
  expect_s3_class(p, "zu_pool_config")
  expect_identical(p$max_idle, 16L)
  expect_identical(p$max_per_host, 4L)
  expect_identical(p$idle_timeout_ms, 30000L)

  expect_identical(zu_pool(idle_timeout = 0.5)$idle_timeout_ms, 500L)

  expect_error(zu_pool(max_idle = 0), "at least 1")
  expect_error(zu_pool(max_idle = NA), "at least 1")
  expect_error(zu_pool(max_per_host = "four"), "at least 1")
  expect_error(zu_pool(max_idle = c(1, 2)), "at least 1")
})

test_that("a client pools by default and can opt out", {
  expect_s3_class(zu_client()$pool, "zu_pool_config")
  expect_null(zu_client(pool = NULL)$pool)
  expect_null(client_pool(zu_client(pool = NULL)))
})

test_that("a bad pool setting is rejected rather than silently ignored", {
  bad <- zu_client()
  bad$pool <- list(max_idle = 4)
  expect_error(client_pool(bad), "must be zu_pool\\(\\) or NULL")
})

# --- lazy creation, §26.5 ------------------------------------------------

test_that("the native pool is created on demand, once, and reused", {
  api <- zu_client()
  expect_null(zu_pool_stats(api))          # nothing built yet

  p1 <- client_pool(api)
  expect_true(pool_valid(p1))
  expect_identical(client_pool(api), p1)   # second call does not rebuild

  # Now it reports, and reports zeroes rather than NULL.
  st <- zu_pool_stats(api)
  expect_type(st, "double")
  expect_identical(st[["hits"]], 0)
  expect_identical(st[["idle"]], 0)
})

test_that("changing pool settings rebuilds the pool rather than keeping the old policy", {
  api <- zu_client(pool = zu_pool(max_idle = 2))
  p1  <- client_pool(api)
  derived <- zu_client_update(api, pool = zu_pool(max_idle = 8))
  p2 <- client_pool(derived)
  # Same external pointer would mean the new max_idle was silently ignored.
  expect_false(identical(p1, p2))
  expect_true(pool_valid(p2))
})

test_that("a client survives saveRDS()/readRDS() and re-creates its pool (§26.5)", {
  api <- zu_client(base_url = "https://example.com", pool = zu_pool(max_idle = 3))
  live <- client_pool(api)
  expect_true(pool_valid(live))

  f <- tempfile(fileext = ".rds"); on.exit(unlink(f), add = TRUE)
  saveRDS(api, f)
  restored <- readRDS(f)

  # Configuration is plain R data and must come back intact...
  expect_identical(restored$base_url, "https://example.com")
  expect_identical(restored$pool$max_idle, 3L)

  # ...the pointer is not. This is the assertion that makes the test
  # non-vacuous: a client that carried no native state at all would pass
  # every other line here without proving anything about §26.5.
  stale <- attr(restored, "pool_state")$ptr
  expect_true(inherits(stale, "externalptr"))
  expect_false(pool_valid(stale))
  expect_null(zu_pool_stats(restored))

  # Lazy re-creation, rather than an error.
  fresh <- client_pool(restored)
  expect_true(pool_valid(fresh))
  expect_false(identical(fresh, stale))
})

test_that("zu_pool_reset() drops idle connections without touching config", {
  api <- zu_client(pool = zu_pool(max_idle = 5))
  invisible(client_pool(api))
  expect_identical(zu_pool_reset(api), api)
  expect_identical(api$pool$max_idle, 5L)
  expect_identical(zu_pool_stats(api)[["idle"]], 0)
})

# --- reuse over a real connection ----------------------------------------

test_that("a second request to the same origin reuses the connection", {
  skip_unless_online()
  api <- zu_client()
  for (i in 1:3) expect_identical(zu_resp_status(zu_get("https://example.com", client = api)), 200L)

  st <- zu_pool_stats(api)
  # Non-vacuous: with pooling removed this is 0 hits and 3 misses.
  expect_identical(st[["misses"]], 1)
  expect_identical(st[["hits"]], 2)
  expect_identical(st[["idle"]], 1)
})

test_that("pooling can be switched off per client", {
  skip_unless_online()
  api <- zu_client(pool = NULL)
  for (i in 1:2) expect_identical(zu_resp_status(zu_get("https://example.com", client = api)), 200L)
  expect_null(zu_pool_stats(api))
})

test_that("the §26.1 key refuses to share across a TLS-config difference", {
  skip_unless_online()
  api <- zu_client()
  expect_identical(zu_resp_status(zu_get("https://example.com", client = api)), 200L)

  # Same origin, different verification. §26.1 calls a key that ignores this
  # "a security bug, not a performance optimisation" — reusing here would run
  # an unverified request over a verified connection.
  suppressWarnings(
    expect_identical(
      zu_resp_status(zu_get("https://example.com", verify = FALSE, client = api)), 200L)
  )
  expect_identical(zu_pool_stats(api)[["hits"]], 0)
  expect_identical(zu_pool_stats(api)[["misses"]], 2)
})

test_that("a different host does not reuse another host's connection", {
  skip_unless_online()
  api <- zu_client()
  expect_identical(zu_resp_status(zu_get("https://example.com", client = api)), 200L)
  expect_identical(zu_resp_status(zu_get("https://www.iana.org", client = api)), 200L)
  expect_identical(zu_pool_stats(api)[["hits"]], 0)
})

test_that("a pooled client under mclapply() drops inherited connections (§26.4)", {
  skip_unless_online()
  testthat::skip_if_not_installed("parallel")
  if (.Platform$OS.type == "windows") skip("fork() is POSIX-only")

  api <- zu_client()
  # Plain HTTP deliberately. Hazard 2 (the macOS trust evaluator, R-12) would
  # otherwise mask hazard 1 on macOS, and hazard 1 — inherited SOCKETS — is
  # what this test is about. test-fork.R covers hazard 2.
  expect_identical(zu_resp_status(zu_get("http://example.com", client = api)), 200L)
  expect_identical(zu_pool_stats(api)[["idle"]], 1)

  res <- parallel::mclapply(1:2, function(i) {
    r  <- zu_get("http://example.com", client = api)
    st <- zu_pool_stats(api)
    list(status = zu_resp_status(r), forks = st[["forks_detected"]],
         dropped = st[["discarded_fork"]], hits = st[["hits"]])
  }, mc.cores = 2)

  for (r in res) {
    expect_false(is.null(r))               # the child survived
    expect_identical(r$status, 200L)       # and completed its own request
    expect_identical(r$forks, 1)           # the PID guard fired
    expect_identical(r$dropped, 1)         # the inherited connection was dropped
    expect_identical(r$hits, 0)            # and NOT reused, which is the point
  }

  # The parent never forked, so its own connection is untouched and usable.
  expect_identical(zu_pool_stats(api)[["idle"]], 1)
  expect_identical(zu_resp_status(zu_get("http://example.com", client = api)), 200L)
  expect_identical(zu_pool_stats(api)[["hits"]], 1)
})

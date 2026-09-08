# §31.16 requires the API to be prototyped against thirteen workflows before it
# is frozen. This is that list, executable, one test per workflow and numbered
# to match the design.
#
# Everything runs against a mock transport (§31.12), so the file is
# deterministic and CRAN-safe: it exercises the API, not the network.

# A transport that records what it was asked to do and answers from a script.
recorder <- function(respond = function(req) zu_response(200L, body = "ok")) {
  calls <- list()
  t <- zu_mock_transport(function(req) {
    calls[[length(calls) + 1L]] <<- req
    respond(req)
  })
  list(transport = t, calls = function() calls, n = function() length(calls))
}

test_that("1. one-line GET", {
  rec <- recorder(function(req) zu_response(200L, body = "hello"))
  r <- zu_get("https://example.com", client = zu_client(transport = rec$transport))

  expect_s3_class(r, "zu_response")
  expect_identical(zu_resp_status(r), 200L)
  expect_identical(zu_resp_text(r), "hello")
  expect_identical(rec$calls()[[1]]$method, "GET")
})

test_that("2. JSON POST", {
  skip_if_not_installed("jsonlite")
  rec <- recorder(function(req) zu_response(201L, body = "{}"))
  r <- zu_post("https://api.example.com/users", json = list(name = "Alice"),
               client = zu_client(transport = rec$transport))

  sent <- rec$calls()[[1]]
  expect_identical(sent$method, "POST")
  expect_identical(rawToChar(sent$body), '{"name":"Alice"}')
  # json = sets the content type, and does it as a header the transport sees.
  expect_identical(unname(sent$headers[["Content-Type"]]), "application/json")
  expect_identical(zu_resp_status(r), 201L)
})

test_that("3. API client with bearer token and base URL", {
  rec <- recorder()
  api <- zu_client(
    base_url = "https://api.example.com",
    headers  = c(Accept = "application/json", Authorization = "Bearer tok"),
    transport = rec$transport
  )
  zu_get("/users", client = api)
  zu_get("/teams", client = api)

  urls <- vapply(rec$calls(), function(r) r$url, character(1))
  expect_identical(urls, c("https://api.example.com/users",
                           "https://api.example.com/teams"))
  expect_identical(unname(rec$calls()[[1]]$headers[["Authorization"]]), "Bearer tok")
})

test_that("4. a package builds a request without performing it", {
  rec <- recorder()
  # This is the §31.1 principle 2 claim: composition performs no I/O.
  req <- zu_request("POST", "https://api.example.com/users")
  req <- zu_query(req, verbose = TRUE)
  req <- zu_headers(req, Accept = "application/json")
  req <- zu_body_raw(req, '{"name":"Alice"}', type = "application/json")
  req <- zu_req_timeout(req, total = 10)

  expect_s3_class(req, "zu_request")
  expect_identical(rec$n(), 0L)         # nothing has happened yet

  zu_perform(req, client = zu_client(transport = rec$transport))
  expect_identical(rec$n(), 1L)
  expect_identical(rec$calls()[[1]]$url,
                   "https://api.example.com/users?verbose=true")
  expect_identical(rec$calls()[[1]]$resolved$timeout, 10)
})

test_that("5. retried idempotent request", {
  # §31.16 workflow 5, unblocked by S13. The point of the workflow is that a
  # caller writes one line and gets bounded, safe retrying — not that the
  # mechanism exists somewhere.
  n <- 0L
  flaky <- zu_mock_transport(function(req) {
    n <<- n + 1L
    if (n < 3L) zu_response(503L) else zu_response(200L, body = '{"ok":true}',
                                                  headers = c("Content-Type" = "application/json"))
  })
  r <- zu_get("https://api.example.com/things",
              retry = zu_retry(attempts = 3, base = 0.01),
              client = zu_client(transport = flaky))

  expect_identical(zu_resp_status(r), 200L)
  expect_true(zu_resp_json(r)$ok)
  expect_identical(n, 3L)
  expect_identical(r$attempts, 3L)
})

test_that("6. streaming download", {
  skip("streaming sinks are S17; today every body is a memory body")
})

test_that("7. mocked package test", {
  # The workflow a package author actually cares about: their function, their
  # test, no network, no server, no internet-dependent CRAN check.
  user_name <- function(id, client = zu_default_client()) {
    zu_resp_json(zu_get(paste0("/users/", id), client = client))$name
  }
  fake <- zu_mock_transport(function(req) {
    if (grepl("/users/7$", req$url))
      zu_response(200L, c("Content-Type" = "application/json"),
                  '{"name":"Alice"}')
    else
      zu_response(404L, c("Content-Type" = "application/json"), '{}')
  })
  api <- zu_client(base_url = "https://api.example.com", transport = fake)

  skip_if_not_installed("jsonlite")
  expect_identical(user_name(7, api), "Alice")
  expect_error(user_name(8, api), class = "zu_http_client_error")
})

test_that("8. a request timeout overrides the client's", {
  rec <- recorder()
  api <- zu_client(timeout = 30, transport = rec$transport)
  zu_get("https://example.com/slow", timeout = 5, client = api)
  zu_get("https://example.com/normal", client = api)
  # §31.9's third rule: NULL is not "the client's value", it is the package's.
  zu_get("https://example.com/reset", timeout = NULL, client = api)

  got <- vapply(rec$calls(), function(r) r$resolved$timeout, numeric(1))
  expect_identical(got, c(5, 30, 30))
  expect_identical(got[[3]], zuhttp:::zu_defaults()$timeout)
})

test_that("9. redirect and error inspection", {
  api <- zu_client(transport = zu_mock_transport(function(req) {
    zu_response(503L, c("Content-Type" = "text/plain"),
                "upstream unavailable", redirects = 2L)
  }))
  r <- zu_get("https://example.com", check = FALSE, client = api)

  expect_identical(zu_resp_status(r), 503L)
  expect_false(zu_resp_ok(r))
  expect_identical(r$redirects, 2L)

  e <- tryCatch(zu_resp_check(r), zu_http_server_error = function(e) e)
  expect_s3_class(e, "zu_http_status_error")
  expect_s3_class(e, "zu_error")
  # §34.4: the server's own words, not just a number.
  expect_match(conditionMessage(e), "upstream unavailable")
})

test_that("10. many requests share one client", {
  rec <- recorder()
  api <- zu_client(transport = rec$transport)
  for (i in 1:5) zu_get(paste0("https://example.com/", i), client = api)
  expect_identical(rec$n(), 5L)
  # That these five share a connection pool is S16's claim to prove; the pool
  # is C-side and not yet wired to the R client. This asserts only what is
  # true today: one client object serves many requests.
})

test_that("11. a client used inside mclapply (§26.4)", {
  skip_on_os("windows")                      # no fork()
  skip_if_not_installed("parallel")
  api <- zu_client(transport = zu_mock_transport(function(req) {
    zu_response(200L, body = paste0("pid=", Sys.getpid()))
  }))
  # Populate the parent's default client FIRST. Without this the test passes
  # for the wrong reason: an unset default is trivially "not inherited".
  zu_default_client()
  parent_pid <- zuhttp:::the_default$pid
  expect_identical(parent_pid, Sys.getpid())

  out <- parallel::mclapply(1:2, function(i) {
    zu_default_client()                       # the PID guard runs here
    list(text = zu_resp_text(zu_get("https://example.com", client = api)),
         default_pid = zuhttp:::the_default$pid,
         pid = Sys.getpid())
  }, mc.cores = 2)

  expect_true(all(vapply(out, function(o) grepl("^pid=", o$text), logical(1))))
  for (o in out) {
    # §26.4: the child re-creates the default client rather than inheriting
    # the parent's, which is what stops it inheriting the parent's pool.
    expect_identical(o$default_pid, o$pid)
    expect_false(identical(o$default_pid, parent_pid))
  }
})

test_that("12. a client survives saveRDS() and a new session (§26.5)", {
  path <- tempfile(fileext = ".rds")
  on.exit(unlink(path), add = TRUE)
  api <- zu_client(base_url = "https://api.example.com",
                   headers = c(Accept = "application/json"),
                   timeout = 7,
                   transport = zu_mock_transport(function(req) {
                     zu_response(200L, body = req$url)
                   }))
  saveRDS(api, path)

  # A genuinely new session, because the point is that nothing in the object
  # depends on this process.
  #
  # From a FILE, not Rscript -e: a multi-line -e argument is what made S8's
  # Windows runs die before executing anything, and backslashes in a Windows
  # tempfile path would not survive being pasted into a string literal either.
  script <- tempfile(fileext = ".R")
  on.exit(unlink(script), add = TRUE)
  writeLines(c(
    'suppressMessages(library(zuhttp))',
    sprintf('api <- readRDS("%s")', normalizePath(path, winslash = "/")),
    'r <- zu_get("/users", client = api)',
    'cat(zu_resp_text(r), zu_get("/x", client = api)$request$resolved$timeout)'
  ), script)
  out <- system2(file.path(R.home("bin"), "Rscript"), c("--vanilla", shQuote(script)),
                 stdout = TRUE, stderr = TRUE)
  expect_identical(paste(out, collapse = " "),
                   "https://api.example.com/users 7")
})

test_that("13. text from a server that sends no charset (§31.7)", {
  # Latin-1 bytes, no charset parameter: step 4 of the chain applies and the
  # default is UTF-8, so these bytes are NOT valid and must be reported rather
  # than silently mangled.
  latin1 <- as.raw(c(0x63, 0x61, 0x66, 0xE9))     # "café" in ISO-8859-1
  api <- zu_client(transport = zu_mock_transport(function(req) {
    zu_response(200L, c("Content-Type" = "text/plain"), latin1)
  }))
  r <- zu_get("https://example.com", client = api)

  expect_error(zu_resp_text(r), class = "zu_body_decode_error")
  expect_identical(zu_resp_text(r, encoding = "ISO-8859-1"), "café")
  expect_match(zu_resp_text(r, on_invalid = "substitute"), "^caf")

  # And the ordinary case: UTF-8 bytes with no charset decode cleanly.
  api2 <- zu_client(transport = zu_mock_transport(function(req) {
    zu_response(200L, c("Content-Type" = "text/plain"),
                charToRaw(enc2utf8("café")))
  }))
  expect_identical(zu_resp_text(zu_get("https://example.com", client = api2)),
                   "café")
})

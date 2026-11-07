# The exported surface the critical review of 8afb36c found untested (#195),
# and the regressions for the fixes it asked for. Offline, every one; inputs
# are built inside each test.

# --- #177: a form body with a NUL does not replace the HTTP error -----------

test_that("a NUL in a form-typed raw body leaves the HTTP error class intact (#177)", {
  cli <- zu_client(
    transport = zu_mock_transport(function(req) zu_response(404L)),
    check = TRUE
  )
  req <- zu_body_raw(
    zu_request("POST", "https://api.example.com/x"),
    as.raw(c(0x61, 0x00, 0x62)),
    type = "application/x-www-form-urlencoded"
  )
  expect_error(zu_perform(req, client = cli), class = "zu_http_client_error")
  # The condition carries the request, redacted, with the body as bytes.
  cnd <- tryCatch(
    zu_perform(req, client = cli),
    zu_http_client_error = identity
  )
  expect_true(is.raw(cnd$request$body))
})

test_that("a form body with a secret is redacted for display, as bytes (#177)", {
  req <- zu_body_form(
    zu_request("POST", "https://api.example.com/x"),
    list(user = "u", password = "hunter2")
  )
  shown <- zuhttp:::redact_request_fields(req)
  expect_true(is.raw(shown$body))
  expect_match(rawToChar(shown$body), "password=<redacted>", fixed = TRUE)
  expect_no_match(rawToChar(shown$body), "hunter2", fixed = TRUE)
  # The request itself is untouched (§42.3).
  expect_match(rawToChar(req$body), "hunter2", fixed = TRUE)
})

# --- #180: an oversized text is the marker, never an error -------------------

test_that("redacting a text past the bound gives the marker, not an error (#180)", {
  skip_on_cran() # a few MiB of string building
  too_long <- paste0("https://h/?", strrep("a", 2^20 + 10))
  expect_identical(zu_redact_url(too_long), "<redacted>")
  # Within the input bound, but the redaction outgrows the output bound.
  grows <- paste0("https://h/?", strrep("sig=1&", 2^20 %/% 6))
  expect_identical(zu_redact_url(grows), "<redacted>")
  # And a URL that fits is still redacted in place.
  expect_identical(
    zu_redact_url("https://h/?sig=1&page=2"),
    "https://h/?sig=<redacted>&page=2"
  )
})

# --- #202: hooks are validated where middleware is ---------------------------

test_that("zu_client(hooks = ) refuses what zu_hooks() would not make (#202)", {
  expect_error(zu_client(hooks = function(p) NULL), "must come from zu_hooks()")
  expect_error(
    zu_client(hooks = list(function(p) NULL)),
    "must come from zu_hooks()"
  )
  expect_error(
    zu_client(hooks = list(on_fire = function(p) NULL)),
    "must come from zu_hooks()"
  )
  expect_error(zu_client(hooks = "verbose"), "must come from zu_hooks()")
})

test_that("zu_client(hooks = ) accepts zu_hooks(), NULL and a named list of handlers (#202)", {
  seen <- character()
  h <- zu_hooks(before_request = function(p) seen <<- c(seen, p$request$url))
  mock <- zu_mock_transport(function(req) zu_response(200L))
  expect_s3_class(zu_client(hooks = h)$hooks, "zu_hooks")
  expect_identical(zu_client(hooks = NULL)$hooks, list())
  expect_length(zu_client(hooks = list())$hooks, 0L)
  plain <- zu_client(
    hooks = list(before_request = function(p) seen <<- c(seen, "plain")),
    transport = mock
  )
  expect_s3_class(plain$hooks, "zu_hooks")
  invisible(zu_get("https://x.test/a", client = plain))
  expect_identical(seen, "plain")
})

# --- #184: the noted items -----------------------------------------------------

test_that("a cassette name is a file name, not a path (#184)", {
  expect_error(zu_cassette_transport(name = "../x"), "not a path")
  expect_error(zu_cassette_transport(name = "a/b"), "not a path")
  expect_error(zu_cassette_transport(name = ".."), "not a path")
  expect_error(
    zu_cassette_transport(name = NA_character_),
    "single non-empty string"
  )
  expect_s3_class(
    zu_cassette_transport(name = "fine.name"),
    "zu_cassette_transport"
  )
})

test_that("a directory is not a PEM file, and says so (#184)", {
  d <- tempfile("zu-dir-")
  dir.create(d)
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  expect_error(zuhttp:::check_tls(zu_tls(ca_file = d)), "is a directory")
  expect_error(zuhttp:::check_tls(zu_tls(ca_extra = d)), "is a directory")
})

test_that("zu_body_file() refuses a directory and a missing file (#184, #195)", {
  d <- tempfile("zu-dir-")
  dir.create(d)
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  req <- zu_request("POST", "https://x.test/up")
  expect_error(zu_body_file(req, d), "is a directory")
  expect_error(zu_body_file(req, file.path(d, "nope.bin")), "no such file")
  f <- file.path(d, "yes.bin")
  writeBin(as.raw(1:5), f)
  expect_identical(zu_body_file(req, f)$body, as.raw(1:5))
})

test_that("argument validation says which argument, not 'is not TRUE' (#204)", {
  expect_error(
    zu_request(c("GET", "POST"), "https://x"),
    "`method` must be a single string"
  )
  expect_error(
    zu_request("GET", NA_character_),
    "`url` must be a single string"
  )
  expect_error(zu_set_json_backend(encode = 1), "`encode` must be a function")
  expect_error(zu_set_json_backend(decode = "x"), "`decode` must be a function")
})

# --- #195: request policy verbs -------------------------------------------------

test_that("zu_req_redirects() and zu_req_check() set the policy, and NULL resets it", {
  req <- zu_request("GET", "https://x.test/")
  expect_identical(zu_req_redirects(req, 3)$policy$redirects, 3)
  expect_s3_class(zu_req_redirects(req)$policy$redirects, "zu_reset")
  expect_s3_class(zu_req_redirects(req, NULL)$policy$redirects, "zu_reset")
  expect_false(zu_req_check(req, FALSE)$policy$check)
  expect_true(zu_req_check(req)$policy$check)
  expect_s3_class(zu_req_check(req, NULL)$policy$check, "zu_reset")
  # And they reach the resolved request through the §31.9 merge: a value
  # wins over the client's, NULL resets to the PACKAGE default, past the
  # client's own setting.
  cli <- zu_client(redirects = 7, check = FALSE)
  expect_identical(
    resolved(zu_req_redirects(req, 1), cli)$resolved$redirects,
    1
  )
  expect_identical(resolved(req, cli)$resolved$redirects, 7)
  expect_identical(
    resolved(zu_req_redirects(req, NULL), cli)$resolved$redirects,
    zu_defaults()$redirects
  )
  expect_true(resolved(zu_req_check(req, TRUE), cli)$resolved$check)
})

test_that("zu_req_retry(idempotency_key = FALSE) adds no header", {
  req <- zu_request("POST", "https://x.test/")
  expect_null(zu_req_retry(req, idempotency_key = FALSE)$headers[[
    "Idempotency-Key"
  ]])
  expect_match(
    zu_req_retry(req, idempotency_key = TRUE)$headers[["Idempotency-Key"]],
    "."
  )
  expect_identical(
    zu_req_retry(req, idempotency_key = "k1")$headers[["Idempotency-Key"]],
    "k1"
  )
})

# --- #195: response accessors ------------------------------------------------------

test_that("zu_resp_method() reports the method the final hop used", {
  cli <- zu_client(
    transport = zu_mock_transport(function(req) zu_response(200L))
  )
  expect_identical(
    zu_resp_method(zu_get("https://x.test/", client = cli)),
    "GET"
  )
  expect_identical(
    zu_resp_method(zu_delete("https://x.test/", client = cli)),
    "DELETE"
  )
})

test_that("zu_resp_trace() surfaces dropped events, and zu_verbose() says so", {
  r <- zu_response(200L)
  r$trace <- list(
    event = c("dns.start", "dns.done"),
    at_ms = c(0, 3),
    n = c(0, 0),
    detail = c("", ""),
    dropped = 4L
  )
  tr <- zu_resp_trace(r)
  expect_s3_class(tr, "data.frame")
  expect_identical(attr(tr, "dropped"), 4L)
  r$trace$dropped <- 0L
  expect_null(attr(zu_resp_trace(r), "dropped"))
  r$trace$dropped <- 4L
  out <- character()
  con <- textConnection("out", "w", local = TRUE)
  on.exit(close(con), add = TRUE)
  h <- zu_verbose(to = con)
  h$after_response(list(response = r))
  expect_true(any(grepl("4 further events not recorded", out, fixed = TRUE)))
})

test_that("zu_verbose(body = FALSE) leaves the body size out", {
  r <- zu_response(200L, body = charToRaw("hello"))
  say <- function(body) {
    out <- character()
    con <- textConnection("out", "w", local = TRUE)
    on.exit(close(con), add = TRUE)
    zu_verbose(to = con, body = body)$after_response(list(response = r))
    out
  }
  expect_true(any(grepl("5 bytes", say(TRUE), fixed = TRUE)))
  expect_false(any(grepl("bytes", say(FALSE), fixed = TRUE)))
})

test_that("a NUL byte makes the text undecodable (try_iconv), not a truncated string", {
  expect_identical(
    zuhttp:::try_iconv(as.raw(c(0x61, 0x00, 0x62)), "UTF-8"),
    NA_character_
  )
  expect_identical(zuhttp:::try_iconv(charToRaw("ab"), "UTF-8"), "ab")
})

test_that("print.zu_response() folds a long header list", {
  h <- setNames(as.character(1:9), paste0("X-H", 1:9))
  r <- zu_response(200L, headers = h, body = charToRaw("x"))
  out <- capture.output(print(r))
  expect_true(any(grepl("... and 1 more headers", out, fixed = TRUE)))
  expect_true(any(grepl("X-H8: 8", out, fixed = TRUE)))
  expect_false(any(grepl("X-H9", out, fixed = TRUE)))
})

# --- #195: the client ----------------------------------------------------------------

test_that("zu_set_default_client(NULL) clears the default and returns the old one", {
  old <- zu_default_client()
  on.exit(zu_set_default_client(old), add = TRUE)
  cli <- zu_client(base_url = "https://x.test")
  expect_identical(zu_set_default_client(cli), old)
  expect_identical(zu_default_client()$base_url, "https://x.test")
  prev <- zu_set_default_client(NULL)
  expect_identical(prev$base_url, "https://x.test")
  # NULL restores the package default, which is made afresh on demand.
  expect_null(zu_default_client()$base_url)
  expect_s3_class(zu_default_client(), "zu_client")
})

test_that("zu_client_update() refuses unnamed arguments and unknown settings", {
  cli <- zu_client()
  expect_error(zu_client_update(cli, 5), "must be named")
  expect_error(zu_client_update(cli, timeout = 5, "x"), "must be named")
  expect_error(zu_client_update(cli, nope = 1), "not a client setting")
  expect_identical(zu_client_update(cli, timeout = 5)$timeout, 5)
})

test_that("headers and query parameters must be named", {
  expect_error(zu_client(headers = c("a", "b")), "named vector")
  expect_error(zu_client(headers = list("a")), "named vector")
  expect_error(zu_client(query = list(1)), "must be named")
  expect_error(zu_client(query = list(a = 1, 2)), "must be named")
})

test_that("zu_body_raw() refuses a vector of strings and a list", {
  req <- zu_request("POST", "https://x.test/")
  expect_error(zu_body_raw(req, c("a", "b")), "single non-NA string")
  expect_error(zu_body_raw(req, NA_character_), "single non-NA string")
  expect_error(zu_body_raw(req, list(1)), "raw vector|character")
})

# --- #195: print methods ---------------------------------------------------------------

test_that("print.zu_stub() names its criteria", {
  s <- zu_stub(
    zu_response(201L),
    method = "post",
    url = "https://x.test/u",
    times = 2
  )
  out <- capture.output(print(s))
  expect_true(any(grepl("method POST", out, fixed = TRUE)))
  expect_true(any(grepl("times 2", out, fixed = TRUE)))
  out <- capture.output(print(zu_stub(zu_response(200L), regex = "/users$")))
  expect_true(any(grepl("regex /users$", out, fixed = TRUE)))
})

test_that("print.zu_retry_policy() distinguishes disabled from enabled", {
  out <- capture.output(print(zu_retry(attempts = 1)))
  expect_true(any(grepl("retrying disabled", out, fixed = TRUE)))
  out <- capture.output(print(zu_retry(attempts = 4)))
  expect_true(any(grepl("attempts: 4 (up to 3 retries)", out, fixed = TRUE)))
})

test_that("print.zu_hooks() lists the events, or none", {
  expect_output(print(zu_hooks()), "<zu_hooks: none>", fixed = TRUE)
  h <- zu_hooks(before_request = function(p) NULL, after_retry = function(p) {
    NULL
  })
  expect_output(
    print(h),
    "<zu_hooks: before_request, after_retry>",
    fixed = TRUE
  )
})

test_that("print.zu_pool_config() shows keepalive off, on, and the default answer window", {
  out <- capture.output(print(zu_pool()))
  expect_true(any(grepl("keepalive:    off", out, fixed = TRUE)))
  out <- capture.output(print(zu_pool(keepalive_time = 30)))
  expect_true(any(grepl(
    "PING after 30s idle, answer within 20s",
    out,
    fixed = TRUE
  )))
  out <- capture.output(print(zu_pool(
    keepalive_time = 30,
    keepalive_timeout = 5
  )))
  expect_true(any(grepl("answer within 5s", out, fixed = TRUE)))
})

test_that("a zu_pool_config saved before W21 still prints and still makes a pool (§26.5)", {
  # fixtures/pool-config-pre-w21.rds: see fixtures/README.md for provenance.
  cfg <- readRDS(test_path("fixtures", "pool-config-pre-w21.rds"))
  expect_null(cfg$keepalive_time_ms)
  out <- capture.output(print(cfg))
  expect_true(any(grepl("keepalive:    off", out, fixed = TRUE)))
  cli <- zu_client(pool = cfg)
  ptr <- client_pool(cli)
  expect_true(pool_valid(ptr))
  got <- pool_config(ptr)
  expect_identical(got[["keepalive_time_ms"]], 0)
  expect_identical(got[["keepalive_timeout_ms"]], 0)
  expect_identical(got[["idle_timeout_ms"]], 60000)
})

test_that("print.zu_cassette_transport() names the file and counts interactions", {
  d <- tempfile("zu-cas-")
  dir.create(d)
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  tp <- zu_cassette_transport(
    dir = d,
    name = "t",
    mode = "record",
    transport = zu_mock_transport(function(req) zu_response(200L))
  )
  out <- capture.output(print(tp))
  expect_true(any(grepl("<zu_cassette_transport [record]>", out, fixed = TRUE)))
  expect_true(any(grepl("0 interaction(s)", out, fixed = TRUE)))
  invisible(zu_get("https://x.test/a", client = zu_client(transport = tp)))
  out <- capture.output(print(tp))
  expect_true(any(grepl("1 interaction(s)", out, fixed = TRUE)))
  expect_true(any(grepl(file.path(d, "t.rds"), out, fixed = TRUE)))
})

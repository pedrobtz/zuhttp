# §42 secret redaction, including the §42.4 canary regression test.

test_that("userinfo is removed from a URL entirely", {
  expect_identical(
    zu_redact_url("https://user:pw@api.example.com/v1/x"),
    "https://api.example.com/v1/x"
  )
  # Even a bare username: it identifies an account on its own (§42.1).
  expect_identical(
    zu_redact_url("https://someone@api.example.com/x"),
    "https://api.example.com/x"
  )
})

test_that("secret query parameters are replaced, others preserved", {
  expect_identical(
    zu_redact_url("https://h/v1?page=2&api_key=SECRET&sort=asc"),
    "https://h/v1?page=2&api_key=<redacted>&sort=asc"
  )
})

test_that("a redacted value is never a truncated prefix (§42.1)", {
  # A prefix is enough to confirm a guess.
  out <- zu_redact_url("https://h/?access_token=abcdefghijklmnopqrstuvwxyz")
  expect_false(grepl("abc", out, fixed = TRUE))
  expect_match(out, "<redacted>", fixed = TRUE)
})

test_that("redaction is vectorised and preserves NA", {
  out <- zu_redact_url(c("https://u:p@a/", NA, "https://b/?sig=X"))
  expect_length(out, 3L)
  expect_identical(out[[1]], "https://a/")
  expect_true(is.na(out[[2]]))
  expect_identical(out[[3]], "https://b/?sig=<redacted>")
})

test_that("arbitrary text is never mangled by redaction", {
  # The scheme is anchored. Scanning for "://" anywhere treated this as
  # scheme + authority and deleted " with u:p@" from the middle; silently
  # removing text from a diagnostic is worse than not redacting it.
  txt <- "not a url at all :// with u:p@h"
  expect_identical(zu_redact_url(txt), txt)
  expect_identical(zu_redact_url("1http://u:p@h/"), "1http://u:p@h/")
})

test_that("a credential nested in a query value is a documented gap", {
  old <- getOption("zuhttp.redact_params")
  on.exit(options(zuhttp.redact_params = old), add = TRUE)

  u <- "https://h/cb?next=http://u:pw@evil.example/"
  # Not descended into, by design -- see §42.1.
  expect_match(zu_redact_url(u), "u:pw", fixed = TRUE)
  # The mitigation is naming the parameter.
  zu_redact_params("next")
  expect_false(grepl("u:pw", zu_redact_url(u), fixed = TRUE))
})

test_that("a URL that does not parse is still redacted", {
  # The malformed URL is exactly the one an error message is about.
  out <- zu_redact_url("https://user:pw@h:99999999/][?api_key=S")
  expect_false(grepl("pw", out, fixed = TRUE))
  expect_false(grepl("user", out, fixed = TRUE))
})

test_that("the default header list matches §42.1", {
  expect_true(all(zu_is_secret_header(c(
    "Authorization", "proxy-authorization", "Cookie", "Set-Cookie",
    "X-Api-Key", "X-Auth-Token"
  ))))
  expect_false(any(zu_is_secret_header(c("Accept", "Content-Type", "X-Request-Id"))))
})

test_that("extra names add to the defaults and cannot remove them", {
  old <- getOption("zuhttp.redact_headers")
  on.exit(options(zuhttp.redact_headers = old), add = TRUE)

  zu_redact_headers("X-Corp-Secret")
  expect_true(zu_is_secret_header("X-Corp-Secret"))
  expect_true(zu_is_secret_header("Authorization"))
})

test_that("extra query parameters are honoured", {
  old <- getOption("zuhttp.redact_params")
  on.exit(options(zuhttp.redact_params = old), add = TRUE)

  zu_redact_params("session_id")
  expect_true(zu_is_secret_param("session_id"))
  expect_identical(
    zu_redact_url("https://h/?session_id=abc&x=1"),
    "https://h/?session_id=<redacted>&x=1"
  )
})

test_that("header display redaction does not mutate the original", {
  # §42.3: redaction is a property of the formatting layer. A redacted request
  # must still be executable.
  h <- c(Authorization = "Bearer TOPSECRET", Accept = "application/json")
  shown <- zu_redact_headers_for_display(h)

  expect_identical(unname(shown[["Authorization"]]), "<redacted>")
  expect_identical(unname(shown[["Accept"]]), "application/json")
  # The original is untouched and still usable.
  expect_identical(unname(h[["Authorization"]]), "Bearer TOPSECRET")
})

test_that("form bodies are redacted with the same policy", {
  expect_identical(
    zu_redact_form("user=alice&api_key=SECRET&scope=read"),
    "user=alice&api_key=<redacted>&scope=read"
  )
})

# ---------------------------------------------------------------------------
# §42.4 — the canary test.
#
# "a test that greps the full output of a verbose request, an error condition,
#  a printed request, and a recording for a canary credential string. This is
#  a regression class that reappears every time a new output path is added."
#
# The transport does not exist yet, so the request/recording egresses are
# marked with skip() rather than silently omitted — an incomplete canary that
# LOOKS complete is worse than one that says what it does not cover.
# ---------------------------------------------------------------------------

CANARY <- "hunter2-DO-NOT-LEAK"

# A byte-level search, so a scan of a file on disk cannot be defeated by an
# encoding or a locale: grepRaw() takes a raw pattern and never converts.
raw_contains <- function(haystack, needle) {
  n <- charToRaw(needle)
  length(haystack) >= length(n) &&
    length(grepRaw(n, haystack, fixed = TRUE, all = FALSE)) > 0
}

# Every string reachable from `x`, at any depth, plus the names along the way.
#
# The shallow version of this walked one level and leaned on print(), which is
# how the hook-payload arm below came to pass while redaction was disabled: a
# payload is list(request = <zu_request>, ...), the request is not atomic so
# the one-level unlist() skipped it, and print() of a zu_request redacts on
# the way out. The canary was inspecting the redacted rendering of the thing
# it was supposed to be checking. Depth is not a refinement here — without it
# the assertion does not touch the value at all.
deep_strings <- function(x) {
  if (is.function(x) || is.environment(x) || is.null(x)) return(character())
  if (is.raw(x)) {
    # Raw bodies may hold NULs, which rawToChar() refuses; drop them rather
    # than lose the whole vector, since a credential is never a NUL.
    return(rawToChar(x[x != as.raw(0)]))
  }
  if (is.atomic(x)) return(c(names(x), as.character(x)))
  if (is.list(x))
    return(c(names(x), unlist(lapply(x, deep_strings), use.names = FALSE)))
  character()
}

expect_no_canary <- function(x, label) {
  txt <- c(utils::capture.output(print(x)), deep_strings(x))
  expect_false(any(grepl(CANARY, txt, fixed = TRUE)),
               info = paste("canary leaked via", label))
}

test_that("the canary does not leak through a condition object (§42.4)", {
  e <- tryCatch(
    stop(zu_condition(
      "zu_connect_error",
      "could not connect",
      url = paste0("https://user:", CANARY, "@h/x?api_key=", CANARY)
    )),
    condition = function(e) e
  )
  expect_no_canary(e, "condition payload")
  expect_false(grepl(CANARY, conditionMessage(e), fixed = TRUE))
  expect_false(grepl(CANARY, e$url, fixed = TRUE))
})

test_that("the canary does not leak through displayed headers (§42.4)", {
  h <- c(Authorization = paste("Bearer", CANARY), Accept = "*/*")
  shown <- zu_redact_headers_for_display(h)
  expect_false(any(grepl(CANARY, shown, fixed = TRUE)))
})

test_that("the canary does not leak through a redacted URL or form (§42.4)", {
  expect_false(grepl(CANARY, zu_redact_url(
    paste0("https://u:", CANARY, "@h/x?access_token=", CANARY)), fixed = TRUE))
  expect_false(grepl(CANARY, zu_redact_form(
    paste0("api_key=", CANARY, "&x=1")), fixed = TRUE))
})

test_that("the canary does not leak through a printed request (§42.4)", {
  req <- zu_request("POST", paste0("https://api.example.com/x?api_key=", CANARY))
  req <- zu_headers(req, Authorization = paste("Bearer", CANARY))
  req <- zu_body_form(req, list(client_secret = CANARY, grant_type = "client_credentials"))

  # PRINTED, not stored: §42.3 requires the live request to keep the real
  # credential, or a redacted request would no longer be executable. What must
  # never carry it is the display.
  printed <- paste(utils::capture.output(print(req)), collapse = "\n")
  expect_false(grepl(CANARY, printed, fixed = TRUE))
  expect_true(grepl(CANARY, req$headers[["Authorization"]], fixed = TRUE))

  # The body arm above is VACUOUS on its own and was so until S14: print()
  # renders "Body: form, 63 bytes" and never the bytes, so the canary could
  # not have appeared whether or not zu_redact_form() worked. Assert against
  # something that really renders the body — otherwise this test claims
  # coverage of an egress it does not touch (§50, "verify non-vacuously").
  expect_false(grepl(CANARY, zu_redact_form(rawToChar(req$body)), fixed = TRUE))
  expect_true(grepl(CANARY, rawToChar(req$body), fixed = TRUE))

  # And through a printed response, and the request a condition carries.
  api <- zu_client(headers = c(Authorization = paste("Bearer", CANARY)),
                   transport = zu_mock_transport(function(r) zu_response(500L)))
  e <- tryCatch(zu_get(paste0("https://h/x?api_key=", CANARY), client = api),
                zu_error = function(e) e)
  expect_no_canary(e, "condition payload from a failed request")
  expect_no_canary(e$request, "the request stored on a condition")
  expect_no_canary(e$response, "the response stored on a condition")
})

test_that("the canary does not reach a cassette on disk (§37, §42.4)", {
  # The egress that matters most, because it is the only one that outlives the
  # session: a cassette gets committed. The byte-level scan is the assertion —
  # inspecting the parsed interaction would only prove the accessors redact,
  # not that the FILE is clean.
  dir <- file.path(tempdir(), "zu-canary-cassette")
  on.exit(unlink(dir, recursive = TRUE), add = TRUE)
  unlink(dir, recursive = TRUE)

  live <- zu_mock_transport(function(req)
    zu_response(200L, headers = c("Set-Cookie" = paste0("s=", CANARY)), body = "ok"))
  api <- zu_client(headers = c(Authorization = paste("Bearer", CANARY)),
                   transport = zu_cassette_transport(dir, "canary", transport = live))
  req <- zu_body_form(
    zu_request("POST", paste0("https://h/x?api_key=", CANARY)),
    list(password = CANARY, client_secret = CANARY, page = "2"))
  expect_identical(zu_resp_status(zu_perform(req, client = api)), 200L)

  f <- file.path(dir, "canary.rds")
  expect_true(file.exists(f))
  # Searched as BYTES. The cassette is written uncompressed precisely so that
  # this scan means something; a compressed file would hide a plaintext
  # credential from it and the test would pass while the leak stood.
  expect_false(raw_contains(readBin(f, "raw", file.size(f)), CANARY))

  # ...and the interaction is still usable, i.e. redaction did not simply
  # destroy the cassette.
  rec <- zu_cassette_interactions(dir, "canary")
  expect_length(rec, 1L)
  expect_match(rec[[1]]$request$url, "api_key=<redacted>", fixed = TRUE)
  expect_identical(unname(rec[[1]]$request$headers[["Authorization"]]), "<redacted>")
  expect_match(rawToChar(rec[[1]]$request$body), "page=2", fixed = TRUE)
})

test_that("the canary does not reach a hook payload (§35.3, §42.4)", {
  # §35.3: "All hook payloads pass through the redaction filter in §42 before
  # the handler sees them." A trace handler that logs request headers must not
  # be the mechanism by which a bearer token reaches a log file — which is the
  # whole point, since logging is exactly what hooks are for.
  seen <- list()
  cli <- zu_client(
    headers   = c(Authorization = paste("Bearer", CANARY)),
    transport = zu_mock_transport(function(r) zu_response(200L)),
    hooks     = zu_hooks(before_request = function(p) seen$before <<- p,
                         after_response = function(p) seen$after  <<- p))
  invisible(zu_get(paste0("https://h/x?api_key=", CANARY), client = cli))

  expect_length(seen, 2L)
  expect_no_canary(seen$before, "the before_request hook payload")
  expect_no_canary(seen$after, "the after_response hook payload")
})

test_that("canary coverage of the remaining egresses is tracked, not assumed", {
  # Recordings joined the canary in S14, hook payloads in S13. Verbose
  # transport logging is a real §42.2 egress that still does not exist at all
  # — there is no verbose mode to trace — so it must fail loudly as "not
  # covered" rather than quietly pass.
  skip("verbose transport logging is not implemented; no egress to test yet")
})

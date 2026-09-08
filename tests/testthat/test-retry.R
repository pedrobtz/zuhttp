# S13 — §33 retry, §31.13 middleware and policy, §35.3 hooks.
#
# All offline: a retry loop is exactly the thing you cannot test against a
# real server, because the interesting cases are "the third attempt succeeds"
# and "the budget ran out mid-backoff". A counting mock is the only way to
# assert those, and §36.1 makes it faithful.

# Internals, reached the way the rest of this suite reaches them.
parse_retry_after <- function(...) zuhttp:::parse_retry_after(...)
backoff_delay     <- function(...) zuhttp:::backoff_delay(...)
retry_sleep       <- function(...) zuhttp:::retry_sleep(...)
zu_defaults       <- function(...) zuhttp:::zu_defaults(...)
zu_stop           <- function(...) zuhttp:::zu_stop(...)

counting <- function(f) {
  n <- 0L
  list(
    transport = zu_mock_transport(function(req) { n <<- n + 1L; f(n, req) }),
    n = function() n
  )
}

# --- §33 the policy object ------------------------------------------------

test_that("zu_retry() counts the FIRST attempt, and validates", {
  # The design calls this out: an earlier draft had `attempts` and
  # `max_attempts` meaning things that differed by one.
  expect_identical(zu_retry()$attempts, 3L)
  expect_identical(zu_retry(attempts = 1)$attempts, 1L)

  expect_error(zu_retry(attempts = 0), "at least 1")
  expect_error(zu_retry(attempts = NA), "at least 1")
  expect_error(zu_retry(base = -1), "non-negative")
  expect_error(zu_retry(backoff = "linear"), "should be one of")
})

test_that("retrying is off by default", {
  # §33 opens by warning that a client which silently replays requests is a
  # data-integrity bug. The default has to be the safe one.
  expect_identical(zu_client()$retry, NULL)
  expect_identical(zu_defaults()$retry$attempts, 1L)

  c1 <- counting(function(n, req) zu_response(503L))
  expect_identical(
    zu_resp_status(zu_get("https://h/x", check = FALSE,
                          client = zu_client(transport = c1$transport))), 503L)
  expect_identical(c1$n(), 1L)
})

# --- §33.1 admissibility --------------------------------------------------

test_that("an idempotent method retries and a POST does not", {
  make <- function() counting(function(n, req)
    if (n < 3L) zu_response(503L) else zu_response(200L))

  for (m in c("GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE")) {
    c1 <- make()
    cli <- zu_client(transport = c1$transport, retry = zu_retry(3, base = 0.001))
    expect_identical(zu_resp_status(zu_perform(zu_request(m, "https://h/x"), client = cli)),
                     200L, info = m)
    expect_identical(c1$n(), 3L, info = m)
  }

  # POST is not idempotent and is never retried automatically (§33.1).
  c1 <- make()
  cli <- zu_client(transport = c1$transport, retry = zu_retry(3, base = 0.001))
  expect_error(zu_perform(zu_request("POST", "https://h/x"), client = cli),
               class = "zu_http_server_error")
  expect_identical(c1$n(), 1L)
})

test_that("a POST opts in with replay_safe or an Idempotency-Key", {
  make <- function() counting(function(n, req)
    if (n < 2L) zu_response(503L) else zu_response(200L))

  c1 <- make(); cli <- zu_client(transport = c1$transport)
  req <- zu_req_retry(zu_request("POST", "https://h/x"), attempts = 3,
                      base = 0.001, replay_safe = TRUE)
  expect_identical(zu_resp_status(zu_perform(req, client = cli)), 200L)
  expect_identical(c1$n(), 2L)

  c2 <- make(); cli2 <- zu_client(transport = c2$transport)
  req2 <- zu_req_retry(zu_request("POST", "https://h/x"), attempts = 3,
                       base = 0.001, idempotency_key = TRUE)
  expect_match(req2$headers[["Idempotency-Key"]], "^[0-9a-f]{32}$")
  expect_identical(zu_resp_status(zu_perform(req2, client = cli2)), 200L)
  expect_identical(c2$n(), 2L)

  # A caller-supplied key is honoured as given.
  req3 <- zu_req_retry(zu_request("POST", "https://h/x"), idempotency_key = "my-key")
  expect_identical(unname(req3$headers[["Idempotency-Key"]]), "my-key")
})

test_that("zu_req_replay_safe() states §33.1's second condition", {
  expect_true(zu_req_replay_safe(zu_request("GET", "https://h/x")))
  expect_true(zu_req_replay_safe(zu_request("delete", "https://h/x")))
  expect_false(zu_req_replay_safe(zu_request("POST", "https://h/x")))
  expect_true(zu_req_replay_safe(
    zu_headers(zu_request("POST", "https://h/x"), "idempotency-key" = "k")))
  expect_true(zu_req_replay_safe(
    zu_req_retry(zu_request("POST", "https://h/x"), replay_safe = TRUE)))
})

test_that("a non-rewindable body refuses rather than truncating (§28.2)", {
  expect_true(zu_body_rewindable(zu_request("GET", "https://h/x")))
  expect_true(zu_body_rewindable(
    zu_body_raw(zu_request("POST", "https://h/x"), "bytes")))

  # No public API produces a non-rewindable body yet — §28.2's connection and
  # callback rows arrive with S17 — so the marker is set directly. The
  # MECHANISM is what this asserts, and it is the mechanism S17 will hand a
  # real body to.
  req <- zu_req_retry(zu_request("POST", "https://h/x"), attempts = 3,
                      replay_safe = TRUE)
  req$body_rewindable <- FALSE
  expect_false(zu_body_rewindable(req))

  c1 <- counting(function(n, req) zu_response(200L))
  expect_error(zu_perform(req, client = zu_client(transport = c1$transport)),
               class = "zu_body_not_replayable")
  # Refused BEFORE any attempt: discovering this only on the first failure
  # would make it intermittent.
  expect_identical(c1$n(), 0L)
})

# --- §33.2 the condition table --------------------------------------------

test_that("only the §33.2 statuses are retried", {
  check_status <- function(st, expect_retry) {
    c1 <- counting(function(n, req) if (n < 2L) zu_response(st) else zu_response(200L))
    cli <- zu_client(transport = c1$transport,
                     retry = zu_retry(3, base = 0.001), check = FALSE)
    invisible(zu_get("https://h/x", client = cli))
    expect_identical(c1$n(), if (expect_retry) 2L else 1L,
                     info = paste("status", st))
  }
  for (st in c(408L, 429L, 500L, 502L, 503L, 504L)) check_status(st, TRUE)
  # "Other 5xx: no by default" — 501 and 505 are not in the table.
  for (st in c(400L, 401L, 403L, 404L, 409L, 418L, 501L, 505L)) check_status(st, FALSE)
  # A success is obviously not retried.
  check_status(200L, FALSE)
})

test_that("`on` extends the retryable status set without replacing it", {
  c1 <- counting(function(n, req) if (n < 2L) zu_response(418L) else zu_response(200L))
  cli <- zu_client(transport = c1$transport,
                   retry = zu_retry(3, base = 0.001, on = 418L))
  expect_identical(zu_resp_status(zu_get("https://h/x", client = cli)), 200L)
  expect_identical(c1$n(), 2L)
})

test_that("a raised condition is retried only when its code says so", {
  # A TLS trust failure will not fix itself (§33.2); an I/O failure might.
  retried_for <- function(cls) {
    c1 <- counting(function(n, req)
      if (n < 2L) zu_stop(cls, "boom", url = "https://h/x") else zu_response(200L))
    cli <- zu_client(transport = c1$transport, retry = zu_retry(3, base = 0.001))
    tryCatch(zu_get("https://h/x", client = cli), zu_error = function(e) NULL)
    c1$n()
  }
  expect_identical(retried_for("zu_io_error"), 2L)
  expect_identical(retried_for("zu_connect_error"), 2L)
  expect_identical(retried_for("zu_dns_error"), 2L)
  expect_identical(retried_for("zu_tls_certificate_error"), 1L)
  expect_identical(retried_for("zu_url_error"), 1L)
})

test_that("a condition that outlives the retries reaches the caller unchanged", {
  c1 <- counting(function(n, req) zu_stop("zu_io_error", "still broken",
                                          url = "https://h/x"))
  cli <- zu_client(transport = c1$transport, retry = zu_retry(3, base = 0.001))
  e <- tryCatch(zu_get("https://h/x", client = cli), zu_error = function(e) e)
  expect_s3_class(e, "zu_io_error")
  expect_match(conditionMessage(e), "still broken")
  expect_identical(c1$n(), 3L)
})

# --- §33.3 backoff and Retry-After ----------------------------------------

test_that("Retry-After is parsed in both RFC 7231 forms and clamped", {
  expect_identical(parse_retry_after("7"), 7)
  expect_identical(parse_retry_after(" 12 "), 12)
  expect_null(parse_retry_after(character()))
  expect_null(parse_retry_after(NA_character_))
  expect_null(parse_retry_after("soon please"))

  # HTTP-date, in the future and in the past. Month names are English
  # regardless of the session's locale, which is why the parser fixes LC_TIME.
  future <- format(Sys.time() + 30, "%a, %d %b %Y %H:%M:%S GMT", tz = "GMT")
  expect_true(abs(parse_retry_after(future) - 30) < 5)
  past <- format(Sys.time() - 3600, "%a, %d %b %Y %H:%M:%S GMT", tz = "GMT")
  expect_identical(parse_retry_after(past), 0)   # never negative

  # Clamped, not trusted: a hostile server must not pin the session.
  p <- zu_retry(max_retry_after = 60)
  expect_identical(backoff_delay(p, 1L, 86400), 60)
  expect_identical(backoff_delay(p, 1L, 5), 5)
})

test_that("exponential backoff grows, is capped, and full jitter stays in range", {
  p <- zu_retry(base = 1, max_delay = 8, jitter = FALSE)
  expect_identical(backoff_delay(p, 1L, NULL), 1)
  expect_identical(backoff_delay(p, 2L, NULL), 2)
  expect_identical(backoff_delay(p, 3L, NULL), 4)
  expect_identical(backoff_delay(p, 4L, NULL), 8)
  expect_identical(backoff_delay(p, 9L, NULL), 8)   # capped

  expect_identical(backoff_delay(zu_retry(base = 2, backoff = "constant",
                                          jitter = FALSE), 5L, NULL), 2)

  # Full jitter is uniform over [0, d] — not d plus a wiggle. Asserting the
  # range AND that it actually varies; a constant would satisfy the range.
  pj <- zu_retry(base = 4, max_delay = 4)
  d <- vapply(1:200, function(i) backoff_delay(pj, 1L, NULL), numeric(1))
  expect_true(all(d >= 0 & d <= 4))
  expect_gt(length(unique(d)), 100)
  expect_lt(min(d), 1)      # values near zero are the point of full jitter
})

test_that("a Retry-After header drives the delay when honoured", {
  c1 <- counting(function(n, req)
    if (n < 2L) zu_response(429L, headers = c("Retry-After" = "0")) else zu_response(200L))
  cli <- zu_client(transport = c1$transport, retry = zu_retry(3))
  expect_identical(zu_resp_status(zu_get("https://h/x", client = cli)), 200L)
  expect_identical(c1$n(), 2L)

  # retry_after = FALSE ignores it and uses backoff instead.
  c2 <- counting(function(n, req)
    if (n < 2L) zu_response(429L, headers = c("Retry-After" = "3600")) else zu_response(200L))
  cli2 <- zu_client(transport = c2$transport,
                    retry = zu_retry(3, base = 0.001, retry_after = FALSE))
  expect_identical(zu_resp_status(zu_get("https://h/x", client = cli2)), 200L)
})

# --- §24.3 the budget -----------------------------------------------------

test_that("the total timeout bounds the whole call, retries included", {
  # The exit criterion, and the reason §24.3 chose this reading: under the
  # per-attempt reading, three retries with exponential backoff run for
  # minutes while the caller was promised 30 seconds.
  c1 <- counting(function(n, req) zu_response(503L))
  cli <- zu_client(transport = c1$transport,
                   retry = zu_retry(attempts = 20, base = 5, jitter = FALSE),
                   check = FALSE)
  t0 <- proc.time()[["elapsed"]]
  invisible(zu_get("https://h/x", timeout = 1, client = cli))
  elapsed <- proc.time()[["elapsed"]] - t0

  # 19 retries at >= 5s each would be over a minute. The budget check happens
  # BEFORE the sleep, so this returns essentially immediately.
  expect_lt(elapsed, 1.5)
  expect_lt(c1$n(), 20L)
})

test_that("a backoff that fits the budget is actually slept", {
  # The mirror of the test above: proving the budget is respected is only
  # half of it, since "never sleeps at all" would also pass that one.
  c1 <- counting(function(n, req) if (n < 2L) zu_response(503L) else zu_response(200L))
  cli <- zu_client(transport = c1$transport,
                   retry = zu_retry(attempts = 2, base = 0.3, jitter = FALSE))
  t0 <- proc.time()[["elapsed"]]
  expect_identical(zu_resp_status(zu_get("https://h/x", timeout = 30, client = cli)), 200L)
  expect_gt(proc.time()[["elapsed"]] - t0, 0.2)
})

test_that("retry_sleep() wakes early when the deadline is closer than the delay", {
  t0 <- proc.time()[["elapsed"]]
  retry_sleep(10, deadline_at = t0 + 0.2)
  expect_lt(proc.time()[["elapsed"]] - t0, 1)
})

# --- §31.13 middleware ----------------------------------------------------

test_that("middleware composes outside-in and can see both directions", {
  order <- character()
  mw <- function(tag) function(req, next_fn) {
    order <<- c(order, paste0("enter:", tag))
    resp <- next_fn(req)
    order <<- c(order, paste0("exit:", tag))
    resp
  }
  cli <- zu_client(transport = zu_mock_transport(function(r) zu_response(200L)),
                   middleware = list(mw("a"), mw("b")))
  expect_identical(zu_resp_status(zu_get("https://h/x", client = cli)), 200L)
  # First in the list is outermost, which is what the §31.13 diagram draws.
  expect_identical(order, c("enter:a", "enter:b", "exit:b", "exit:a"))
})

test_that("middleware can modify the request and short-circuit the transport", {
  called <- FALSE
  cli <- zu_client(
    transport = zu_mock_transport(function(r) { called <<- TRUE; zu_response(200L) }),
    middleware = function(req, next_fn) zu_response(418L))
  expect_identical(zu_resp_status(zu_get("https://h/x", check = FALSE, client = cli)), 418L)
  expect_false(called)

  seen <- NULL
  cli2 <- zu_client(
    transport = zu_mock_transport(function(r) { seen <<- r$headers; zu_response(200L) }),
    middleware = function(req, next_fn) {
      req$headers <- c(req$headers, c("X-Signed" = "yes")); next_fn(req)
    })
  invisible(zu_get("https://h/x", client = cli2))
  expect_identical(unname(seen[["X-Signed"]]), "yes")
})

test_that("middleware is validated and must return a response", {
  expect_error(zu_client(middleware = "nope"), "must be a function")
  expect_error(zu_client(middleware = list(function(a, b) NULL, 42)),
               "must be a function")
  cli <- zu_client(transport = zu_mock_transport(function(r) zu_response(200L)),
                   middleware = function(req, next_fn) "not a response")
  expect_error(zu_get("https://h/x", client = cli), "must return a zu_response")
})

test_that("the retry loop sits inside middleware, so middleware sees one request", {
  entries <- 0L
  c1 <- counting(function(n, req) if (n < 3L) zu_response(503L) else zu_response(200L))
  cli <- zu_client(transport = c1$transport, retry = zu_retry(3, base = 0.001),
                   middleware = function(req, next_fn) {
                     entries <<- entries + 1L; next_fn(req)
                   })
  expect_identical(zu_resp_status(zu_get("https://h/x", client = cli)), 200L)
  expect_identical(c1$n(), 3L)      # three attempts...
  expect_identical(entries, 1L)     # ...one logical request
})

# --- §35.3 hooks ----------------------------------------------------------

test_that("hooks observe the lifecycle, including every retry (§33.4)", {
  events <- list()
  note <- function(tag) function(p) events[[length(events) + 1L]] <<- c(list(tag = tag), p)

  c1 <- counting(function(n, req) if (n < 3L) zu_response(503L) else zu_response(200L))
  cli <- zu_client(transport = c1$transport, retry = zu_retry(3, base = 0.001),
                   hooks = zu_hooks(before_request = note("before_request"),
                                    after_response = note("after_response"),
                                    before_retry   = note("before_retry"),
                                    after_retry    = note("after_retry")))
  expect_identical(zu_resp_status(zu_get("https://h/x", client = cli)), 200L)

  tags <- vapply(events, function(e) e$tag, character(1))
  expect_identical(sum(tags == "before_request"), 3L)
  expect_identical(sum(tags == "before_retry"), 2L)
  expect_identical(sum(tags == "after_retry"), 2L)
  expect_identical(sum(tags == "after_response"), 1L)

  # §33.4: the payload must say why and for how long, or the retry is a
  # latency mystery for whoever debugs it later.
  br <- events[tags == "before_retry"]
  expect_identical(br[[1]]$why, "HTTP 503")
  expect_true(is.numeric(br[[1]]$delay))
  expect_identical(br[[1]]$attempt, 1L)
  expect_identical(br[[2]]$attempt, 2L)
})

test_that("hook payloads are redacted before the handler sees them (§35.3)", {
  CANARY <- "hunter2-DO-NOT-LEAK"
  seen <- list()
  cli <- zu_client(
    headers = c(Authorization = paste("Bearer", CANARY)),
    transport = zu_mock_transport(function(r) zu_response(200L)),
    hooks = zu_hooks(
      before_request = function(p) seen$req <<- p$request,
      after_response = function(p) seen$resp <<- p$response))
  invisible(zu_get(paste0("https://h/x?api_key=", CANARY), client = cli))

  # A trace handler that logs request headers must not be how a bearer token
  # reaches a log file.
  expect_false(grepl(CANARY, seen$req$headers[["Authorization"]], fixed = TRUE))
  expect_false(grepl(CANARY, seen$req$url, fixed = TRUE))
  expect_false(any(grepl(CANARY, unlist(seen$resp$request), fixed = TRUE)))

  # ...and the real request still carries the real credential (§42.3).
  expect_true(grepl(CANARY, zu_client(headers = c(Authorization = paste("Bearer", CANARY)))$headers[[1]],
                    fixed = TRUE))
})

test_that("a hook cannot modify the request, and a failing hook cannot break it", {
  seen <- NULL
  cli <- zu_client(
    transport = zu_mock_transport(function(r) { seen <<- r$headers; zu_response(200L) }),
    hooks = zu_hooks(before_request = function(p) {
      p$request$headers <- c(p$request$headers, c("X-Injected" = "1"))
      p  # returning it must change nothing: a hook that mutates is middleware
    }))
  invisible(zu_get("https://h/x", client = cli))
  expect_false("X-Injected" %in% names(seen %||% character()))

  cli2 <- zu_client(transport = zu_mock_transport(function(r) zu_response(200L)),
                    hooks = zu_hooks(before_request = function(p) stop("hook blew up")))
  expect_warning(r <- zu_get("https://h/x", client = cli2), "hook `before_request` failed")
  expect_identical(zu_resp_status(r), 200L)
})

test_that("zu_hooks() validates its handlers", {
  expect_error(zu_hooks(before_request = "nope"), "must be a function")
  expect_s3_class(zu_hooks(), "zu_hooks")
})

# --- §33.3 / §25: the backoff sleep is interruptible ----------------------

test_that("a backoff sleep responds to Ctrl-C", {
  # S13's fourth exit criterion. S15 records that this harness cannot test
  # cancellation, and for a blocking network read in C that is true — but a
  # BACKOFF sleep is R-level and can be tested honestly: start a request that
  # parks in a 60-second backoff, deliver SIGINT (which is what Ctrl-C sends),
  # and require the process to react. If Sys.sleep() were not interruptible,
  # or the sleep were one long block outside R's control, this would time out.
  skip_on_cran()
  if (.Platform$OS.type != "unix") skip("SIGINT delivery here is POSIX-only")
  if (!nzchar(Sys.which("Rscript"))) skip("Rscript not on PATH")

  tmp    <- tempfile("zu-sigint-"); dir.create(tmp)
  on.exit(unlink(tmp, recursive = TRUE), add = TRUE)
  script <- file.path(tmp, "run.R")
  outf   <- file.path(tmp, "out.txt")
  pidf   <- file.path(tmp, "pid.txt")

  writeLines(c(
    # deparse() of a long vector comes back in SEVERAL elements; collapsing is
    # not cosmetic here, since sprintf() would otherwise silently use only the
    # first line and write a script with unbalanced parentheses.
    sprintf(".libPaths(%s)", paste(deparse(.libPaths()), collapse = "")),
    "library(zuhttp)",
    sprintf('con <- file(%s, "w")', deparse(outf)),
    'writeLines("START", con); flush(con)',
    "cli <- zu_client(transport = zu_mock_transport(function(r) zu_response(503L)),",
    "                 retry = zu_retry(attempts = 5, base = 60, jitter = FALSE),",
    "                 check = FALSE)",
    "tryCatch(zu_get('https://h/x', timeout = 600, client = cli),",
    "         interrupt = function(e) {",
    "           writeLines('INTERRUPTED', con); flush(con); quit(save = 'no') })",
    # Only reachable if the retries ran to completion, which needs 4 backoffs
    # of 60s. Its presence would mean the interrupt was swallowed.
    'writeLines("DONE", con); flush(con); close(con)'
  ), script)

  # `exec` so the recorded pid is R's own and not a shell that wraps it.
  system2("sh", c("-c", shQuote(sprintf("echo $$ > %s; exec Rscript %s", pidf, script))),
          wait = FALSE, stdout = NULL, stderr = NULL)

  wait_for <- function(f, what, limit = 30) {
    deadline <- Sys.time() + limit
    while (Sys.time() < deadline) {
      if (file.exists(f) && any(grepl(what, readLines(f, warn = FALSE)))) return(TRUE)
      Sys.sleep(0.05)
    }
    FALSE
  }

  if (!wait_for(outf, "START")) skip("the helper R process did not start")
  pid <- as.integer(readLines(pidf, warn = FALSE)[[1]])
  Sys.sleep(0.5)                      # let it reach the backoff sleep

  t0 <- Sys.time()
  tools::pskill(pid, tools::SIGINT)
  reacted <- wait_for(outf, "INTERRUPTED", limit = 10)
  elapsed <- as.numeric(difftime(Sys.time(), t0, units = "secs"))
  tools::pskill(pid, tools::SIGKILL)  # whatever happened, do not leave it running

  expect_true(reacted)
  # The sleep was 60s and the deadline 600s, so anything under a couple of
  # seconds can only be the interrupt — not the backoff finishing.
  expect_lt(elapsed, 5)
  expect_false(any(grepl("DONE", readLines(outf, warn = FALSE))))
})

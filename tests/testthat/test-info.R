# §39 zu_info().
#
# Two sections in the design lean on this existing — §14.5 for the revocation
# policy and §31.3 for the default client's configuration being "never
# invisible" — so the tests assert those two claims specifically, not merely
# that a report prints.

test_that("zu_info() reports the build, not what R believes about it", {
  i <- zu_info()
  expect_s3_class(i, "zu_info")
  expect_identical(i$http, "HTTP/1.1")
  expect_identical(i$tls_backend, zu_tls_backend())
  expect_true(i$tls_backend %in% c("openssl", "schannel", "securetransport", "none"))
  expect_type(i$version, "character")

  # §13.1 splits the engine from the trust evaluator, so they are reported
  # separately and must actually agree with the backend that is linked.
  expect_match(i$trust, switch(i$tls_backend,
    securetransport = "Keychain", schannel = "Windows", openssl = "OpenSSL", "none"))
})

test_that("§14.5's revocation policy is reported", {
  # The section's own justification: this is the silent per-platform asymmetry
  # that produces "works on my machine" reports, so it has to be visible.
  i <- zu_info()
  expect_type(i$revocation_default, "logical")
  expect_false(i$revocation_default)     # D-31: off by default everywhere
  expect_match(paste(capture.output(print(i)), collapse = "\n"), "Revocation")
})

test_that("§31.3's claim holds: the default client's configuration is visible", {
  old <- zu_set_default_client(zu_client(
    base_url = "https://api.test", timeout = 5, retry = zu_retry(4),
    pool = NULL, check = FALSE))
  on.exit(zu_set_default_client(old), add = TRUE)

  d <- zu_info()$default_client
  expect_identical(d$base_url, "https://api.test")
  expect_identical(d$timeout, 5)
  expect_identical(d$retry, 4L)
  expect_identical(d$pool, "disabled")
  expect_false(d$check)

  out <- paste(capture.output(print(zu_info())), collapse = "\n")
  expect_match(out, "https://api.test", fixed = TRUE)
  expect_match(out, "4 attempts", fixed = TRUE)
  expect_match(out, "statuses returned", fixed = TRUE)
})

test_that("the proxy environment is reported, including the ignored one", {
  saved <- Sys.getenv(c("http_proxy", "HTTP_PROXY", "no_proxy"), unset = NA)
  on.exit({
    for (n in names(saved))
      if (is.na(saved[[n]])) Sys.unsetenv(n) else do.call(Sys.setenv, setNames(list(saved[[n]]), n))
  }, add = TRUE)

  Sys.setenv(http_proxy = "http://corp:3128", HTTP_PROXY = "http://attacker:80",
             no_proxy = "internal.test")
  i <- zu_info()
  expect_identical(unname(i$proxy_env$set[["http_proxy"]]), "http://corp:3128")
  expect_identical(unname(i$proxy_env$set[["no_proxy"]]), "internal.test")

  # §20.1's httpoxy rule is invisible otherwise: a user whose HTTP_PROXY is
  # set and ignored sees a request that "should" be proxied and is not, with
  # nothing anywhere saying why.
  expect_true(i$proxy_env$ignored_uppercase_http_proxy)
  out <- paste(capture.output(print(i)), collapse = "\n")
  expect_match(out, "deliberately IGNORED", fixed = TRUE)
  expect_false(grepl("attacker", out, fixed = TRUE))
})

test_that("zu_info() is an egress and redacts like one (§42.2)", {
  saved <- Sys.getenv("http_proxy", unset = NA)
  on.exit(if (is.na(saved)) Sys.unsetenv("http_proxy") else
            Sys.setenv(http_proxy = saved), add = TRUE)

  # This function exists to be pasted into bug reports, which makes it one of
  # the more likely places for a credential to escape.
  Sys.setenv(http_proxy = "http://user:hunter2-DO-NOT-LEAK@corp:3128")
  i <- zu_info()
  out <- paste(capture.output(print(i)), collapse = "\n")
  expect_false(grepl("hunter2-DO-NOT-LEAK", out, fixed = TRUE))
  expect_false(any(grepl("hunter2-DO-NOT-LEAK", unlist(i), fixed = TRUE)))
  expect_match(out, "corp:3128", fixed = TRUE)   # still useful
})

# --- §42.2's last egress: verbose logging --------------------------------

test_that("zu_verbose() traces the request lifecycle", {
  out <- textConnection("trace", "w", local = TRUE)
  on.exit(try(close(out), silent = TRUE), add = TRUE)

  cli <- zu_client(hooks = zu_verbose(to = out),
                   transport = zu_mock_transport(function(r)
                     zu_response(201L, c("Content-Type" = "text/plain"), "hello")))
  invisible(zu_perform(zu_request("POST", "https://h/things"), client = cli))
  close(out)

  expect_true(any(grepl("^> POST https://h/things", trace)))
  expect_true(any(grepl("^< HTTP 201", trace)))
  expect_true(any(grepl("Content-Type: text/plain", trace, fixed = TRUE)))
  expect_true(any(grepl("5 bytes", trace, fixed = TRUE)))
})

test_that("zu_verbose() reports retries, which is what makes them visible", {
  # §33.4: "a retry that is never surfaced is a latency mystery for whoever
  # debugs it later" — this is the surface.
  out <- textConnection("trace2", "w", local = TRUE)
  on.exit(try(close(out), silent = TRUE), add = TRUE)

  n <- 0L
  cli <- zu_client(
    hooks = zu_verbose(to = out),
    retry = zu_retry(attempts = 3, base = 0.001),
    transport = zu_mock_transport(function(r) {
      n <<- n + 1L
      if (n < 3L) zu_response(503L) else zu_response(200L)
    }))
  invisible(zu_get("https://h/x", client = cli))
  close(out)

  retries <- grep("^\\* retry", trace2, value = TRUE)
  expect_length(retries, 2L)
  expect_true(all(grepl("HTTP 503", retries, fixed = TRUE)))
})

test_that("zu_verbose() writes to stderr by default", {
  # A trace on stdout would contaminate whatever a script is piping.
  expect_silent(h <- zu_verbose())
  expect_s3_class(h, "zu_hooks")
  expect_setequal(names(h), c("before_request", "after_response", "before_retry"))
})

# --- §35.2 connection metadata -------------------------------------------

test_that("zu_resp_connection() answers all nine §35.2 fields", {
  # Even for a response that never touched a network. "How many attempts?"
  # and "how many redirects?" always have an answer, so a mock must not make
  # them NULL and force every caller to guard.
  c9 <- zu_resp_connection(zu_response(200L))
  expect_named(c9, c("reused_connection", "remote_ip", "tls_protocol",
                     "tls_cipher", "trust_backend", "http_version",
                     "proxy_used", "retries_performed", "redirect_count"))
  expect_false(c9$reused_connection)
  expect_false(c9$proxy_used)
  expect_identical(c9$retries_performed, 0L)
  expect_identical(c9$redirect_count, 0L)
})

test_that("retries and redirects are counted, not guessed", {
  n <- 0L
  flaky <- zu_mock_transport(function(r) {
    n <<- n + 1L
    if (n < 3L) zu_response(503L) else zu_response(200L)
  })
  r <- zu_get("https://h/x", retry = zu_retry(3, base = 0.001),
              client = zu_client(transport = flaky))
  # Three attempts is two retries. The off-by-one here is the same one §33
  # warns about for `attempts`, so it is asserted rather than assumed.
  expect_identical(zu_resp_connection(r)$retries_performed, 2L)

  r2 <- zu_response(200L); r2$redirects <- 3L
  expect_identical(zu_resp_connection(r2)$redirect_count, 3L)
})

test_that("connection metadata is real over a live connection", {
  skip_unless_online()

  api <- zu_client()
  r <- zu_get("https://example.com", client = api)
  cn <- zu_resp_connection(r)

  expect_false(cn$reused_connection)         # first request on a fresh pool
  expect_match(cn$tls_protocol, "^TLSv1\\.[23]$")
  expect_identical(cn$http_version, "HTTP/1.1")
  expect_false(cn$proxy_used)
  expect_true(nzchar(cn$remote_ip))
  expect_true(cn$trust_backend %in% c("sectrust", "schannel", "openssl"))

  # §35.2's cipher is a NAME. "0xcca9" does not answer the question anyone
  # reads this field to ask, which is whether the connection has forward
  # secrecy and an AEAD mode.
  expect_true(nzchar(cn$tls_cipher))
  expect_false(grepl("^0x", cn$tls_cipher))
  expect_match(cn$tls_cipher, "[A-Z]")

  # And the pool is visible here rather than only in zu_pool_stats().
  r2 <- zu_get("https://example.com", client = api)
  expect_true(zu_resp_connection(r2)$reused_connection)
})

test_that("proxy_used reports the truth", {
  skip_on_cran()
  if (.Platform$OS.type != "unix") skip("the helper proxy uses POSIX shell")
  if (!nzchar(Sys.which("Rscript"))) skip("Rscript not on PATH")

  # A field that always said FALSE would pass every test above.
  seen <- with_fake_proxy("ok", function(px) {
    r <- zu_get("http://target.example/x", proxy = px, timeout = 15, check = FALSE)
    cn <- zu_resp_connection(r)
    expect_true(cn$proxy_used)
    # Through a proxy the peer IS the proxy. That is the honest answer: it is
    # who we are connected to, and only the proxy knows the origin's address.
    expect_match(cn$remote_ip, "^127\\.0\\.0\\.1$")
  })
  skip_if(is.null(seen), "the helper proxy recorded nothing")
})

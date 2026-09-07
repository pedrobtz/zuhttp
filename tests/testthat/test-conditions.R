# The §34.1 condition hierarchy, and §34.3's "base R only" rule.

test_that("every class is catchable by base tryCatch with no extra package", {
  # §34.1: "Every class inherits from `error` and `condition` so that base R
  # tryCatch() works without any additional package."
  codes <- zu_error_codes()
  codes <- codes[names(codes) != "zu_ok"]

  for (nm in names(codes)) {
    caught <- tryCatch(
      stop(zu_condition(nm, "boom")),
      condition = function(e) e
    )
    expect_s3_class(caught, nm)
    expect_s3_class(caught, "zu_error")
    expect_s3_class(caught, "error")
    expect_s3_class(caught, "condition")
  }
})

test_that("catching a parent class catches its children (§34.1)", {
  # The tree is the whole point: a caller who wants "any TLS problem" must not
  # have to enumerate the four leaves.
  leaves <- c("zu_tls_certificate_error", "zu_tls_hostname_error",
              "zu_tls_handshake_error", "zu_tls_pin_error")
  for (leaf in leaves) {
    caught <- tryCatch(stop(zu_condition(leaf, "boom")),
                       zu_tls_error = function(e) "parent")
    expect_identical(caught, "parent")
  }

  expect_identical(
    tryCatch(stop(zu_condition("zu_proxy_auth_error", "x")),
             zu_proxy_error = function(e) "parent"),
    "parent"
  )
  expect_identical(
    tryCatch(stop(zu_condition("zu_interrupted_error", "x")),
             zu_cancelled_error = function(e) "parent"),
    "parent"
  )
  expect_identical(
    tryCatch(stop(zu_condition("zu_too_many_redirects", "x")),
             zu_redirect_error = function(e) "parent"),
    "parent"
  )
})

test_that("a sibling class is NOT caught", {
  # A hierarchy that catches too much is as wrong as one that catches too little.
  expect_error(
    tryCatch(stop(zu_condition("zu_dns_error", "x")),
             zu_tls_error = function(e) "wrong"),
    class = "zu_dns_error"
  )
})

test_that("the condition carries the §34.2 payload", {
  e <- tryCatch(
    stop(zu_condition("zu_tls_certificate_error",
                      "TLS certificate verification failed for `api.example.com`.",
                      url = "https://user:pw@api.example.com/v1?api_key=SECRET",
                      phase = "tls", backend = "openssl", backend_code = 20L)),
    condition = function(e) e
  )
  expect_identical(e$phase, "tls")
  expect_identical(e$backend, "openssl")
  expect_identical(e$backend_code, 20L)
  expect_identical(e$code, unname(zu_error_codes()[["zu_tls_certificate_error"]]))
  expect_false(e$retryable)
  expect_true(is.character(conditionMessage(e)))
})

test_that("the URL in a condition is redacted (§42.2)", {
  e <- tryCatch(
    stop(zu_condition("zu_connect_error", "nope",
                      url = "https://user:hunter2@h/x?api_key=SEKRIT")),
    condition = function(e) e
  )
  expect_false(grepl("hunter2", e$url, fixed = TRUE))
  expect_false(grepl("SEKRIT", e$url, fixed = TRUE))
  expect_false(grepl("user", e$url, fixed = TRUE))
  expect_match(e$url, "<redacted>", fixed = TRUE)
})

test_that("retryability is reported and matches the C registry", {
  expect_true(zu_code_retryable("zu_connect_error"))
  expect_true(zu_code_retryable("zu_dns_error"))
  expect_false(zu_code_retryable("zu_tls_certificate_error"))
  expect_false(zu_code_retryable("zu_http_parse_error"))
  expect_false(zu_code_retryable("zu_url_error"))
  expect_true(is.na(zu_code_retryable("no_such_class")))
})

test_that("an unknown code is refused rather than silently accepted", {
  expect_error(zu_condition("not_a_real_class", "x"), "unknown zuhttp error code")
  expect_error(zu_condition(9999L, "x"), "unknown zuhttp error code")
})

test_that("codes are stable identifiers, names are the classes", {
  codes <- zu_error_codes()
  expect_true(is.integer(codes))
  expect_true(all(nzchar(names(codes))))
  expect_identical(anyDuplicated(names(codes)), 0L)
  expect_true("zu_url_error" %in% names(codes))
})

test_that("conditions are well-formed for rlang without depending on it", {
  # §34.3: no rlang dependency, but the standard layout means rlang users get
  # working conditions for free.
  e <- tryCatch(stop(zu_condition("zu_timeout_error", "took too long")),
                condition = function(e) e)
  expect_true(is.list(e))
  expect_true(all(c("message", "call") %in% names(e)))
  expect_identical(conditionMessage(e), "took too long")
})

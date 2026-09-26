# §14 TLS and trust configuration, from R.
#
# The §50.5 certificate matrix — trusted/untrusted/expired/wrong-host against
# locally generated certs — is a separate piece of work needing a local TLS
# server. What is here is the configuration SURFACE: that each knob reaches
# the backend, that ca_file and ca_extra genuinely differ, and that the §26.1
# pool key keeps connections with different TLS settings apart.

# A CA that is real, correctly formed, and trusts nothing on the internet.
# That is what distinguishes "adds to" from "replaces": with it added, a
# public host still validates; with it substituted, the same host must not.
# Shared with the §50.5 matrix in test-certs.R via helper-tlsfixture.R rather
# than generated twice — two fixtures for one concept drift.
local_ca <- function() {
  fx <- tls_fixture()
  list(dir = fx$dir, pem = fx$ca)
}

# --- the object (offline) ------------------------------------------------

test_that("zu_tls() validates and keeps ca_file and ca_extra apart", {
  t <- zu_tls(ca_file = "/etc/hosts", ca_extra = "/etc/hosts",
              pins = "sha256//YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=",
              revocation = TRUE, min_version = 12)
  expect_s3_class(t, "zu_tls_config")
  expect_true(t$revocation)
  expect_identical(t$min_version, 12L)
  # Two fields, never one overloaded `ca =`: §14.2 calls the distinction
  # security-relevant, and an overloaded argument is how someone ends up
  # trusting only their corporate root without noticing.
  expect_named(t, c("ca_file", "ca_extra", "pins", "revocation", "min_version"))

  expect_error(zu_tls(pins = "notapin"), "sha256//")
  expect_error(zu_tls(pins = "sha256//has spaces"), "sha256//")
  expect_error(zu_tls(min_version = 11), "12 \\(TLS 1.2\\) or 13")
  expect_error(zu_tls(ca_file = c("a", "b")), "single file path")
  expect_error(zu_tls(ca_file = NA_character_), "single file path")

  expect_false(zu_tls()$revocation)          # §14.5: off by default
  expect_identical(zu_tls()$min_version, 0L)
})

test_that("a missing CA file is reported by argument name", {
  # "cannot load CA file" without saying which of the two is the error this
  # replaces; the caller has two arguments that take a PEM path.
  expect_error(zuhttp:::check_tls(zu_tls(ca_file = "/no/such/a.pem")),
               "`ca_file` does not exist")
  expect_error(zuhttp:::check_tls(zu_tls(ca_extra = "/no/such/b.pem")),
               "`ca_extra` does not exist")
  expect_error(zuhttp:::check_tls(list(ca_file = "x")), "must come from zu_tls")
  expect_null(zuhttp:::check_tls(NULL))
})

test_that("the printed form says `replaces` and `adds to` (§14.2)", {
  # The section requires those words in the first sentence of the help; the
  # printed object is where a user actually looks when debugging trust.
  out <- paste(capture.output(print(zu_tls(ca_file = "/etc/hosts"))), collapse = " ")
  expect_match(out, "REPLACES", fixed = TRUE)
  out2 <- paste(capture.output(print(zu_tls(ca_extra = "/etc/hosts"))), collapse = " ")
  expect_match(out2, "adds to", fixed = TRUE)
})

# --- the semantics that matter (§14.2, §14.3) ----------------------------

test_that("ca_extra ADDS to system trust and ca_file REPLACES it", {
  skip_unless_online()
  skip_unless_tls_supports("ca_extra")
  skip_unless_tls_supports("ca_file")
  ca <- local_ca()

  # §14.3's claim, stated as a test: "with a locally generated CA supplied
  # additively, a public host still validates through system trust; with the
  # same CA supplied as a replacement, the public host is correctly rejected."
  # The same file both times, so the only variable is which argument it went
  # to — which is the entire distinction.
  r <- zu_get("https://example.com", tls = zu_tls(ca_extra = ca$pem))
  expect_identical(zu_resp_status(r), 200L)

  e <- tryCatch(zu_get("https://example.com", tls = zu_tls(ca_file = ca$pem)),
                condition = function(e) e)
  expect_s3_class(e, "zu_tls_certificate_error")
  expect_s3_class(e, "zu_tls_error")
})

test_that("revocation is off by default (§14.5)", {
  # No network needed: this is what the build reports about itself.
  expect_false(zu_info()$revocation_default)
})

test_that("revocation = TRUE does not break ordinary verification (§14.5)", {
  skip_unless_online()
  # Turning it on should cost latency, which is the documented reason it is
  # not the default — not the ability to connect at all. OpenSSL refuses the
  # flag outright (no CRL or OCSP source, #6); that is asserted offline below.
  skip_unless_tls_supports("revocation")
  expect_identical(
    zu_resp_status(zu_get("https://example.com", tls = zu_tls(revocation = TRUE))),
    200L)
})

# --- D-56: refused, never downgraded (offline) ------------------------------
#
# One config per setting some backend cannot honour. The ones this backend
# honours must pass check_tls(); the ones it does not must raise
# zu_tls_unsupported_error. Every backend has at least one of each today, so
# neither half is empty on any CI leg.

unsupported_cases <- function() {
  # PEM-shaped, so check_tls()'s PEM check passes and the capability check is
  # what decides; the certificate itself is never parsed on this path.
  pem <- tempfile(fileext = ".pem")
  writeLines(c("-----BEGIN CERTIFICATE-----", "MIIB", "-----END CERTIFICATE-----"), pem)
  list(
    pins       = zu_tls(pins = "sha256//YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg="),
    tls13      = zu_tls(min_version = 13),
    ca_file    = zu_tls(ca_file = pem),
    ca_extra   = zu_tls(ca_extra = pem),
    revocation = zu_tls(revocation = TRUE)
  )
}

test_that("zu_info() reports the zu_tls() capabilities from C", {
  caps <- zu_info()$tls_capabilities
  expect_type(caps, "character")
  expect_true(all(caps %in% names(unsupported_cases())))
  # Pinned to what each backend's zu_tls_backend_caps() says, so a change to a
  # backend's support has to be made here on purpose.
  expected <- switch(zu_tls_backend(),
    openssl         = c("pins", "tls13", "ca_file", "ca_extra"),
    securetransport = c("ca_file", "ca_extra", "revocation"),
    schannel        = "revocation",
    character())
  expect_setequal(caps, expected)
})

test_that("a setting the backend cannot honour is refused; one it can is not", {
  cases <- unsupported_cases()
  caps <- zu_info()$tls_capabilities
  refused <- setdiff(names(cases), caps)
  expect_gt(length(refused), 0L)   # the refusal half is never empty
  for (nm in names(cases)) {
    e <- tryCatch(zuhttp:::check_tls(cases[[nm]]), condition = function(e) e)
    if (nm %in% caps) {
      expect_false(inherits(e, "condition"), info = nm)
    } else {
      expect_s3_class(e, "zu_tls_unsupported_error")
      expect_s3_class(e, "zu_tls_error")
      # Never the mismatch class: "cannot pin" and "pin did not match" must
      # stay distinguishable (#12).
      expect_false(inherits(e, "zu_tls_pin_error"), info = nm)
      expect_false(isTRUE(e$retryable), info = nm)
      expect_match(conditionMessage(e), zu_tls_backend(), fixed = TRUE, info = nm)
    }
  }
})

test_that("the refusal happens before any network I/O", {
  # A reserved .invalid name: if the refusal were not wired into the request
  # path, this would reach getaddrinfo and raise zu_dns_error instead. The
  # class tells the two apart, which is what makes this non-vacuous.
  cases <- unsupported_cases()
  refused <- setdiff(names(cases), zu_info()$tls_capabilities)
  for (nm in refused) {
    e <- tryCatch(zu_get("https://zuhttp-test.invalid/", tls = cases[[nm]]),
                  condition = function(e) e)
    expect_s3_class(e, "zu_tls_unsupported_error")
    expect_false(inherits(e, "zu_dns_error"), info = nm)
  }
})

test_that("min_version = 12 works everywhere (§14.1)", {
  skip_unless_online()
  expect_identical(
    zu_resp_status(zu_get("https://example.com", tls = zu_tls(min_version = 12))), 200L)
})

test_that("a wrong pin against a public host is a pin mismatch (§14.4)", {
  skip_unless_online()
  # Where pinning is refused, the offline tests above cover it. Here the pin is
  # really compared, so the class must be the mismatch one and never the
  # refusal: accepting any zu_tls_error is how this test used to pass on
  # Windows, which never compared a pin at all (#12).
  skip_unless_tls_supports("pins")
  e <- tryCatch(
    zu_get("https://example.com",
           tls = zu_tls(pins = "sha256//YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=")),
    condition = function(e) e)
  expect_s3_class(e, "zu_tls_pin_error")
  expect_false(inherits(e, "zu_tls_unsupported_error"))
  expect_false(inherits(e, "zu_response"))
})

# --- §26.1: TLS settings are part of the pool key ------------------------

test_that("a connection is never shared across a TLS-config difference", {
  skip_unless_online()
  skip_unless_tls_supports("ca_extra")
  ca <- local_ca()

  api <- zu_client()
  expect_identical(zu_resp_status(zu_get("https://example.com", client = api)), 200L)
  expect_identical(zu_pool_stats(api)[["idle"]], 1)

  # Same origin, different trust configuration. §26.1 calls a key that ignores
  # this "a security bug, not a performance optimisation": reusing here would
  # run a request that asked for extra trust over a connection established
  # without it.
  expect_identical(
    zu_resp_status(zu_get("https://example.com", tls = zu_tls(ca_extra = ca$pem),
                          client = api)), 200L)
  st <- zu_pool_stats(api)
  expect_identical(st[["hits"]], 0)
  expect_identical(st[["misses"]], 2)

  # ...and the same settings again DO share, or the key would be useless.
  expect_identical(
    zu_resp_status(zu_get("https://example.com", tls = zu_tls(ca_extra = ca$pem),
                          client = api)), 200L)
  expect_identical(zu_pool_stats(api)[["hits"]], 1)
})

test_that("a pinned request is never served over an unpinned connection", {
  skip_unless_online()
  # Where pins are refused the request fails before the pool is consulted, so
  # this would pass without exercising the key.
  skip_unless_tls_supports("pins")
  # The sharpest statement of why §26.1 calls a coarse key a security bug, and
  # what it looks like when it bites. Dropping the TLS fields from the key
  # makes this test return 200: the pinned request draws the connection the
  # UNPINNED request established, so the handshake — and with it the pin check
  # — never runs at all. The pin is not bypassed by a flaw in pinning; it is
  # bypassed by never being reached.
  api <- zu_client()
  expect_identical(zu_resp_status(zu_get("https://example.com", client = api)), 200L)
  expect_identical(zu_pool_stats(api)[["idle"]], 1)

  r <- tryCatch(
    zu_get("https://example.com", client = api,
           tls = zu_tls(pins = "sha256//YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=")),
    condition = function(e) e)

  # Whatever the backend does with the pin — enforce it, or refuse to pin at
  # all — a SUCCESSFUL response here means the connection was reused and the
  # pin was silently skipped.
  expect_false(inherits(r, "zu_response"))
  expect_s3_class(r, "zu_tls_pin_error")
  expect_identical(zu_pool_stats(api)[["hits"]], 0)
})

test_that("revocation and min_version are part of the key too", {
  skip_unless_online()
  api <- zu_client()
  # min_version rather than revocation as the distinguishing field: both are
  # in the key, and only this one can complete a request on every backend
  # (OpenSSL refuses revocation = TRUE, D-56).
  expect_identical(zu_resp_status(zu_get("https://example.com", client = api)), 200L)
  expect_identical(
    zu_resp_status(zu_get("https://example.com", tls = zu_tls(min_version = 12),
                          client = api)), 200L)
  # A field left out of the key is invisible until it is a vulnerability, so
  # each one is asserted rather than assumed to have been included.
  expect_identical(zu_pool_stats(api)[["hits"]], 0)
  expect_identical(zu_pool_stats(api)[["misses"]], 2)
})

test_that("a DER certificate file is named as such, with the fix", {
  # Offline. The extension is irrelevant (.crt is used for PEM and DER alike);
  # the content decides. Before this check the backends said only "cannot
  # read CA file".
  pem <- tempfile(fileext = ".crt")
  writeLines(c("-----BEGIN CERTIFICATE-----", "MIIB", "-----END CERTIFICATE-----"), pem)
  expect_null(zuhttp:::check_pem(pem, "ca_extra"))
  der <- tempfile(fileext = ".crt")
  writeBin(as.raw(c(0x30, 0x82, 0x01, 0x0a, 0x02)), der)
  expect_error(zuhttp:::check_tls(zu_tls(ca_extra = der)), "DER .*openssl x509 -inform der")
  junk <- tempfile(fileext = ".crt"); writeLines("not a certificate", junk)
  expect_error(zuhttp:::check_tls(zu_tls(ca_file = junk)), "`ca_file` has no PEM certificate")
})

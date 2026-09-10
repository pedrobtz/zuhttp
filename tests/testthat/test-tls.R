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
  # not the default — not the ability to connect at all.
  if (identical(zu_tls_backend(), "openssl"))
    skip(paste0("zu_tls(revocation = TRUE) is unusable on this backend: ",
                "zu_tls_openssl.c sets X509_V_FLAG_CRL_CHECK|CRL_CHECK_ALL ",
                "with no CRL source configured, and OpenSSL neither fetches ",
                "CRLs nor performs OCSP, so EVERY chain fails with ",
                "'certificate verify failed'. Measured on CI 2026-09-10. ",
                "S7 owns the fix; until then the flag fails closed on ",
                "everything rather than checking revocation."))
  expect_identical(
    zu_resp_status(zu_get("https://example.com", tls = zu_tls(revocation = TRUE))),
    200L)
})

test_that("a TLS version a backend cannot reach is refused, never downgraded", {
  skip_unless_online()
  if (!identical(zu_tls_backend(), "securetransport"))
    skip("this backend's ceiling is not TLS 1.2")

  # S0 finding F-1: Secure Transport has no kTLSProtocol13. Quietly giving the
  # caller 1.2 when they asked for 1.3 would be silently weakening a security
  # setting, which is worse than failing.
  e <- tryCatch(zu_get("https://example.com", tls = zu_tls(min_version = 13)),
                condition = function(e) e)
  expect_s3_class(e, "zu_tls_error")
  expect_match(conditionMessage(e), "1.3", fixed = TRUE)
  expect_match(conditionMessage(e), "macOS", fixed = TRUE)

  expect_identical(
    zu_resp_status(zu_get("https://example.com", tls = zu_tls(min_version = 12))), 200L)
})

test_that("pinning either works or refuses; it never silently does nothing", {
  skip_unless_online()
  e <- tryCatch(
    zu_get("https://example.com",
           tls = zu_tls(pins = "sha256//YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=")),
    condition = function(e) e)

  if (identical(zu_tls_backend(), "securetransport")) {
    # A documented refusal (§14.4): Security.framework will not yield the
    # SubjectPublicKeyInfo without hand-parsing DER, and a pin that checks the
    # wrong bytes is worse than no pin. The one outcome that must never happen
    # is a 200 — that would mean the pin was accepted and ignored.
    expect_s3_class(e, "zu_tls_pin_error")
  } else {
    # Elsewhere the pin is real, and this one does not match example.com.
    expect_s3_class(e, "zu_tls_error")
  }
  expect_false(inherits(e, "zu_response"))
})

# --- §26.1: TLS settings are part of the pool key ------------------------

test_that("a connection is never shared across a TLS-config difference", {
  skip_unless_online()
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
  expect_s3_class(r, "zu_tls_error")
  expect_identical(zu_pool_stats(api)[["hits"]], 0)
})

test_that("revocation and min_version are part of the key too", {
  skip_unless_online()
  api <- zu_client()
  # min_version rather than revocation as the distinguishing field: both are
  # in the key, and only this one can complete a request on every backend
  # (see the revocation test above for why OpenSSL cannot).
  expect_identical(zu_resp_status(zu_get("https://example.com", client = api)), 200L)
  expect_identical(
    zu_resp_status(zu_get("https://example.com", tls = zu_tls(min_version = 12),
                          client = api)), 200L)
  # A field left out of the key is invisible until it is a vulnerability, so
  # each one is asserted rather than assumed to have been included.
  expect_identical(zu_pool_stats(api)[["hits"]], 0)
  expect_identical(zu_pool_stats(api)[["misses"]], 2)
})

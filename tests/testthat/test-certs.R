# §50.5 — the certificate matrix, against locally generated certificates.
#
# "These negative tests are mandatory from the first commit of any TLS
# backend, on every platform, in CI." The reason is S0 finding F-3: the
# spike's first working build accepted EVERY invalid certificate, because
# OpenSSL clients default to SSL_VERIFY_NONE and under it a verify callback
# returning 0 records the failure without aborting the handshake. That bug
# produced a perfectly working HTTPS connection and would have passed any
# happy-path test. A verification bypass is only visible to a test that
# expects rejection.
#
# So the shape of this file is: one row per way a certificate can be wrong,
# each asserting a REJECTION and a specific condition class. The single
# accepting row exists to prove the fixture can succeed at all — without it,
# a build that rejected everything would pass every other test here.

test_that("a valid certificate from a trusted CA is accepted", {
  # The control. Every rejection below is only meaningful if this passes:
  # a client that refused everything would satisfy the whole matrix.
  skip_unless_local_tls()
  fx <- tls_fixture()
  with_tls_server("good", function(url) {
    r <- zu_get(url, tls = zu_tls(ca_file = fx$ca), timeout = 10)
    expect_identical(zu_resp_status(r), 200L)
    expect_match(r$tls_version, "^TLSv1\\.[23]$")
  })
})

test_that("an unknown issuer is rejected (§14.6)", {
  skip_unless_local_tls()
  fx <- tls_fixture()
  # Signed by a CA the client is never told about. This is the row that F-3
  # would have failed: the handshake completes fine at the protocol level and
  # only trust evaluation can object.
  with_tls_server("untrusted", function(url) {
    e <- tryCatch(zu_get(url, tls = zu_tls(ca_file = fx$ca), timeout = 10),
                  condition = function(e) e)
    expect_s3_class(e, "zu_tls_certificate_error")
    expect_s3_class(e, "zu_tls_error")
    expect_s3_class(e, "zu_error")
    expect_false(inherits(e, "zu_response"))
  })
})

test_that("a hostname mismatch is its OWN condition class (§14.6)", {
  skip_unless_local_tls()
  fx <- tls_fixture()
  # The certificate is valid and correctly signed; only the name is wrong.
  # §14.6 requires this to be distinguishable from an untrusted issuer,
  # because the two have completely different fixes — one is a misconfigured
  # server, the other a missing root.
  with_tls_server("wronghost", function(url) {
    e <- tryCatch(zu_get(url, tls = zu_tls(ca_file = fx$ca), timeout = 10),
                  condition = function(e) e)
    expect_s3_class(e, "zu_tls_hostname_error")
    expect_false(inherits(e, "zu_tls_certificate_error"))
    expect_match(conditionMessage(e), "localhost", fixed = TRUE)
  })
})

test_that("an expired certificate is rejected", {
  skip_unless_local_tls()
  fx <- tls_fixture()
  with_tls_server("expired", function(url) {
    e <- tryCatch(zu_get(url, tls = zu_tls(ca_file = fx$ca), timeout = 10),
                  condition = function(e) e)
    expect_s3_class(e, "zu_tls_certificate_error")
    expect_match(conditionMessage(e), "expired", fixed = TRUE)
  })
})

test_that("a not-yet-valid certificate is rejected", {
  skip_unless_local_tls()
  fx <- tls_fixture()
  with_tls_server("notyet", function(url) {
    e <- tryCatch(zu_get(url, tls = zu_tls(ca_file = fx$ca), timeout = 10),
                  condition = function(e) e)
    # §14.6 groups "expired or not yet valid" as one bullet, and the platforms
    # agree: Security.framework reports a not-yet-valid certificate with the
    # word "expired" too. The class is what matters, and the class is right;
    # the wording is the platform's, and paraphrasing it would put a second
    # description of the failure between the user and their trust store.
    expect_s3_class(e, "zu_tls_certificate_error")
  })
})

test_that("ca_file REPLACES: the system store no longer vouches for anything", {
  skip_unless_local_tls()
  fx <- tls_fixture()
  # The complement of the test-tls.R pair. There, a public host was rejected
  # under a local ca_file; here, a local host is rejected under the WRONG
  # local ca_file. Same rule from the other side: only these roots are
  # trusted, and nothing else is.
  with_tls_server("good", function(url) {
    e <- tryCatch(zu_get(url, tls = zu_tls(ca_file = fx$rogue_ca), timeout = 10),
                  condition = function(e) e)
    expect_s3_class(e, "zu_tls_certificate_error")
  })
})

test_that("ca_extra ADDS: a locally signed host validates without losing system trust", {
  skip_unless_local_tls()
  fx <- tls_fixture()
  with_tls_server("good", function(url) {
    r <- zu_get(url, tls = zu_tls(ca_extra = fx$ca), timeout = 10)
    expect_identical(zu_resp_status(r), 200L)
  })
})

test_that("the system store alone does not trust a locally signed host", {
  skip_unless_local_tls()
  # The other half of the ca_extra test: without the extra root the same
  # server is rejected, so the previous test proves ca_extra did something
  # rather than that the certificate was acceptable all along.
  with_tls_server("good", function(url) {
    e <- tryCatch(zu_get(url, timeout = 10), condition = function(e) e)
    expect_s3_class(e, "zu_tls_certificate_error")
  })
})

test_that("verify = FALSE accepts what verification would reject", {
  skip_unless_local_tls()
  # Not an endorsement — the point is that the switch does what it says, and
  # that everything above fails for trust reasons rather than because the
  # fixture is broken. If this row also failed, the matrix would be measuring
  # a broken server rather than a working client.
  with_tls_server("untrusted", function(url) {
    r <- suppressWarnings(zu_get(url, verify = FALSE, timeout = 10))
    expect_identical(zu_resp_status(r), 200L)
  })
})

test_that("verify = FALSE warns, every time, and names what it turns off", {
  skip_unless_local_tls()
  # §14.1: no single "insecure" switch that disables both peer and hostname
  # checking without naming what it turns off.
  with_tls_server("untrusted", function(url) {
    expect_warning(zu_get(url, verify = FALSE, timeout = 10),
                   "certificate AND hostname")
  })
})

# --- §14.5 revocation (test-hardening A1) ---------------------------------
#
# §14.5's whole argument rests on one measured fact: the platforms do NOT
# check revocation by default. The section exists because an earlier draft
# claimed they did and that claim was false — so of everything in this file,
# this is the claim with the most riding on a test and, until now, the least.

test_that("revocation is off by default: a revoked certificate is accepted (§14.5)", {
  skip_unless_online()
  # Not a bug and not an endorsement — it is what the platform does, and what
  # §14.5 documents. If a future macOS or OpenSSL started checking by default
  # this fails, which is exactly when the section needs rewriting.
  r <- zu_get("https://revoked.badssl.com", timeout = 20)
  expect_identical(zu_resp_status(r), 200L)
})

test_that("zu_tls(revocation = TRUE) changes the outcome for a revoked host", {
  skip_unless_online()
  # The PARENT class, not zu_tls_certificate_error: the subclass differs by
  # backend and asserting one of them made this fail on Linux CI. Secure
  # Transport reports a certificate error; OpenSSL aborts the handshake, since
  # its CRL check fails before the chain is judged. What both must agree on is
  # that the request does not succeed.
  expect_error(
    zu_get("https://revoked.badssl.com", timeout = 20,
           tls = zu_tls(revocation = TRUE)),
    class = "zu_tls_error")
})

test_that("a revocation failure is ABOUT revocation (S9 criterion 4)", {
  skip_unless_online()
  # The arm above is not evidence that revocation checking works, and writing
  # it without this one would have been the vacuous pass §50 keeps warning
  # about. Measured 2026-09-10 on Secure Transport: a VALID badssl.com
  # certificate fails under revocation = TRUE with the identical error as the
  # revoked one — both Let's Encrypt, both "certificates do not meet pinning
  # requirements". Let's Encrypt retired OCSP, so a policy that demands a
  # positive revocation answer cannot get one and fails closed on the whole
  # chain. The revoked host's failure therefore proves nothing about
  # revocation on that backend.
  #
  # So the control comes first, and decides whether there is a test here at
  # all: a same-CA valid certificate must PASS before the revoked one failing
  # means anything.
  tls <- zu_tls(revocation = TRUE)
  control <- tryCatch(zu_get("https://badssl.com", timeout = 20, tls = tls),
                      error = function(e) e)
  if (inherits(control, "condition"))
    skip(paste0("no usable control: a valid badssl.com certificate also fails ",
                "under revocation = TRUE on this backend (", zu_tls_backend(),
                "), so the revoked host proves nothing. S9 criterion 4 stays ",
                "open until a CA that still answers revocation queries is used."))

  expect_identical(zu_resp_status(control), 200L)
  expect_error(
    zu_get("https://revoked.badssl.com", timeout = 20, tls = tls),
    class = "zu_tls_certificate_error")
})

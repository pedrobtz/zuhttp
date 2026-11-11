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

test_that("the committed TLS fixture is not about to expire (#193)", {
  skip_on_cran()
  # The live leaves are valid for 397 days (fixtures/README.md). When they
  # run out the whole matrix fails for the wrong reason, so this says why
  # first, and what to do: tools/make-tls-fixture, then commit fixtures/tls.
  fx <- tls_fixture()
  for (n in c("good", "wronghost", "untrusted", "ip", "ipother", "ipdns")) {
    pem <- readLines(fx$cert(n), warn = FALSE)
    # The notAfter date, read without the openssl CLI: the certificate's
    # DER, base64 in the PEM, carries it as a UTCTime "YYMMDDhhmmssZ" right
    # after notBefore in the Validity sequence.
    der <- openssl_der(pem)
    not_after <- der_utc_times(der)[2]
    expect_true(
      not_after - Sys.Date() > 45,
      info = paste0(
        n,
        ".pem expires on ",
        not_after,
        ": run tools/make-tls-fixture and commit tests/testthat/fixtures/tls"
      )
    )
  }
})

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
    e <- tryCatch(
      zu_get(url, tls = zu_tls(ca_file = fx$ca), timeout = 10),
      condition = function(e) e
    )
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
    e <- tryCatch(
      zu_get(url, tls = zu_tls(ca_file = fx$ca), timeout = 10),
      condition = function(e) e
    )
    expect_s3_class(e, "zu_tls_hostname_error")
    expect_false(inherits(e, "zu_tls_certificate_error"))
    expect_match(conditionMessage(e), "localhost", fixed = TRUE)
  })
})

test_that("a name only in the subject CN is no name (#308)", {
  skip_unless_local_tls()
  fx <- tls_fixture()
  # RFC 9110 §4.3.4: a client MUST NOT use a CN-ID. OpenSSL's host check
  # fell back to the CN when a certificate had no DNS SAN, and accepted
  # what Network.framework refused.
  with_tls_server("cnonly", function(url) {
    e <- tryCatch(
      zu_get(url, tls = zu_tls(ca_file = fx$ca), timeout = 10),
      error = function(e) e
    )
    expect_s3_class(e, "zu_tls_hostname_error")
  })
})

test_that("a client-authentication certificate is not a server's (#309)", {
  skip_unless_local_tls()
  fx <- tls_fixture()
  # Trusted CA, right name, EKU clientAuth only (RFC 5280 §4.2.1.12): a
  # certificate failure, as every backend says for every other chain
  # fault, not OpenSSL's zu_tls_handshake_error.
  with_tls_server("clientonly", function(url) {
    e <- tryCatch(
      zu_get(url, tls = zu_tls(ca_file = fx$ca), timeout = 10),
      error = function(e) e
    )
    expect_s3_class(e, "zu_tls_certificate_error")
  })
})

test_that("an IP literal verifies against an iPAddress SAN (#216, #246)", {
  # The control for the two rows after it: a certificate naming 127.0.0.1
  # as an address is accepted when the URL names 127.0.0.1.
  skip_unless_local_tls()
  fx <- tls_fixture()
  with_tls_server(
    "ip",
    function(url) {
      r <- zu_get(url, tls = zu_tls(ca_file = fx$ca), timeout = 10)
      expect_identical(zu_resp_status(r), 200L)
    },
    host = "127.0.0.1"
  )
})

test_that("an IP literal is refused by another address or a DNS SAN (#246)", {
  # RFC 6125 §1.7.2: an IP literal matches iPAddress entries only. So a
  # certificate naming 127.0.0.2, or naming 127.0.0.1 as a dNSName, is a
  # name mismatch: the hostname class, not "untrusted" and not a handshake
  # fault (#290 was OpenSSL reporting the latter).
  skip_unless_local_tls()
  fx <- tls_fixture()
  for (cert in c("ipother", "ipdns")) {
    with_tls_server(
      cert,
      function(url) {
        e <- tryCatch(
          zu_get(url, tls = zu_tls(ca_file = fx$ca), timeout = 10),
          condition = function(e) e
        )
        expect_s3_class(e, "zu_tls_hostname_error")
        expect_false(inherits(e, "zu_tls_certificate_error"))
        expect_false(inherits(e, "zu_response"))
      },
      host = "127.0.0.1"
    )
  }
})

test_that("an expired certificate is rejected", {
  skip_unless_local_tls()
  skip_unless_cert("expired")
  fx <- tls_fixture()
  with_tls_server("expired", function(url) {
    e <- tryCatch(
      zu_get(url, tls = zu_tls(ca_file = fx$ca), timeout = 10),
      condition = function(e) e
    )
    expect_s3_class(e, "zu_tls_certificate_error")
    expect_match(conditionMessage(e), "expired", fixed = TRUE)
  })
})

test_that("a not-yet-valid certificate is rejected", {
  skip_unless_local_tls()
  skip_unless_cert("notyet")
  fx <- tls_fixture()
  with_tls_server("notyet", function(url) {
    e <- tryCatch(
      zu_get(url, tls = zu_tls(ca_file = fx$ca), timeout = 10),
      condition = function(e) e
    )
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
    e <- tryCatch(
      zu_get(url, tls = zu_tls(ca_file = fx$rogue_ca), timeout = 10),
      condition = function(e) e
    )
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

test_that("ca_extra adds to a ca_file too, not only to the system store (§14.2)", {
  skip_unless_local_tls()
  fx <- tls_fixture()
  # Two independent roots: ca_file names the one that did NOT sign the
  # server, ca_extra the one that did. On macOS the ca_extra branch was an
  # `else if` of the ca_file one, so the extra root was silently dropped and
  # this failed; OpenSSL has always added it on top.
  with_tls_server("good", function(url) {
    r <- zu_get(
      url,
      tls = zu_tls(ca_file = fx$rogue_ca, ca_extra = fx$ca),
      timeout = 10
    )
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

test_that("a TLS session is never resumed past the trust it was verified with (#307)", {
  skip_unless_local_tls()
  # Network.framework kept a process-wide session cache and a resumed
  # handshake skipped the verify block, so a strict request after an
  # unverified one to the same server was accepted unverified. TLS 1.2,
  # because that is where s_server resumed; each request is a fresh client,
  # so the pool is not what carries the session.
  fx <- tls_fixture()
  with_tls_server(
    "good",
    function(url) {
      get <- function(...) {
        tryCatch(
          zu_get(url, timeout = 10, client = zu_client(...)),
          error = function(e) e
        )
      }
      r <- suppressWarnings(get(verify = FALSE))
      expect_identical(zu_resp_status(r), 200L)
      expect_s3_class(get(), "zu_tls_certificate_error")
      expect_identical(
        zu_resp_status(get(tls = zu_tls(ca_file = fx$ca))),
        200L
      )
      expect_s3_class(
        get(tls = zu_tls(ca_file = fx$rogue_ca)),
        "zu_tls_certificate_error"
      )
    },
    args = "-tls1_2"
  )
})

test_that("verify = FALSE warns, every time, and names what it turns off", {
  skip_unless_local_tls()
  # §14.1: no single "insecure" switch that disables both peer and hostname
  # checking without naming what it turns off.
  with_tls_server("untrusted", function(url) {
    expect_warning(
      zu_get(url, verify = FALSE, timeout = 10),
      "certificate AND hostname"
    )
  })
})

# --- §14.4 pinning (S7 criterion 4, #12) ----------------------------------
#
# Three rows, each against the local fixture with a pin computed by the
# openssl CLI (spki_pin), never by zuhttp itself: a test that asked zuhttp for
# the expected value would pass whatever zuhttp hashed. Backends that cannot
# pin refuse before connecting; test-tls.R asserts that, so these skip there.

test_that("a matching pin connects", {
  skip_unless_local_tls()
  skip_unless_tls_supports("pins")
  fx <- tls_fixture()
  with_tls_server("good", function(url) {
    r <- zu_get(
      url,
      tls = zu_tls(ca_file = fx$ca, pins = spki_pin("good")),
      timeout = 10
    )
    expect_identical(zu_resp_status(r), 200L)
  })
})

test_that("a pin that does not match is zu_tls_pin_error, not a refusal", {
  skip_unless_local_tls()
  skip_unless_tls_supports("pins")
  fx <- tls_fixture()
  # The chain is valid and trusted; only the key differs. The class must be
  # the MISMATCH one: zu_tls_unsupported_error here would mean the pin was
  # never compared, which is the vacuous pass #12 found on Windows.
  with_tls_server("good", function(url) {
    e <- tryCatch(
      zu_get(
        url,
        tls = zu_tls(ca_file = fx$ca, pins = spki_pin("wronghost")),
        timeout = 10
      ),
      condition = function(e) e
    )
    expect_s3_class(e, "zu_tls_pin_error")
    expect_false(inherits(e, "zu_tls_unsupported_error"))
  })
})

test_that("a matching pin does not bypass chain verification (§14.4)", {
  skip_unless_local_tls()
  skip_unless_tls_supports("pins")
  fx <- tls_fixture()
  # "Checked in addition to, never instead of": the pin matches the served
  # key exactly, and the untrusted issuer must still be rejected.
  with_tls_server("untrusted", function(url) {
    e <- tryCatch(
      zu_get(
        url,
        tls = zu_tls(ca_file = fx$ca, pins = spki_pin("untrusted")),
        timeout = 10
      ),
      condition = function(e) e
    )
    expect_s3_class(e, "zu_tls_certificate_error")
  })
})

# --- §14.5 revocation (test-hardening A1) ---------------------------------
#
# §14.5's whole argument rests on one measured fact: the platforms do NOT
# check revocation by default. The section exists because an earlier draft
# claimed they did and that claim was false — so of everything in this file,
# this is the claim with the most riding on a test and, until now, the least.

test_that("revocation off by default: what each platform then does (§14.5)", {
  skip_unless_online()
  # Not a bug and not an endorsement — it is what the platform does, and what
  # §14.5 documents. If a platform changes its default, this fails, which is
  # exactly when the section needs rewriting.
  #
  # macOS did, and not deterministically: on 2026-10-29 SecTrust rejected
  # revoked.badssl.com with no revocation policy set on macOS 15.7.9 and on
  # one CI run, under Secure Transport and Network.framework alike, and
  # accepted it on the next CI run. The system consults Apple's revocation
  # data when it has it. zuhttp adds no check and cannot remove that one, so
  # on macOS either outcome is the platform's; what must not happen is a
  # failure of any other kind.
  if (identical(Sys.info()[["sysname"]], "Darwin")) {
    r <- tryCatch(
      zu_get_badssl("https://revoked.badssl.com", timeout = 20),
      error = function(e) e
    )
    if (inherits(r, "error")) {
      expect_s3_class(r, "zu_tls_certificate_error")
    } else {
      expect_identical(zu_resp_status(r), 200L)
    }
  } else {
    r <- zu_get_badssl("https://revoked.badssl.com", timeout = 20)
    expect_identical(zu_resp_status(r), 200L)
  }
})

test_that("zu_tls(revocation = TRUE) changes the outcome for a revoked host", {
  skip_unless_online()
  # Where revocation is refused, the request fails before connecting, which
  # would satisfy the assertion below without testing anything.
  skip_unless_tls_supports("revocation")
  # The PARENT class, not zu_tls_certificate_error: the subclass differs by
  # backend and asserting one of them made this fail on Linux CI. Secure
  # Transport reports a certificate error; OpenSSL aborts the handshake, since
  # its CRL check fails before the chain is judged. What both must agree on is
  # that the request does not succeed.
  expect_error(
    zu_get_badssl(
      "https://revoked.badssl.com",
      timeout = 20,
      tls = zu_tls(revocation = TRUE)
    ),
    class = "zu_tls_error"
  )
})

test_that("a revocation failure is ABOUT revocation (S9 criterion 4)", {
  skip_unless_online()
  skip_unless_tls_supports("revocation")
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
  control <- tryCatch(
    zu_get_badssl("https://badssl.com", timeout = 20, tls = tls),
    error = function(e) e
  )
  if (inherits(control, "condition")) {
    skip(paste0(
      "no usable control: a valid badssl.com certificate also fails ",
      "under revocation = TRUE on this backend (",
      zu_tls_backend(),
      "), so the revoked host proves nothing. S9 criterion 4 stays ",
      "open until a CA that still answers revocation queries is used."
    ))
  }

  expect_identical(zu_resp_status(control), 200L)
  expect_error(
    zu_get_badssl("https://revoked.badssl.com", timeout = 20, tls = tls),
    class = "zu_tls_certificate_error"
  )
})

# --- what the OpenSSL mutation run found untested (the TLS backend pass) --

test_that("min_version = 13 is refused by a TLS 1.2-only server", {
  skip_unless_local_tls()
  skip_unless_tls_supports("tls13")
  fx <- tls_fixture()
  # Mutating the 13 into a 1.2 floor survived: nothing asked a 1.2 server
  # for 1.3. Refused in the handshake, never quietly served at 1.2 (D-56).
  with_tls_server(
    "good",
    function(url) {
      tls <- zu_tls(ca_file = fx$ca, min_version = 13)
      e <- tryCatch(zu_get(url, tls = tls, timeout = 10), error = function(e) e)
      expect_s3_class(e, "zu_tls_handshake_error")
      r <- zu_get(url, tls = zu_tls(ca_file = fx$ca), timeout = 10)
      expect_identical(zu_resp_connection(r)$tls_protocol, "TLSv1.2")
    },
    args = "-tls1_2"
  )
})

test_that("SNI names the host, so a virtual-hosting server picks its certificate", {
  skip_unless_local_tls()
  fx <- tls_fixture()
  # s_server answers SNI "localhost" with `good` and anything else, no SNI
  # included, with `wronghost`. Swapping when SNI is sent (names vs IP
  # literals) survived the mutation run: no server here depended on it.
  with_tls_server(
    "wronghost",
    function(url) {
      r <- zu_get(url, tls = zu_tls(ca_file = fx$ca), timeout = 10)
      expect_identical(zu_resp_status(r), 200L)
    },
    args = sprintf(
      "-servername localhost -cert2 %s -key2 %s",
      fx$cert("good"),
      fx$key("good")
    )
  )
})

test_that("connection metadata is real on a local TLS connection (§35.2)", {
  skip_unless_local_tls()
  fx <- tls_fixture()
  # test-info.R checks this against example.com, which only the network
  # suite reaches; dropping the cipher or trust-backend fields survived.
  with_tls_server("good", function(url) {
    r <- zu_get(url, tls = zu_tls(ca_file = fx$ca), timeout = 10)
    cn <- zu_resp_connection(r)
    expect_match(cn$tls_protocol, "^TLSv1\\.[23]$")
    expect_true(cn$trust_backend %in% c("sectrust", "schannel", "openssl"))
    expect_true(nzchar(cn$tls_cipher))
    expect_false(grepl("^0x", cn$tls_cipher))
    expect_match(cn$tls_cipher, "[A-Z]")
    expect_true(cn$remote_ip %in% c("127.0.0.1", "::1"))
  })
})

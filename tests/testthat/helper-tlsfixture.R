# §50.5's certificate matrix needs certificates. This builds them.
#
# Locally generated, as §50.5 requires: "Reproducing a system trust store in
# CI is the hard part. The practical approach is to test the trust EVALUATOR
# against a store the test controls." Nothing here touches the developer's or
# CI machine's Keychain, and nothing reaches the internet — §50.5 also says
# external internet tests must never be required for CRAN checks.
#
# Built once per session and cached: five leaf certificates and two CAs is a
# few seconds of RSA keygen, and every test in the matrix wants the same set.

.zu_tls_fixture <- new.env(parent = emptyenv())

openssl_bin <- function() {
  p <- Sys.which("openssl")
  if (!nzchar(p)) NULL else unname(p)
}

# system2() does not quote its arguments, so every value here is space-free by
# construction. A subject like "/CN=zuhttp test CA" makes openssl read "test"
# as an option, the generation fails, and the tests skip() themselves — which
# looks like an absent toolchain rather than a broken fixture.
ssl <- function(...) {
  suppressWarnings(system2(openssl_bin(), c(...), stdout = FALSE, stderr = FALSE))
}

tls_fixture <- function() {
  if (!is.null(.zu_tls_fixture$dir)) return(.zu_tls_fixture$paths)
  if (is.null(openssl_bin())) testthat::skip("openssl CLI not available")

  d <- tempfile("zu-certs-"); dir.create(d)
  f <- function(...) file.path(d, paste0(...))

  ca <- function(name, cn) {
    ssl("req", "-x509", "-newkey", "rsa:2048", "-keyout", f(name, ".key"),
        "-out", f(name, ".pem"), "-days", "30", "-nodes", "-subj", paste0("/CN=", cn))
  }
  # Two CAs. The second signs a certificate the client is never told about,
  # which is the "unknown or untrusted issuer" row of §14.6 — distinct from a
  # certificate that is malformed or expired.
  ca("ca", "zuhttp-test-CA")
  ca("rogueca", "zuhttp-rogue-CA")

  leaf <- function(name, san, signer, ...) {
    # serverAuth is not optional: SecTrust's SSL policy rejects a leaf without
    # it as "not permitted for this usage", which reads like a trust failure
    # and is really a missing extension in the fixture.
    writeLines(c(paste0("subjectAltName=DNS:", san),
                 "basicConstraints=CA:FALSE",
                 "keyUsage=digitalSignature,keyEncipherment",
                 "extendedKeyUsage=serverAuth"), f(name, ".ext"))
    ssl("req", "-newkey", "rsa:2048", "-keyout", f(name, ".key"),
        "-out", f(name, ".csr"), "-nodes", "-subj", paste0("/CN=", san))
    ssl("x509", "-req", "-in", f(name, ".csr"), "-CA", f(signer, ".pem"),
        "-CAkey", f(signer, ".key"), "-CAcreateserial", "-out", f(name, ".pem"),
        "-extfile", f(name, ".ext"), ...)
  }

  # A leaf with explicit validity dates, so the intent is readable and the
  # fixture does not depend on today. `x509 -not_before` exists only from
  # OpenSSL 3.4; Ubuntu's 3.0 rejects it, and until 2026-09-25 that made
  # the whole matrix skip on every Linux leg — the OpenSSL backend's §50.5
  # rows had never run in CI. `openssl ca -startdate` is the portable route.
  dated <- function(name, from, to) {
    leaf(name, "localhost", "ca", "-not_before", from, "-not_after", to)
    if (file.exists(f(name, ".pem"))) return(invisible())
    cadir <- f("ca-db-", name); dir.create(cadir)
    file.create(file.path(cadir, "index.txt"))
    writeLines("01", file.path(cadir, "serial"))
    writeLines(c("[ca]", "default_ca=zu", "[zu]",
                 paste0("database=", file.path(cadir, "index.txt")),
                 paste0("new_certs_dir=", cadir),
                 paste0("serial=", file.path(cadir, "serial")),
                 "default_md=sha256", "policy=pol", "unique_subject=no",
                 "[pol]", "commonName=supplied"),
               file.path(cadir, "ca.cnf"))
    ssl("ca", "-batch", "-notext", "-config", file.path(cadir, "ca.cnf"),
        "-cert", f("ca.pem"), "-keyfile", f("ca.key"),
        "-in", f(name, ".csr"), "-out", f(name, ".pem"),
        "-extfile", f(name, ".ext"), "-startdate", from, "-enddate", to)
  }

  leaf("good",      "localhost",  "ca", "-days", "30")
  leaf("wronghost", "other.test", "ca", "-days", "30")
  leaf("untrusted", "localhost",  "rogueca", "-days", "30")
  dated("expired", "20240101000000Z", "20240201000000Z")
  dated("notyet",  "20400101000000Z", "20400201000000Z")

  paths <- list(dir = d, ca = f("ca.pem"), rogue_ca = f("rogueca.pem"),
                cert = function(n) f(n, ".pem"), key = function(n) f(n, ".key"))
  # The three certificates every other row needs. The dated two are checked
  # by the rows that use them (skip_unless_cert), so a toolchain that cannot
  # date a certificate costs two rows, not the matrix.
  for (n in c("good", "wronghost", "untrusted"))
    if (!file.exists(paths$cert(n)))
      testthat::skip(paste("could not generate the", n, "certificate"))

  .zu_tls_fixture$dir   <- d
  .zu_tls_fixture$paths <- paths
  paths
}

skip_unless_cert <- function(name) {
  if (!file.exists(tls_fixture()$cert(name)))
    testthat::skip(paste("could not generate the", name, "certificate"))
}

# The §14.4 pin of a fixture certificate, computed by the openssl CLI rather
# than by zuhttp, so a pin test compares zuhttp's digest with an independent
# one (#12, S7 criterion 4). SHA-256 over the DER SubjectPublicKeyInfo.
spki_pin <- function(cert) {
  fx <- tls_fixture()
  o <- shQuote(openssl_bin())
  cmd <- sprintf(paste("%s x509 -in %s -pubkey -noout | %s pkey -pubin -outform der",
                       "| %s dgst -sha256 -binary | %s base64 -A"),
                 o, shQuote(fx$cert(cert)), o, o, o)
  b64 <- suppressWarnings(system2("sh", c("-c", shQuote(cmd)), stdout = TRUE,
                                  stderr = FALSE))
  if (length(b64) != 1L || !grepl("^[A-Za-z0-9+/]{43}=$", b64))
    testthat::skip(paste("could not compute the pin of", cert))
  paste0("sha256//", b64)
}

# Serve `cert` over TLS on loopback for the duration of `code`, which receives
# the base URL. openssl s_server -www answers any request with a small page,
# which is all the matrix needs — what is under test is the handshake.
with_tls_server <- function(cert, code) {
  fx <- tls_fixture()
  port <- NULL
  for (attempt in 1:8) {
    p <- sample(20000:59000, 1L)
    pidf <- tempfile("zu-s_server-")
    system2("sh", c("-c", shQuote(sprintf(
      "echo $$ > %s; exec %s s_server -cert %s -key %s -accept %d -www -quiet",
      pidf, openssl_bin(), fx$cert(cert), fx$key(cert), p))),
      wait = FALSE, stdout = NULL, stderr = NULL)

    deadline <- Sys.time() + 10
    up <- FALSE
    while (Sys.time() < deadline) {
      con <- try(suppressWarnings(socketConnection("127.0.0.1", p, open = "r+b",
                                                   timeout = 1, blocking = TRUE)),
                 silent = TRUE)
      if (!inherits(con, "try-error")) { close(con); up <- TRUE; break }
      Sys.sleep(0.1)
    }
    if (up) { port <- p; break }
    if (file.exists(pidf))
      try(tools::pskill(as.integer(readLines(pidf, warn = FALSE)[[1]]),
                        tools::SIGKILL), silent = TRUE)
  }
  if (is.null(port)) testthat::skip("could not start a local TLS server")
  on.exit({
    if (file.exists(pidf))
      try(tools::pskill(as.integer(readLines(pidf, warn = FALSE)[[1]]),
                        tools::SIGKILL), silent = TRUE)
    unlink(pidf)
  }, add = TRUE)

  code(sprintf("https://localhost:%d/", port))
}

skip_unless_local_tls <- function() {
  testthat::skip_on_cran()
  if (.Platform$OS.type != "unix") testthat::skip("the fixture uses a POSIX shell")
  if (is.null(openssl_bin())) testthat::skip("openssl CLI not available")
  # Every row of the matrix names its roots with ca_file.
  skip_unless_tls_supports("ca_file")
}

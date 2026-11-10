# S8 (§63.2): the slice from R on Windows over Schannel, a live network
# check run by tools/ci/platform.sh. Kept in a file: `Rscript -e` with a
# multi-line argument dies on Windows before executing anything.
library(zuhttp)
stopifnot(identical(zu_tls_backend(), "schannel"))

r <- zu_get("https://example.com")
cat("status", zu_resp_status(r), "tls", r$tls_version,
    "bytes", length(zu_resp_raw(r)), "\n")
stopifnot(zu_resp_status(r) == 200L)
stopifnot(grepl("Example Domain", zu_resp_text(r), fixed = TRUE))
stopifnot(identical(r$tls_version, "TLSv1.2"))

# §65.1, W20: Schannel offers h2 by ALPN, and http2 = "off" does not.
h <- zu_get("https://httpbingo.org/get")
cat("h2 ->", zu_resp_connection(h)$http_version, "\n")
stopifnot(identical(zu_resp_connection(h)$http_version, "HTTP/2"))
h1 <- zu_get("https://httpbingo.org/get", client = zu_client(http2 = "off"))
stopifnot(identical(zu_resp_connection(h1)$http_version, "HTTP/1.1"))

# The whole point of D-5: Windows has trust anchors again. badssl.com
# refuses runners at times (#63, #283): three attempts, then a check
# whose host never answered is skipped and says so. A verdict, right
# or wrong, still decides; the rule is tests/testthat/helper-net.R's.
unreachable <- function(e) {
  inherits(e, c("zu_timeout_error", "zu_io_error")) ||
    (inherits(e, "zu_connect_error") && !is.null(e$backend_code))
}
badssl <- function(url) {
  for (attempt in 1:3) {
    e <- tryCatch(zu_get(url), error = function(e) e)
    if (!(inherits(e, "error") && unreachable(e))) return(e)
    Sys.sleep(c(1, 3, 0)[attempt])
  }
  cat("SKIP", url, ": badssl.com unreachable after 3 attempts (#63):",
      conditionMessage(e), "\n")
  NULL
}
e <- badssl("https://expired.badssl.com/")
if (!is.null(e)) {
  cat("expired ->", class(e)[1], "|", conditionMessage(e), "\n")
  stopifnot(inherits(e, "zu_tls_certificate_error"))
}
e2 <- badssl("https://wrong.host.badssl.com/")
if (!is.null(e2)) {
  cat("wrong host ->", class(e2)[1], "\n")
  stopifnot(inherits(e2, "zu_tls_hostname_error"))
}

cat("S8: Windows HTTPS works, and bad certificates are rejected\n")

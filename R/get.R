# §63.2 — the vertical slice's R surface.
#
# This is deliberately NOT the API of §31: there is no client object, no
# middleware, no retry policy, no streaming sink. Those arrive with S11/S13/S17.
# What this proves is that the stack composes end to end, and it gives the R
# layer something real to be built against.

#' Perform an HTTP GET
#'
#' The first end-to-end path through zuhttp: URL parsing, TCP, TLS with
#' certificate and hostname verification, request construction, strict response
#' framing, chunked decoding, transparent gzip, one redirect, and a total
#' deadline.
#'
#' @param url A single URL. Only `http://` and `https://` are accepted.
#' @param timeout Total seconds for the whole operation, redirects included.
#' @param follow_redirects Maximum redirects to follow. `0` returns the 3xx.
#' @param verify Verify the peer certificate and hostname. Leave this `TRUE`;
#'   it exists so tests can reach a server with a self-signed certificate.
#' @param max_body Maximum decoded body size in bytes.
#' @param user_agent `User-Agent` to send.
#' @return A `zu_response` object. Use [zu_resp_status()], [zu_resp_body()],
#'   [zu_resp_headers()] and [zu_resp_url()] to read it.
#' @section Cancellation:
#' A request checks for a user interrupt roughly every 100 milliseconds, so
#' Ctrl-C aborts it promptly and raises `zu_interrupted_error`. The connection
#' is closed rather than reused, because after an interrupt the framing
#' position is unknown and reusing it could splice one response into another.
#'
#' **DNS lookups are not interruptible.** A request blocked in the system
#' resolver will not respond to Ctrl-C until the resolver returns, because
#' `getaddrinfo()` offers no way to cancel it. In practice this bounds the
#' worst-case delay by the resolver's own timeout, typically a few seconds.
#'
#' @section Platform status:
#' The long-term design uses each platform's native TLS stack. Until those
#' backends land this package links OpenSSL everywhere, and **on Windows that
#' means HTTPS cannot verify certificates**: OpenSSL there looks for a CA
#' bundle at a compiled-in path that does not exist and does not consult the
#' Windows certificate store. `zu_get()` on Windows therefore fails with
#' `zu_tls_certificate_error` until the Schannel backend arrives.
#'
#' @export
#' @examples
#' # Requires network access, so it is not run during checks.
#' \dontrun{
#' r <- zu_get("https://example.com")
#' zu_resp_status(r)
#' zu_resp_text(r)
#' }
zu_get <- function(url, timeout = 30, follow_redirects = 1L, verify = TRUE,
                   max_body = 16 * 1024^2, user_agent = NULL) {
  stopifnot(is.character(url), length(url) == 1L, !is.na(url))
  if (!isTRUE(verify)) {
    # Not a warning that can be switched off: turning verification off is the
    # single most consequential thing a caller can do here (§14.1).
    warning("verify = FALSE disables certificate AND hostname checking; ",
            "anyone on the network path can read and alter this request.",
            call. = FALSE)
  }
  raw <- .Call(C_zu_get, url,
               as.integer(timeout * 1000),
               as.integer(follow_redirects),
               isTRUE(verify),
               as.numeric(max_body),
               user_agent)
  structure(raw, class = "zu_response")
}

#' Response accessors
#'
#' @param resp A `zu_response` from [zu_get()].
#' @return `zu_resp_status()` an integer; `zu_resp_body()` a raw vector;
#'   `zu_resp_headers()` a named character vector; `zu_resp_url()` the final
#'   URL after redirects, with any credentials removed (§42).
#' @name zu_resp
NULL

#' @rdname zu_resp
#' @export
zu_resp_status <- function(resp) resp$status

#' @rdname zu_resp
#' @export
zu_resp_body <- function(resp) resp$body

#' @rdname zu_resp
#' @export
zu_resp_headers <- function(resp) resp$headers

#' @rdname zu_resp
#' @export
zu_resp_url <- function(resp) resp$url

#' @rdname zu_resp
#' @param encoding Character encoding to assume when the server does not say.
#' @export
zu_resp_text <- function(resp, encoding = "UTF-8") {
  # §31.7's full charset chain arrives with S11; this covers the common case
  # and is explicit about what it does not do.
  ct <- resp$headers[["Content-Type"]]
  cs <- if (!is.null(ct)) sub('.*charset=["\']?([^;"\'[:space:]]+).*', "\\1", ct,
                              ignore.case = TRUE) else NA_character_
  if (!is.null(ct) && identical(cs, ct)) cs <- NA_character_
  enc <- if (!is.na(cs) && nzchar(cs)) cs else encoding
  iconv(readBin(resp$body, "character", 1L, length(resp$body)),
        from = enc, to = "UTF-8", sub = "byte")
}

#' @export
print.zu_response <- function(x, ...) {
  cat(sprintf("<zu_response> %d  %s\n", x$status, x$url))
  if (!is.null(x$tls_version)) cat("  tls:      ", x$tls_version, "\n", sep = "")
  if (x$redirects > 0L) cat("  redirects:", x$redirects, "\n")
  cat("  body:     ", length(x$body), " bytes\n", sep = "")
  # §42.2: printing is an egress, so header values are redacted for display.
  h <- zu_redact_headers_for_display(x$headers)
  if (length(h)) {
    n <- min(length(h), 8L)
    for (i in seq_len(n)) cat("  ", names(h)[i], ": ", h[[i]], "\n", sep = "")
    if (length(h) > n) cat("  ... and ", length(h) - n, " more\n", sep = "")
  }
  invisible(x)
}

#' Which TLS backend was this build linked against?
#'
#' @return A short backend identifier, e.g. `"openssl"`.
#' @export
zu_tls_backend <- function() .Call(C_zu_tls_backend)

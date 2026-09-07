# §42 secret redaction.
#
# The policy itself is in C (src/zu_redact.c) so that there is ONE definition
# applied at every egress. These are the R-visible entry points.
#
# §42.3: nothing here mutates a request. Redaction is a property of the
# formatting layer — a redacted request must still be executable, and storing
# "<redacted>" into one would produce a client that fails authentication in
# confusing ways.

zu_redact_opt <- function(name, default = character()) {
  v <- getOption(name, default)
  if (is.null(v)) character() else as.character(v)
}

#' Additional header names to redact
#'
#' The defaults are `Authorization`, `Proxy-Authorization`, `Cookie`,
#' `Set-Cookie`, `X-Api-Key` and `X-Auth-Token` (§42.1). This adds to them; it
#' cannot remove a default.
#'
#' @param ... Header names, or a single character vector.
#' @return The resulting character vector of extra names, invisibly.
#' @export
zu_redact_headers <- function(...) {
  v <- unique(as.character(unlist(list(...), use.names = FALSE)))
  options(zuhttp.redact_headers = v)
  invisible(v)
}

#' Additional query parameter names to redact
#'
#' The defaults are `access_token`, `api_key`, `signature` and `sig` (§42.1).
#'
#' @param ... Parameter names, or a single character vector.
#' @return The resulting character vector of extra names, invisibly.
#' @export
zu_redact_params <- function(...) {
  v <- unique(as.character(unlist(list(...), use.names = FALSE)))
  options(zuhttp.redact_params = v)
  invisible(v)
}

#' Redact credentials from a URL
#'
#' Removes userinfo entirely and replaces the value of any secret query
#' parameter with `<redacted>` — never with a truncated prefix, which would be
#' enough to confirm a guess (§42.1).
#'
#' Works on text rather than on a parsed URL, because a URL that failed to
#' parse is exactly the one an error message is about.
#'
#' @param url A character vector of URLs.
#' @return A character vector of the same length.
#' @export
#' @examples
#' zu_redact_url("https://user:pw@api.example.com/v1?api_key=SECRET&page=2")
zu_redact_url <- function(url) {
  extra <- zu_redact_opt("zuhttp.redact_params")
  vapply(as.character(url), function(u) {
    .Call(C_zu_redact_url, u, extra)
  }, character(1), USE.NAMES = FALSE)
}

#' Redact a form-encoded request body
#'
#' @param body A single `application/x-www-form-urlencoded` string.
#' @return The redacted string.
#' @export
zu_redact_form <- function(body) {
  extra <- zu_redact_opt("zuhttp.redact_params")
  vapply(as.character(body), function(b) {
    .Call(C_zu_redact_form, b, extra)
  }, character(1), USE.NAMES = FALSE)
}

#' Which header names carry a secret value?
#'
#' @param name A character vector of header names.
#' @return A logical vector.
#' @export
zu_is_secret_header <- function(name) {
  .Call(C_zu_is_secret_header, as.character(name),
        zu_redact_opt("zuhttp.redact_headers"))
}

#' Which query parameter names carry a secret value?
#'
#' @param name A character vector of parameter names.
#' @return A logical vector.
#' @export
zu_is_secret_param <- function(name) {
  .Call(C_zu_is_secret_param, as.character(name),
        zu_redact_opt("zuhttp.redact_params"))
}

#' Redact a set of headers for display
#'
#' Returns the headers with secret values replaced. The originals are
#' untouched: this is for `print()`, traces and conditions (§42.2). The
#' documented asymmetry is that `zu_req_headers()` returns real values,
#' because a user asking for their own header by name is not an accidental
#' disclosure.
#'
#' @param headers A named character vector or list.
#' @return The same shape, with secret values replaced by `<redacted>`.
#' @export
zu_redact_headers_for_display <- function(headers) {
  if (length(headers) == 0) return(headers)
  nms <- names(headers)
  if (is.null(nms)) return(headers)
  secret <- zu_is_secret_header(nms)
  secret[is.na(secret)] <- FALSE
  headers[secret] <- "<redacted>"
  headers
}

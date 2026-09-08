# §14 TLS and trust configuration.
#
# The two things this file exists to keep apart are `ca_file` and `ca_extra`.
# §14.2 calls the distinction security-relevant and says it "routinely
# surprises users who expect additive behavior", and requires the words
# "replaces" and "adds to" in the first sentence of each. They are separate
# arguments and never one overloaded `ca =`, because an overloaded argument is
# how a user ends up trusting only their corporate root and not noticing.

#' TLS and certificate trust settings
#'
#' @param ca_file Path to a PEM bundle that **replaces** the system trust
#'   store: only these roots are trusted. Matches curl and OpenSSL, and
#'   surprises people who expect it to add — for that, use `ca_extra`.
#' @param ca_extra Path to a PEM bundle that **adds to** the system trust
#'   store: the platform's roots are still trusted, plus these. This is the
#'   enterprise case — a corporate root alongside the public ones.
#' @param pins Public-key pins as `"sha256//<base64>"` strings. Checked **in
#'   addition to** chain and hostname verification, never instead of it
#'   (§14.4). A connection must satisfy both.
#' @param revocation Check certificate revocation. **Off by default**, and the
#'   default is deliberate — see below.
#' @param min_version Minimum TLS version: `12` or `13`.
#' @return A `zu_tls_config` object, for `zu_client(tls = )` or
#'   `zu_get(url, tls = )`.
#'
#' @section Why revocation is off by default:
#' Two measured reasons (§14.5, S0 finding F-4). It costs 7-15x on macOS —
#' trust evaluation went from ~4-9 ms to ~62 ms, because a positive response
#' requires an OCSP or CRL fetch. And that fetch happens *inside* the
#' platform's trust evaluator, which zuhttp neither owns nor can deadline or
#' cancel: it is invisible to the timeout model and punches a hole in the
#' cancellation guarantee. Turning it on is a reasonable choice; making it the
#' default would mean every request carries an uninterruptible network call
#' nobody asked for.
#'
#' @section Verification is not configured here:
#' Use `verify = FALSE` on the client or the request. It is a merged policy
#' argument like `timeout`, and having a second place to set it would make
#' "is this connection verified?" a question with two answers.
#'
#' @seealso [zu_info()], which reports the effective revocation policy.
#' @export
#' @examples
#' zu_tls(ca_extra = "corporate-root.pem")
#' zu_tls(pins = "sha256//YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=")
zu_tls <- function(ca_file = NULL, ca_extra = NULL, pins = NULL,
                   revocation = FALSE, min_version = NULL) {
  path1 <- function(x, nm) {
    if (is.null(x)) return(NULL)
    if (!is.character(x) || length(x) != 1L || is.na(x) || !nzchar(x))
      stop("`", nm, "` must be a single file path", call. = FALSE)
    path.expand(x)
  }
  if (!is.null(pins)) {
    pins <- as.character(pins)
    bad <- !grepl("^sha256//[A-Za-z0-9+/]+=*$", pins)
    if (any(bad))
      stop("pins must look like \"sha256//<base64>\"; got ",
           paste(pins[bad], collapse = ", "), call. = FALSE)
  }
  if (!is.null(min_version) && !isTRUE(min_version %in% c(12, 13)))
    stop("`min_version` must be 12 (TLS 1.2) or 13 (TLS 1.3)", call. = FALSE)

  structure(
    list(ca_file = path1(ca_file, "ca_file"),
         ca_extra = path1(ca_extra, "ca_extra"),
         pins = pins,
         revocation = isTRUE(revocation),
         min_version = if (is.null(min_version)) 0L else as.integer(min_version)),
    class = "zu_tls_config"
  )
}

#' @export
print.zu_tls_config <- function(x, ...) {
  cat("<zu_tls_config>\n")
  if (!is.null(x$ca_file))  cat("  ca_file:  ", x$ca_file, " (REPLACES system trust)\n", sep = "")
  if (!is.null(x$ca_extra)) cat("  ca_extra: ", x$ca_extra, " (adds to system trust)\n", sep = "")
  if (length(x$pins))       cat("  pins:     ", length(x$pins), "\n", sep = "")
  cat("  revocation: ", if (x$revocation) "on" else "off", "\n", sep = "")
  if (x$min_version) cat("  min TLS:  1.", x$min_version - 10L, "\n", sep = "")
  invisible(x)
}

# Files are checked in R, where the error can name the argument and the path.
# Doing it in C would produce "cannot load CA file" with no indication of which
# of the two the caller got wrong.
check_tls <- function(tls) {
  if (is.null(tls)) return(NULL)
  if (!inherits(tls, "zu_tls_config"))
    stop("`tls` must come from zu_tls(); got ", class(tls)[[1]], call. = FALSE)
  for (f in c("ca_file", "ca_extra")) {
    p <- tls[[f]]
    if (!is.null(p) && !file.exists(p))
      stop("`", f, "` does not exist: ", p, call. = FALSE)
  }
  tls
}

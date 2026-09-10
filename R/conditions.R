#' @useDynLib zuhttp, .registration = TRUE
NULL

# The §34.1 condition hierarchy.
#
# Built with base R only (§34.3): `structure(class = ...)` and `stop()`, not
# rlang::abort(). That keeps the hard-dependency count at zero, and the
# conditions are still well-formed for rlang::catch_cnd() because the class
# vector and the message/call fields follow the standard layout.
#
# The class chain comes from C (zu_code_class_chain) rather than from a table
# here, so the hierarchy has one definition. A parent map maintained in R
# would drift from the C enum the first time a code was added.

#' Error codes used by zuhttp
#'
#' A named integer vector mapping each condition class to its stable code.
#' The code is part of the public API; message wording is not.
#'
#' @return A named integer vector.
#' @export
#' @examples
#' zu_error_codes()[["zu_tls_certificate_error"]]
zu_error_codes <- function() {
  .Call(C_zu_error_codes)
}

#' Is an error code worth retrying?
#'
#' @param code An integer code, or the class name of a zuhttp condition.
#' @return `TRUE`, `FALSE`, or `NA` if the code is unknown.
#' @export
zu_code_retryable <- function(code) {
  code <- as_zu_code(code)
  if (is.na(code)) return(NA)
  .Call(C_zu_code_retryable, code)
}

as_zu_code <- function(code) {
  if (is.character(code)) {
    all <- zu_error_codes()
    idx <- match(code, names(all))
    return(if (is.na(idx)) NA_integer_ else unname(all[[idx]]))
  }
  code <- suppressWarnings(as.integer(code))
  if (length(code) != 1L) NA_integer_ else code
}

#' Construct a zuhttp condition
#'
#' Mostly internal, but exported so that package authors building on zuhttp can
#' raise conditions their users can catch with the same handlers.
#'
#' @param code Integer code or class name, e.g. `"zu_tls_certificate_error"`.
#' @param message The human-readable message (§34.4: what was attempted, what
#'   failed, and the most likely fix).
#' @param url Optional URL. It is **redacted** before being stored (§42.2), so
#'   a condition object can be printed or logged safely.
#' @param phase One of `"dns"`, `"connect"`, `"tls"`, `"write"`, `"ttfb"`,
#'   `"read"`, `"decode"`, or `NULL`.
#' @param backend,backend_code The platform backend and its native code, where
#'   useful. Present but never leading (§34.4).
#' @param request,response Objects where they exist.
#' @param call The originating call.
#' @return A condition object inheriting from the §34.1 classes, plus `error`
#'   and `condition`.
#' @export
zu_condition <- function(code, message, url = NULL, phase = NULL,
                         backend = NULL, backend_code = NULL,
                         request = NULL, response = NULL,
                         call = sys.call(-1)) {
  icode <- as_zu_code(code)
  if (is.na(icode)) stop("unknown zuhttp error code: ", format(code))

  structure(
    class = .Call(C_zu_condition_classes, icode),
    list(
      message      = message,
      call         = call,
      code         = icode,
      # §42.3: the stored URL is redacted because a condition is a formatting
      # artefact, not something anyone re-executes.
      url          = if (is.null(url)) NULL else zu_redact_url(url),
      phase        = phase,
      backend      = backend,
      backend_code = backend_code,
      retryable    = .Call(C_zu_code_retryable, icode),
      request      = request,
      response     = response
    )
  )
}

zu_stop <- function(code, message, ..., call = sys.call(-1)) {
  stop(zu_condition(code, message, ..., call = call))
}

# Called from C (src/init.c) when a request fails. Building the condition here
# rather than in C keeps the §34.1 hierarchy in exactly one place.
zu_stop_from_c <- function(code, message, url, phase, backend, backend_code) {
  stop(zu_condition(
    code, message,
    url          = url,
    phase        = if (identical(phase, "none")) NULL else phase,
    backend      = backend,
    backend_code = if (is.null(backend)) NULL else backend_code,
    call         = sys.call(-1)
  ))
}

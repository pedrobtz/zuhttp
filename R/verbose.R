# §42.2's last egress: verbose transport logging.
#
# Built as a set of §35.3 hooks rather than as a separate tracing path, and
# that is the whole design. Hook payloads already pass through the §42
# redaction filter before any handler sees them, so a verbose trace CANNOT
# carry a credential — not because this file is careful, but because it never
# receives one. A parallel logging path would have needed its own redaction,
# which is the second implementation §42 opens by warning about.

#' Print a trace of each request
#'
#' Returns hooks that log the request lifecycle, for
#' `zu_client(hooks = zu_verbose())`.
#'
#' @param to A connection to write to. Defaults to [stderr()], so a trace
#'   never contaminates data a script is writing to stdout.
#' @param body Show response body sizes.
#' @return A [zu_hooks()] object.
#'
#' @section Credentials:
#' A trace cannot leak one. It is built on §35.3 hooks, whose payloads are
#' redacted before any handler runs, so this function never sees a real
#' `Authorization` header or a secret query parameter — there is nothing here
#' to get right or wrong. That is why verbose logging is implemented as hooks
#' rather than as its own path through the request.
#'
#' @seealso [zu_hooks()] for your own handlers.
#' @export
#' @examples
#' cli <- zu_client(hooks = zu_verbose(),
#'                  transport = zu_mock_transport(function(r) zu_response(200L)))
#' invisible(zu_get("https://example.test/x", client = cli))
zu_verbose <- function(to = stderr(), body = TRUE) {
  say <- function(...) cat(..., "\n", sep = "", file = to)

  zu_hooks(
    before_request = function(p) {
      say("> ", p$request$method %||% "GET", " ", p$request$url %||% "")
      h <- p$request$headers
      for (i in seq_along(h)) say(">   ", names(h)[i], ": ", h[[i]])
    },
    after_response = function(p) {
      r <- p$response
      say("< HTTP ", r$status %||% NA,
          if (!is.null(r$tls_version)) paste0(" over ", r$tls_version) else "")
      h <- r$headers
      for (i in seq_along(h)) say("<   ", names(h)[i], ": ", h[[i]])
      if (isTRUE(body)) say("< ", length(r$body %||% raw()), " bytes")
      t <- r$timings[["total"]]
      if (!is.null(t) && !is.na(t)) say("< ", sprintf("%.3fs", t))
    },
    before_retry = function(p) {
      say("* retry ", p$attempt, " after ", sprintf("%.2fs", p$delay %||% 0),
          " (", p$why %||% "?", ")")
    }
  )
}

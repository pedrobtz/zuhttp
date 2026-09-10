# §42.2's last egress: verbose transport logging.
#
# Built as a set of §35.3 hooks rather than as a separate tracing path, and
# that is the whole design. Hook payloads already pass through the §42
# redaction filter before any handler sees them, so a verbose trace CANNOT
# carry a credential — not because this file is careful, but because it never
# receives one. A parallel logging path would have needed its own redaction,
# which is the second implementation §42 opens by warning about.
#
# The §35.3 event log is the exception to "never receives one", and it was a
# leak until D-51: those events are read off the response rather than handed
# to a hook, so nothing on the R side had filtered them and
# `zu_get(url, trace = TRUE)` printed the URL's userinfo and secret query
# parameters here. The engine now redacts a URL as it enters the log, which
# is the only place that can work — by the time R sees a trace, the detail is
# already stored on the response object.

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
#' A trace cannot leak one, and in two different ways. The request and
#' response lines come from §35.3 hooks, whose payloads are redacted before
#' any handler runs, so this function never sees a real `Authorization` header
#' — there is nothing here to get right or wrong, which is why verbose logging
#' is implemented as hooks rather than as its own path through the request.
#' The phase lines from `trace = TRUE` are different: they are read off the
#' response, so the engine redacts each URL as it records it (§42.2, D-51). A
#' traced URL therefore shows `?access_token=<redacted>` rather than the
#' token, and userinfo is dropped entirely.
#'
#' @section Seeing the whole chain:
#' Pair it with `trace = TRUE` on the request and the §35.3 phases appear —
#' DNS, connect, TLS handshake, request, headers, body — each with the time it
#' happened and the gap since the previous one. Without `trace`, the output is
#' the HTTP layer only.
#'
#' @seealso [zu_resp_trace()], [zu_hooks()] for your own handlers.
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
      # §35.3's phases, when the request was traced. Printed before the
      # response line because that is the order they happened in, and the
      # point of a trace is to show where the time went rather than to
      # summarise it afterwards.
      tr <- zu_resp_trace(r)
      if (!is.null(tr)) {
        prev <- 0
        for (i in seq_len(nrow(tr))) {
          gap <- tr$at_ms[i] - prev
          prev <- tr$at_ms[i]
          say("* ", format(sprintf("%.0fms", tr$at_ms[i]), width = 7),
              " +", format(sprintf("%.0f", gap), width = 4), "  ",
              format(tr$event[i], width = 18),
              if (nzchar(tr$detail[i])) tr$detail[i] else "",
              if (tr$n[i] > 0) paste0("  (", tr$n[i], ")") else "")
        }
        if (!is.null(attr(tr, "dropped")))
          say("* ", attr(tr, "dropped"), " further events not recorded")
      }
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

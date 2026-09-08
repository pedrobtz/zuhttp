# §31.13 middleware and §35.3 hooks.
#
# The section's own warning is the design: policy is NOT middleware. An
# earlier draft let zu_retry() be passed both as `retry =` and inside
# `middleware = list(...)`, and it cannot be both — ordering, merging and
# zu_client_update() all go ambiguous. So:
#
#   policy      declarative, dedicated arguments, merged per §31.9
#   middleware  user behaviour, function(req, next_fn) -> response
#   hooks       observability, must NOT be able to modify the request
#
# Built-in policies (retry) are implemented internally as middleware but are
# not CONFIGURED that way. That distinction is the whole point of §31.13.

#' Register lifecycle hooks
#'
#' Hooks are observability (§35.3). They are handed a payload and their return
#' value is discarded — a hook that could modify the request would be
#' middleware wearing a disguise, and §31.13 keeps the two apart deliberately.
#'
#' Every payload passes through the §42 redaction filter before a handler sees
#' it. A trace handler that logs request headers must not be the mechanism by
#' which a bearer token reaches a log file.
#'
#' @param before_request Called with `list(request)` before each attempt.
#' @param after_response Called with `list(request, response, attempt)`.
#' @param before_retry Called with `list(request, attempt, delay, why)`
#'   before sleeping — §33.4 requires that a retry be visible, because a
#'   retry nobody can see is a latency mystery for whoever debugs it later.
#' @param after_retry Called with `list(request, attempt)` when a retried
#'   attempt begins.
#' @return A `zu_hooks` object, for `zu_client(hooks = )`.
#' @export
#' @examples
#' seen <- character()
#' h <- zu_hooks(before_request = function(p) seen <<- c(seen, p$request$url))
#' cli <- zu_client(hooks = h,
#'                  transport = zu_mock_transport(function(r) zu_response(200L)))
#' invisible(zu_get("https://x.test/a", client = cli))
#' seen
zu_hooks <- function(before_request = NULL, after_response = NULL,
                     before_retry = NULL, after_retry = NULL) {
  h <- list(before_request = before_request, after_response = after_response,
            before_retry = before_retry, after_retry = after_retry)
  h <- h[!vapply(h, is.null, logical(1))]
  for (nm in names(h))
    if (!is.function(h[[nm]]))
      stop("hook `", nm, "` must be a function of one argument", call. = FALSE)
  structure(h, class = "zu_hooks")
}

#' @export
print.zu_hooks <- function(x, ...) {
  cat("<zu_hooks: ", if (length(x)) paste(names(x), collapse = ", ") else "none",
      ">\n", sep = "")
  invisible(x)
}

# Fire one event. A hook must never be able to break a request: a handler that
# errors is downgraded to a warning, because observability that can take down
# the thing it observes is worse than no observability.
fire_hook <- function(hooks, event, payload) {
  f <- hooks[[event]]
  if (is.null(f)) return(invisible(NULL))
  payload <- redact_payload(payload)
  tryCatch(f(payload), error = function(e)
    warning("hook `", event, "` failed: ", conditionMessage(e), call. = FALSE))
  invisible(NULL)
}

# §35.3: "All hook payloads pass through the redaction filter in §42 before
# the handler sees it." Applied to the request and response a payload carries,
# not to the payload's scalars.
redact_payload <- function(p) {
  if (!is.null(p$request)) {
    p$request$url     <- zu_redact_url(p$request$url %||% "")
    p$request$headers <- zu_redact_headers_for_display(p$request$headers)
  }
  if (!is.null(p$response)) {
    p$response$url     <- zu_redact_url(p$response$url %||% "")
    p$response$headers <- zu_redact_headers_for_display(p$response$headers)
    if (!is.null(p$response$request)) {
      p$response$request$url     <- zu_redact_url(p$response$request$url %||% "")
      p$response$request$headers <-
        zu_redact_headers_for_display(p$response$request$headers)
    }
  }
  p
}

# Compose middleware around a terminal function. The first element of
# `middleware` is outermost, which is the order the §31.13 diagram draws and
# the order a reader of `middleware = list(logging, signing)` expects.
compose_middleware <- function(middleware, terminal) {
  f <- terminal
  for (m in rev(middleware)) {
    local({
      inner <- f
      mw    <- m
      f <<- function(req) mw(req, inner)
    })
  }
  f
}

check_middleware <- function(middleware) {
  if (is.null(middleware)) return(list())
  if (is.function(middleware)) middleware <- list(middleware)
  if (!is.list(middleware) || !all(vapply(middleware, is.function, logical(1))))
    stop("`middleware` must be a function of (req, next_fn), or a list of them",
         call. = FALSE)
  middleware
}

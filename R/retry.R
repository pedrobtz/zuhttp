# §33 retry.
#
# "Retry must be safe by default. An HTTP client that silently replays a POST
# is a data-integrity bug waiting to happen." Everything here follows from
# that sentence, and the shape it forces is: retrying is a decision with THREE
# independent preconditions (§33.1), all of which must hold, and the default
# answer to each is no.
#
# The layer lives in R, above the transport, because a retry re-runs the whole
# transport call — including a mock or a cassette, which is what makes retry
# behaviour testable offline.

#' Retry policy
#'
#' Retrying is **off by default**: the package default is `attempts = 1`.
#'
#' @param attempts Total attempts *including the first*, so `attempts = 1`
#'   means no retrying and `attempts = 3` means at most two retries. (An
#'   earlier draft of the design used `attempts` and `max_attempts` with
#'   meanings differing by one; there is one name and one meaning.)
#' @param backoff `"exponential"` or `"constant"`.
#' @param base Seconds for the first backoff interval.
#' @param max_delay Ceiling for a single computed backoff, in seconds.
#' @param jitter Randomise each delay over `[0, delay]` ("full jitter").
#'   On by default: synchronised retries from many R sessions are a real
#'   thundering-herd source (§33.3).
#' @param retry_after Honour a `Retry-After` response header.
#' @param max_retry_after Clamp for `Retry-After`, in seconds. A hostile or
#'   misconfigured server must not be able to pin an R session for hours.
#' @param attempt_timeout Optional per-attempt bound in seconds. The `total`
#'   timeout still bounds the whole call (§24.3); this bounds one try.
#' @param on Extra HTTP statuses to treat as retryable, beyond §33.2's
#'   408, 429, 500, 502, 503 and 504.
#' @return A `zu_retry_policy`, for `zu_client(retry = )` or
#'   [zu_req_retry()].
#' @seealso [zu_req_retry()] for per-request opt-in, including the
#'   replay-safety override that a POST needs.
#' @export
#' @examples
#' zu_retry(attempts = 3)
#' zu_client(retry = zu_retry(attempts = 5, max_delay = 10))
zu_retry <- function(attempts = 3L, backoff = c("exponential", "constant"),
                     base = 1, max_delay = 60, jitter = TRUE,
                     retry_after = TRUE, max_retry_after = 60,
                     attempt_timeout = NULL, on = NULL) {
  backoff <- match.arg(backoff)
  if (!is.numeric(attempts) || length(attempts) != 1L || is.na(attempts) ||
      attempts < 1)
    stop("`attempts` must be a single number of at least 1 ",
         "(1 means no retrying)", call. = FALSE)
  pos <- function(x, nm) {
    if (!is.numeric(x) || length(x) != 1L || is.na(x) || x < 0)
      stop("`", nm, "` must be a single non-negative number", call. = FALSE)
    as.numeric(x)
  }
  structure(
    list(attempts = as.integer(attempts), backoff = backoff,
         base = pos(base, "base"), max_delay = pos(max_delay, "max_delay"),
         jitter = isTRUE(jitter), retry_after = isTRUE(retry_after),
         max_retry_after = pos(max_retry_after, "max_retry_after"),
         attempt_timeout = if (is.null(attempt_timeout)) NULL
                           else pos(attempt_timeout, "attempt_timeout"),
         on = if (is.null(on)) integer() else as.integer(on)),
    class = "zu_retry_policy"
  )
}

#' @export
print.zu_retry_policy <- function(x, ...) {
  cat("<zu_retry_policy>\n")
  if (x$attempts <= 1L) {
    cat("  attempts: 1 (retrying disabled)\n")
    return(invisible(x))
  }
  cat("  attempts: ", x$attempts, " (up to ", x$attempts - 1L, " retries)\n", sep = "")
  cat("  backoff:  ", x$backoff, ", base ", x$base, "s, max ", x$max_delay, "s",
      if (x$jitter) ", full jitter", "\n", sep = "")
  if (x$retry_after)
    cat("  Retry-After honoured, clamped to ", x$max_retry_after, "s\n", sep = "")
  if (!is.null(x$attempt_timeout))
    cat("  attempt_timeout: ", x$attempt_timeout, "s\n", sep = "")
  invisible(x)
}

#' Per-request retry settings
#'
#' The only way to make a non-idempotent request retryable. `zu_retry()` on a
#' client says *how* to retry; this says *whether this particular request may
#' be*.
#'
#' @param req A `zu_request`.
#' @param attempts Total attempts for this request; see [zu_retry()].
#' @param replay_safe Declare that replaying this request is safe even though
#'   its method is not idempotent. This is a promise about the server, and
#'   only the caller can make it.
#' @param idempotency_key `TRUE` to generate an `Idempotency-Key` header, or a
#'   string to supply one. A request carrying that header is replay-safe by
#'   §33.1, because the header is the mechanism the payment and API ecosystem
#'   standardised on for exactly this.
#' @param ... Further [zu_retry()] arguments.
#' @return The request, modified.
#' @seealso [zu_retry()]
#' @export
#' @examples
#' req <- zu_request("POST", "https://api.example.com/charges")
#' # A POST is never retried automatically; this is the opt-in.
#' req <- zu_req_retry(req, attempts = 3, idempotency_key = TRUE)
#' zu_req_replay_safe(req)
zu_req_retry <- function(req, attempts = 3L, replay_safe = NULL,
                         idempotency_key = NULL, ...) {
  req <- check_req(req)
  req$policy$retry <- zu_retry(attempts = attempts, ...)
  if (!is.null(replay_safe)) req$replay_safe <- isTRUE(replay_safe)
  if (!is.null(idempotency_key) && !identical(idempotency_key, FALSE)) {
    key <- if (isTRUE(idempotency_key)) new_idempotency_key()
           else as.character(idempotency_key)
    req <- zu_headers(req, "Idempotency-Key" = key)
  }
  req
}

# A random 32-hex-character token. Not a UUID: R has no uuid in base, and the
# header's contract is only that the value be unique per logical operation.
new_idempotency_key <- function() {
  paste(format(as.hexmode(sample.int(16L, 32L, replace = TRUE) - 1L), width = 1),
        collapse = "")
}

#' Is this request safe to replay?
#'
#' `TRUE` when §33.1's second condition holds: the method is idempotent, or
#' the caller declared it replay-safe, or the request carries an
#' `Idempotency-Key`.
#'
#' @param req A `zu_request`.
#' @return A logical.
#' @seealso [zu_body_rewindable()], which is §33.1's third condition.
#' @export
#' @examples
#' zu_req_replay_safe(zu_request("GET", "https://x.test/"))
#' zu_req_replay_safe(zu_request("POST", "https://x.test/"))
zu_req_replay_safe <- function(req) {
  req <- check_req(req)
  if (isTRUE(req$replay_safe)) return(TRUE)
  nms <- tolower(names(req$headers) %||% character())
  if ("idempotency-key" %in% nms) return(TRUE)
  # RFC 7231's idempotent methods. POST is deliberately absent.
  toupper(req$method) %in% c("GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE")
}

#' Can this request's body be replayed?
#'
#' §28.2 makes rewindability a property of the body rather than a convention,
#' so the retry layer (§33) and the redirect layer (§19.1) can refuse rather
#' than truncate.
#'
#' @param req A `zu_request`.
#' @return A logical. `TRUE` for an absent body and for any in-memory body,
#'   which is every body this version can construct.
#' @seealso [zu_req_replay_safe()]
#' @export
#' @examples
#' zu_body_rewindable(zu_request("GET", "https://x.test/"))
zu_body_rewindable <- function(req) {
  req <- check_req(req)
  # Explicitly marked wins, so a body source that knows it cannot rewind can
  # say so. Streaming bodies (§28.2's connection and callback rows) arrive
  # with S17 and are the first things that will set this to FALSE; until then
  # every body this package can build is a raw vector in memory.
  if (!is.null(req$body_rewindable)) return(isTRUE(req$body_rewindable))
  is.null(req$body) || is.raw(req$body)
}

# --- §33.2 the condition table -------------------------------------------

# Retryability of a completed attempt. `resp` is a response if one arrived,
# `cnd` the condition if one was raised; exactly one is non-NULL.
#
# Returns a list(retry = logical, after = seconds or NULL, why = string). The
# reason is carried rather than reconstructed because §33.4 puts it in the
# before_retry hook, and a retry nobody can see is a latency mystery later.
retry_verdict <- function(resp, cnd, policy) {
  if (!is.null(cnd)) {
    code <- cnd$code
    if (!is.null(code) && isTRUE(zu_code_retryable(code)))
      return(list(retry = TRUE, after = NULL, why = class(cnd)[[1]]))
    return(list(retry = FALSE, after = NULL, why = class(cnd)[[1]]))
  }
  st <- zu_resp_status(resp)
  # §33.2. "Other 5xx: no by default" — so this is a list, not `st >= 500`.
  retryable <- c(408L, 429L, 500L, 502L, 503L, 504L, policy$on)
  if (!(st %in% retryable))
    return(list(retry = FALSE, after = NULL, why = paste("HTTP", st)))
  after <- if (isTRUE(policy$retry_after))
    parse_retry_after(zu_resp_header(resp, "retry-after")) else NULL
  list(retry = TRUE, after = after, why = paste("HTTP", st))
}

# `Retry-After` in both RFC 7231 forms: delta-seconds, or an HTTP-date.
# Returns seconds, or NULL when absent or unparseable — never an error, since
# a malformed header from a server must not break the request.
parse_retry_after <- function(v) {
  if (length(v) == 0 || is.na(v[[1]]) || !nzchar(v[[1]])) return(NULL)
  v <- trimws(v[[1]])
  if (grepl("^[0-9]+$", v)) return(as.numeric(v))
  # HTTP-date. Parsed in C locale and UTC explicitly: the month abbreviations
  # in an HTTP date are English regardless of the R session's locale, and
  # %Z is not reliably parsed, so the offset is fixed rather than read.
  old <- Sys.getlocale("LC_TIME")
  on.exit(try(Sys.setlocale("LC_TIME", old), silent = TRUE), add = TRUE)
  try(Sys.setlocale("LC_TIME", "C"), silent = TRUE)
  t <- suppressWarnings(as.POSIXct(v, format = "%a, %d %b %Y %H:%M:%S", tz = "GMT"))
  if (is.na(t)) return(NULL)
  d <- as.numeric(difftime(t, Sys.time(), units = "secs"))
  # A date in the past means "now"; it must not become a negative delay.
  max(0, d)
}

# §33.3 the delay for one retry.
backoff_delay <- function(policy, attempt, retry_after) {
  if (!is.null(retry_after)) {
    # Clamped, not trusted (§33.3).
    return(min(retry_after, policy$max_retry_after))
  }
  d <- if (identical(policy$backoff, "exponential"))
    policy$base * 2^(attempt - 1L) else policy$base
  d <- min(d, policy$max_delay)
  # Full jitter: uniform over [0, d], not d plus a wiggle. The point is to
  # decorrelate many sessions that failed at the same instant, and only the
  # full-jitter form actually does that.
  if (isTRUE(policy$jitter)) d <- stats::runif(1, 0, d)
  d
}

# §33.3 / §25: the backoff sleep.
#
# Two properties are wanted, and they come from different places, which is
# worth being precise about because an earlier draft of this function had a
# stub `interrupt_pending()` that always returned FALSE — a checkpoint that
# checked nothing, which reads as a mechanism and is not one.
#
#   Ctrl-C     comes from Sys.sleep() itself, which R implements as an
#              interruptible wait on every platform. Slicing does not add it.
#   the budget comes from the loop: §33.3 requires the retry layer to fail
#              rather than sleep past the deadline, and re-checking the clock
#              each slice means a deadline that passes DURING a long backoff
#              cuts the wait short instead of being noticed afterwards.
#
# So the loop exists for the deadline, and the interruptibility is inherited.
# Saying so is the difference between a comment and a claim.
retry_sleep <- function(seconds, deadline_at, slice = 0.1) {
  repeat {
    left <- min(seconds, max(0, deadline_at - proc.time()[["elapsed"]]))
    if (left <= 0) break
    Sys.sleep(min(slice, left))
    seconds <- seconds - min(slice, left)
    if (seconds <= 0) break
  }
  invisible(NULL)
}

# §26 — the connection pool, from R.
#
# The pool itself is C (src/zu_pool.c) and has been since S16's first half.
# This file is only the part §26.5 puts in R: deciding WHEN a client needs a
# native pool, and re-creating one that did not survive a saveRDS().
#
# The shape follows from two facts that pull in opposite directions:
#
#   * a pool is native, mutable, process-bound state — the opposite of the
#     value semantics §31.1 principle 6 promises for a client;
#   * a client is copied freely (zu_client_update), serialized, and restored
#     into sessions where every pointer it holds is meaningless.
#
# So the client carries the pool's CONFIGURATION as plain R data, which copies
# and serializes correctly, and the live pool hangs off it in an environment
# created on demand. Configuration is the client's identity; the pool is a
# cache keyed by it.

#' Connection pool settings
#'
#' Passed to [zu_client()] as `pool =`. The defaults are §26.2's deliberately
#' conservative ones: a pool that is slightly too eager to discard costs
#' latency, while one that is slightly too eager to reuse corrupts responses.
#'
#' @param max_idle Maximum idle connections kept across all hosts.
#' @param max_per_host Maximum idle connections for one scheme/host/port.
#' @param idle_timeout Seconds an unused connection may sit in the pool.
#' @return A `zu_pool_config`, for `zu_client(pool = )`. `zu_client(pool =
#'   NULL)` disables reuse entirely, which is what one-shot calls want.
#'
#' @section What is never shared:
#' Two requests reuse a connection only if scheme, host, port, proxy identity
#' *including credentials*, and the whole TLS configuration match (§26.1).
#' That is enforced in C, on every acquisition, by comparing the key field by
#' field — so deriving a client with [zu_client_update()] can never cause a
#' request with `verify = FALSE` to travel over a connection established with
#' verification on, even though the derived client shares its parent's pool.
#'
#' @seealso [zu_pool_stats()] to see whether reuse is actually happening.
#' @export
#' @examples
#' api <- zu_client(pool = zu_pool(max_idle = 4, idle_timeout = 10))
#' zu_pool_stats(api)
zu_pool <- function(max_idle = 16L, max_per_host = 4L, idle_timeout = 30) {
  check_count <- function(x, nm) {
    if (!is.numeric(x) || length(x) != 1L || is.na(x) || x < 1)
      stop("`", nm, "` must be a single number of at least 1", call. = FALSE)
    as.integer(x)
  }
  structure(
    list(
      max_idle        = check_count(max_idle, "max_idle"),
      max_per_host    = check_count(max_per_host, "max_per_host"),
      idle_timeout_ms = check_count(idle_timeout * 1000, "idle_timeout")
    ),
    class = "zu_pool_config"
  )
}

#' @export
print.zu_pool_config <- function(x, ...) {
  cat("<zu_pool_config>\n")
  cat("  max_idle:     ", x$max_idle, "\n", sep = "")
  cat("  max_per_host: ", x$max_per_host, "\n", sep = "")
  cat("  idle_timeout: ", x$idle_timeout_ms / 1000, "s\n", sep = "")
  invisible(x)
}

# The live pool for a client, created on demand. NULL when the client has
# pooling switched off, which the C side reads as "open and close your own
# connection" rather than as an error.
#
# §26.5's three cases all land here and all have the same answer — build one:
#
#   1. the client has never made a request;
#   2. the client came back from readRDS(), so its external pointer is a
#      valid SEXP with a NULL address;
#   3. the client's pool settings were changed by zu_client_update() after a
#      pool had already been built, so the live one has the wrong policy.
#
# C_zu_pool_valid answers 1 and 2 together by asking the pointer itself rather
# than by tracking what happened to it, which is the only version of this that
# survives a client being saved in one session and used in another.
client_pool <- function(client) {
  cfg <- client$pool
  if (is.null(cfg)) return(NULL)
  if (!inherits(cfg, "zu_pool_config"))
    stop("`pool` must be zu_pool() or NULL; got ", class(cfg)[[1]],
         call. = FALSE)

  st <- attr(client, "pool_state")
  # A client built before this attribute existed, or one whose attribute was
  # stripped: give it somewhere to put the pool rather than refusing to run.
  if (!is.environment(st)) st <- new.env(parent = emptyenv())

  if (!is.null(st$ptr) && isTRUE(.Call(C_zu_pool_valid, st$ptr)) &&
      identical(st$cfg, cfg))
    return(st$ptr)

  st$ptr <- .Call(C_zu_pool_new, cfg$max_idle, cfg$max_per_host,
                  cfg$idle_timeout_ms)
  st$cfg <- cfg
  st$ptr
}

#' Connection reuse counters
#'
#' The §26.2 counters for a client's pool. `hits` is the number of requests
#' that reused an existing connection; without it, a pooled client and an
#' unpooled one are indistinguishable from R, since both simply return
#' responses.
#'
#' @param client A `zu_client`.
#' @return A named numeric vector, or `NULL` if the client has pooling
#'   disabled or has not made a request yet. `discarded_fork` and
#'   `forks_detected` count connections dropped by the §26.4 PID guard.
#' @seealso [zu_pool()], [zu_pool_reset()]
#' @export
#' @examples
#' zu_pool_stats(zu_client())
zu_pool_stats <- function(client) {
  stopifnot(inherits(client, "zu_client"))
  st <- attr(client, "pool_state")
  if (!is.environment(st) || is.null(st$ptr)) return(NULL)
  .Call(C_zu_pool_stats, st$ptr)
}

#' Close a client's idle connections
#'
#' Drops every pooled connection without affecting the client's configuration;
#' the next request opens a fresh one. Useful when a server has been restarted
#' underneath a long-lived client.
#'
#' @param client A `zu_client`.
#' @return `client`, invisibly.
#' @export
#' @examples
#' api <- zu_client()
#' zu_pool_reset(api)
zu_pool_reset <- function(client) {
  stopifnot(inherits(client, "zu_client"))
  st <- attr(client, "pool_state")
  if (is.environment(st) && !is.null(st$ptr)) .Call(C_zu_pool_clear, st$ptr)
  invisible(client)
}

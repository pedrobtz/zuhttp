# §31.12 — the transport is an explicit client dependency, not a hidden global.
#
# zu_perform() does the merging (§31.9) and then hands a fully resolved request
# to a transport. Substituting the transport is therefore how you test package
# code that makes HTTP calls, rather than mocking .Call or shimming the
# network. Record/replay is S14's; the seam it needs is here.

#' Transports
#'
#' A transport is the object that actually performs a request.
#' `zu_native_transport()` is the real one. `zu_mock_transport()` takes a
#' function of one argument — the resolved request — and returns whatever that
#' function returns, so package tests can exercise their own code without a
#' network, a server, or an internet-dependent CRAN check.
#'
#' @param handler A function of one argument (a `zu_request` with client
#'   configuration already merged in) returning a [zu_response()]; or one or
#'   more [zu_stub()]s, which match on method, URL, headers and body (§37).
#' @param ... Further [zu_stub()]s.
#' @return A transport object, for `zu_client(transport = )`.
#' @name zu_transport
#' @examples
#' fake <- zu_mock_transport(function(req) {
#'   zu_response(status = 200L, body = charToRaw('{"ok":true}'),
#'               headers = c("Content-Type" = "application/json"))
#' })
#' zu_resp_json(zu_get("https://example.com", client = zu_client(transport = fake)))
NULL

#' @rdname zu_transport
#' @export
zu_native_transport <- function() {
  structure(list(), class = c("zu_native_transport", "zu_transport"))
}

#' @rdname zu_transport
#' @export
zu_mock_transport <- function(handler = NULL, ...) {
  stubs <- c(if (inherits(handler, "zu_stub")) list(handler)
             else if (is.list(handler) && !is.function(handler)) handler,
             list(...))
  if (length(stubs)) {
    if (!all(vapply(stubs, inherits, logical(1), "zu_stub")))
      stop("every stub must come from zu_stub()", call. = FALSE)
    # An environment, not a list: `times` has to count across calls, and a
    # transport is copied by value into every request that uses it.
    state <- new.env(parent = emptyenv())
    state$stubs <- stubs
    return(structure(list(state = state),
                     class = c("zu_mock_transport", "zu_transport")))
  }
  if (!is.function(handler))
    stop("zu_mock_transport() needs a handler function or one or more zu_stub()s",
         call. = FALSE)
  structure(list(handler = handler),
            class = c("zu_mock_transport", "zu_transport"))
}

#' Perform a request through a transport
#'
#' The generic exists so that a package can supply its own transport; S3
#' dispatch is the extension point. Implementations receive a resolved request
#' and must return a [zu_response()].
#'
#' @param transport A transport object.
#' @param req A resolved `zu_request`.
#' @return A `zu_response`.
#' @export
zu_transport_perform <- function(transport, req) UseMethod("zu_transport_perform")

#' @export
zu_transport_perform.zu_native_transport <- function(transport, req) {
  p <- req$resolved
  h <- req$headers
  raw <- .Call(C_zu_perform,
               req$method,
               req$url,
               if (length(h)) names(h) else NULL,
               if (length(h)) unname(h) else NULL,
               req$body,
               timeout_ms(p$timeout),
               as.integer(p$redirects),
               isTRUE(p$verify),
               as.numeric(p$max_body),
               p$user_agent,
               isTRUE(p$decode),
               req$pool,
               req$path,
               req$callback,
               p$proxy,
               check_tls(p$tls))
  structure(raw, class = "zu_response")
}

# The deadline crosses into C as an int of milliseconds, so timeout = Inf --
# a reasonable way to write "no timeout" -- must land on the largest value
# that survives the conversion rather than on NA, which C would read as
# INT_MIN and silently replace with the 30-second default.
timeout_ms <- function(seconds) {
  ms <- seconds * 1000
  if (!is.finite(ms) || ms > .Machine$integer.max) .Machine$integer.max
  else as.integer(ms)
}

#' @export
zu_transport_perform.zu_mock_transport <- function(transport, req) {
  if (!is.null(transport$state)) {
    stubs <- transport$state$stubs
    for (i in seq_along(stubs)) {
      if (!stub_matches(stubs[[i]], req)) next
      # Count the match before running the response, so a handler that itself
      # performs a request cannot re-enter this stub past its `times`.
      stubs[[i]]$matched <- stubs[[i]]$matched + 1L
      transport$state$stubs <- stubs
      r <- stubs[[i]]$response
      resp <- if (is.function(r)) r(req) else r
      return(check_mock_response(resp))
    }
    # Naming the request is the whole value of this error: an unmatched mock
    # otherwise surfaces as a confusing NULL several frames later.
    stop("no zu_stub() matched ", req$method, " ", zu_redact_url(req$url),
         "\n  ", length(stubs), " stub(s) were tried", call. = FALSE)
  }
  check_mock_response(transport$handler(req))
}

check_mock_response <- function(resp) {
  if (!inherits(resp, "zu_response"))
    stop("a mock transport must return a zu_response(); got ",
         class(resp)[[1]], call. = FALSE)
  resp
}

#' @export
zu_transport_perform.default <- function(transport, req) {
  stop("`transport` must be a transport object, e.g. zu_native_transport(); got ",
       class(transport)[[1]], call. = FALSE)
}

# Apply §31.9 to produce a request that needs no further context: absolute URL
# with the query attached, every header merged, every policy decided.
resolve_request <- function(req, client) {
  url <- req$url
  if (!is_absolute_url(url)) url <- join_url(client$base_url, url)

  headers <- merge_headers(client$headers, req$headers)
  # The content type implied by the body is a default, so it loses to any
  # header that survived the merge (§31.2: "unless explicitly overridden").
  if (!is.null(req$content_type) &&
      !any(tolower(names(headers)) == "content-type"))
    headers <- c(headers, structure(req$content_type, names = "Content-Type"))

  policy <- lapply(policy_fields(), merge_policy,
                   client = client, req_policy = req$policy)
  names(policy) <- policy_fields()

  if (!isTRUE(policy$verify)) {
    # Not a message that can be switched off: turning verification off is the
    # most consequential thing a caller can do here (§14.1).
    warning("verify = FALSE disables certificate AND hostname checking; ",
            "anyone on the network path can read and alter this request.",
            call. = FALSE)
  }
  if (!is.numeric(policy$timeout) || length(policy$timeout) != 1L ||
      is.na(policy$timeout) || policy$timeout <= 0)
    stop("`timeout` must be a positive number of seconds", call. = FALSE)
  if (!is.numeric(policy$redirects) || length(policy$redirects) != 1L ||
      is.na(policy$redirects) || policy$redirects < 0)
    stop("`redirects` must be 0 or more", call. = FALSE)
  # Not merely a range check: the C side reads max_body == 0 as "use the
  # default", so a caller writing max_body = 0 to mean "refuse any body"
  # would silently get 16 MB. Refuse the value rather than honour the
  # opposite of what it says.
  if (!is.numeric(policy$max_body) || length(policy$max_body) != 1L ||
      is.na(policy$max_body) || policy$max_body < 1)
    stop("`max_body` must be at least 1 byte", call. = FALSE)

  req$url      <- url_with_query(url, merge_query(client$query, req$query))
  req$query    <- NULL          # folded into the URL; one representation
  req$headers  <- headers
  req$resolved <- policy
  # §26.5: resolved here, not in the transport, because this is the last point
  # that can see the client. A transport receives a request that needs no
  # further context — that is the whole contract (§31.12) — so the pool has to
  # travel with it rather than be looked up later.
  req$pool     <- client_pool(client)
  req
}

#' Perform a request
#'
#' The boundary between building a request and touching the network
#' (§31.1 principle 2). Client configuration is merged into the request here,
#' by the rules in [zu_client()] and §31.9.
#'
#' @param req A `zu_request` from [zu_request()].
#' @param client A `zu_client`. Always named, never positional (§31.3).
#' @return A `zu_response`. By default a 4xx or 5xx status raises a condition
#'   instead; see [zu_resp_check()] and `check = FALSE`.
#' @export
#' @examples
#' fake <- zu_mock_transport(function(req) zu_response(status = 204L))
#' zu_perform(zu_request("DELETE", "https://example.com/x"),
#'            client = zu_client(transport = fake))
zu_perform <- function(req, client = zu_default_client()) {
  req <- check_req(req)
  if (!inherits(client, "zu_client"))
    stop("`client` must be a zu_client(); got ", class(client)[[1]],
         call. = FALSE)
  # §27.4. A streaming callback runs arbitrary R code, which may call zu_get()
  # again. Re-entrancy is permitted — but not on the client whose connection
  # is currently being read, which would deadlock on a pool slot or interleave
  # writes onto a live connection. The flag lives in the client's pool_state
  # environment because that is already the one reference cell a client
  # carries, and it is set only while the user's callback is on the stack, so
  # ordinary nesting through middleware is unaffected.
  st <- attr(client, "pool_state")
  if (is.environment(st) && isTRUE(st$in_callback))
    stop("a streaming callback cannot make a request on the same client\n",
         "  it would reuse the connection it is currently reading from\n",
         "  use a different client, or collect the data and request afterwards",
         call. = FALSE)

  r <- resolve_request(req, client)
  if (is.function(r$callback)) r$callback <- guard_callback(r$callback, st)
  hooks <- client$hooks %||% list()

  t0 <- proc.time()[["elapsed"]]
  # §24.3: `total` is a wall-clock budget for the WHOLE call — every redirect
  # hop and every retry attempt, never reset between them. It is the only
  # reading under which zu_get(url, timeout = 30) actually returns in 30s.
  deadline_at <- t0 + r$resolved$timeout

  # §31.13: middleware wraps request execution; the retry loop is inside it,
  # so a user's middleware sees one logical request and not each attempt.
  terminal <- function(rq) attempt_with_retries(rq, client, hooks, deadline_at)
  resp <- compose_middleware(check_middleware(client$middleware), terminal)(r)
  elapsed <- proc.time()[["elapsed"]] - t0

  if (!inherits(resp, "zu_response"))
    stop("middleware must return a zu_response(); got ", class(resp)[[1]],
         call. = FALSE)

  # Fields the transport should not have to fill in, and that a mock would
  # otherwise have to fake to keep the accessors honest.
  resp$method  <- r$method
  if (is.null(resp$url)) resp$url <- zu_redact_url(r$url)
  resp$timings <- c(total = elapsed)
  resp$request <- r
  if (is.null(resp$redirects)) resp$redirects <- 0L

  fire_hook(hooks, "after_response",
            list(request = r, response = resp, attempt = resp$attempts %||% 1L))
  if (isTRUE(r$resolved$check)) zu_resp_check(resp)
  resp
}

# §33.1. All three preconditions must hold, and each defaults to "no".
#
# Admissibility is decided ONCE, before the first attempt, and not re-derived
# per failure: whether a request may be replayed is a property of the request,
# and re-asking it inside the loop invites a code path where it answers
# differently on attempt three than on attempt one.
attempt_with_retries <- function(r, client, hooks, deadline_at) {
  policy <- r$resolved$retry %||% zu_retry(attempts = 1L)
  may_replay <- policy$attempts > 1L && zu_req_replay_safe(r)

  # §33.1's third condition, and §28.2's promise to refuse rather than
  # truncate. Raised eagerly: a caller who asked for retries on a body that
  # cannot be replayed has a bug, and discovering it only on the first
  # failure makes it intermittent.
  if (may_replay && !zu_body_rewindable(r))
    zu_stop("zu_body_not_replayable",
            "this request's body cannot be replayed, so it cannot be retried",
            url = r$url)

  attempt <- 1L
  repeat {
    fire_hook(hooks, "before_request", list(request = r, attempt = attempt))
    resp <- NULL; cnd <- NULL
    resp <- tryCatch(zu_transport_perform(client$transport, r),
                     zu_error = function(e) { cnd <<- e; NULL })

    if (!may_replay || attempt >= policy$attempts) break
    v <- retry_verdict(resp, cnd, policy)
    if (!isTRUE(v$retry)) break

    delay <- backoff_delay(policy, attempt, v$after)
    # §33.3: check the budget BEFORE sleeping and fail now rather than sleep
    # past the deadline. Without this, `timeout = 30` with three retries is a
    # promise the client cannot keep.
    left <- deadline_at - proc.time()[["elapsed"]]
    if (left <= 0 || delay >= left) break

    fire_hook(hooks, "before_retry",
              list(request = r, attempt = attempt, delay = delay, why = v$why))
    retry_sleep(delay, deadline_at)
    attempt <- attempt + 1L
    fire_hook(hooks, "after_retry", list(request = r, attempt = attempt))
  }

  # A condition that survived the loop is the caller's to see, unchanged.
  if (is.null(resp)) stop(cnd)
  resp$attempts <- attempt
  resp
}

# §27.4: mark the client as "inside a callback" for exactly as long as the
# user's function is on the stack, and no longer. on.exit() rather than a
# plain assignment after the call, so an error thrown by the callback — which
# §27.3 re-signals — still clears the flag and does not leave the client
# permanently unusable.
guard_callback <- function(f, state) {
  # force() is load-bearing, not defensive. The caller writes
  #   r$callback <- guard_callback(r$callback, st)
  # so `f` is a promise for `r$callback` in the caller's frame — and that
  # binding is replaced by THIS wrapper before the promise is ever forced.
  # Without force(), calling f(chunk) evaluates the promise, gets the wrapper
  # back, and recurses until R's expression depth runs out. The symptom is an
  # "evaluation nested too deeply" from inside a C callback, which points
  # nowhere near the actual cause.
  force(f)
  if (!is.environment(state)) return(f)
  function(chunk) {
    state$in_callback <- TRUE
    on.exit(state$in_callback <- FALSE, add = TRUE)
    f(chunk)
  }
}

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
#'   configuration already merged in) returning a [zu_response()].
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
zu_mock_transport <- function(handler) {
  stopifnot(is.function(handler))
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
               isTRUE(p$decode))
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
  resp <- transport$handler(req)
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
  r <- resolve_request(req, client)

  t0 <- proc.time()[["elapsed"]]
  resp <- zu_transport_perform(client$transport, r)
  elapsed <- proc.time()[["elapsed"]] - t0

  # Fields the transport should not have to fill in, and that a mock would
  # otherwise have to fake to keep the accessors honest.
  resp$method  <- r$method
  if (is.null(resp$url)) resp$url <- zu_redact_url(r$url)
  resp$timings <- c(total = elapsed)
  resp$request <- r
  if (is.null(resp$redirects)) resp$redirects <- 0L

  if (isTRUE(r$resolved$check)) zu_resp_check(resp)
  resp
}

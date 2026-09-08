# §31.3 reusable clients, and §31.9's merge rules.
#
# The merge rules are the part of this file worth reading. §31.9 states them as
# two kinds of option that behave differently, plus an eraser:
#
#   collection-like   headers, query     client and request values COMBINE
#   scalar/policy     timeout, verify,   the request value REPLACES the
#                     redirects, ...     client's
#   NA   in a header  removes an inherited field
#   NULL for a policy resets to the PACKAGE default, not to the client's value
#
# The last rule is the surprising one and is deliberate: `timeout = NULL` means
# "forget what the client said and use the package default", because otherwise
# a client default is impossible to escape at the request level.
#
# Making it work needs three states, not two: not supplied, supplied as NULL,
# supplied as a value. R gives us the first through missing(), and the second
# is carried as the .zu_reset sentinel because a list cannot hold a NULL.

.zu_reset <- structure(list(), class = "zu_reset")

# The package defaults. One definition; both `NULL` resets and clients with
# nothing set land here.
zu_defaults <- function() {
  list(
    timeout    = 30,
    redirects  = 1L,
    verify     = TRUE,
    max_body   = 16 * 1024^2,
    user_agent = NULL,
    check      = TRUE,
    decode     = TRUE,
    # Retrying is off by default (§33): attempts counts the FIRST try, so 1
    # means "no retrying". A client that silently replayed requests would be
    # the data-integrity bug §33 opens by warning about.
    retry      = zu_retry(attempts = 1L),
    # §20.1: NULL is "consult the environment", which is what an unconfigured
    # client must do. Disabling is FALSE — see D-48 and the note in
    # zu_client()'s docs for why it cannot be NULL.
    proxy      = NULL
  )
}

policy_fields <- function() names(zu_defaults())

# Read the policy arguments the *caller's* frame actually received. missing()
# has to be evaluated in that frame, which is why this takes an environment
# rather than the values: by the time a value has been passed on, the
# difference between "not supplied" and "supplied as NULL" is gone, and that
# difference is exactly what §31.9 hangs the NULL rule on.
collect_policy <- function(env = parent.frame()) {
  out <- list()
  for (f in policy_fields()) {
    if (!exists(f, envir = env, inherits = FALSE)) next
    if (isTRUE(eval(call("missing", as.name(f)), env))) next
    v <- get(f, envir = env)
    out[[f]] <- if (is.null(v)) .zu_reset else v
  }
  out
}

#' Create a reusable client
#'
#' A client carries what many requests share: a base URL, default headers and
#' query parameters, policy defaults, and the connection pool.
#' It is never the first argument of a request function — see below.
#'
#' @param base_url Optional base URL, so that `zu_get("/users", client = api)`
#'   works. Joining is textual, not RFC 3986 resolution: see Details.
#' @param headers Named character vector of default headers.
#' @param query Named list of default query parameters.
#' @param timeout Total seconds for a request, redirects included.
#' @param redirects Maximum redirects to follow. `0` returns the 3xx itself.
#' @param verify Verify the certificate and hostname. Leave this `TRUE`.
#' @param max_body Maximum decoded body size in bytes.
#' @param user_agent Default `User-Agent`.
#' @param check Raise a condition for 4xx and 5xx responses (§31.14). `FALSE`
#'   returns the response whatever its status.
#' @param decode Decompress the body transparently (§21.2).
#' @param transport The object that actually performs requests. Defaults to
#'   [zu_native_transport()]; [zu_mock_transport()] replaces the network in
#'   tests.
#' @param pool Connection reuse settings from [zu_pool()], or `NULL` to open a
#'   fresh connection for every request.
#' @param retry A [zu_retry()] policy. The default retries nothing.
#' @param proxy Proxy URL, e.g. `"http://proxy:3128"`. Leave unset to honour
#'   the environment (§20.1); pass `FALSE` to force a direct connection.
#'   **Not `NULL`** — under the §31.9 merge rules `NULL` means "reset to the
#'   package default", which for a proxy is "consult the environment". `FALSE`
#'   is the only spelling that can mean "definitely do not proxy" without
#'   making this one argument an exception to a rule every other policy
#'   argument follows.
#' @param middleware A function of `(req, next_fn)`, or a list of them,
#'   wrapping request execution (§31.13). The first is outermost.
#' @param hooks Lifecycle observers from [zu_hooks()].
#' @return A `zu_client` object.
#'
#' @details
#' `base_url` is **joined** to a request path, not resolved against it: a
#' client with `base_url = "https://api.example.com/v1"` and a request path of
#' `"/users"` produces `https://api.example.com/v1/users`. RFC 3986 resolution
#' would give `https://api.example.com/users` — the `/v1` silently dropped —
#' which is the single most common surprise in libraries that resolve here.
#' An absolute request URL ignores `base_url` entirely.
#'
#' @section The client is never the first argument:
#' `zu_get(url, ..., client = api)`, never `zu_get(api, url)`. Overloading
#' argument one by type breaks autocomplete, makes dispatch murky, and turns a
#' misplaced argument into a confusing error instead of a clear one (§31.3).
#' For client-first phrasing there are thin wrappers: `api |>
#' zu_client_get("/users")`.
#'
#' @seealso [zu_client_update()] to derive a client without mutating it.
#' @export
#' @examples
#' api <- zu_client(
#'   base_url = "https://api.example.com",
#'   headers  = c(Accept = "application/json")
#' )
#' api
zu_client <- function(base_url = NULL, headers = NULL, query = NULL,
                      timeout = NULL, redirects = NULL, verify = NULL,
                      max_body = NULL, user_agent = NULL, check = NULL,
                      decode = NULL, transport = zu_native_transport(),
                      pool = zu_pool(), retry = NULL, middleware = NULL,
                      hooks = NULL, proxy = NULL) {
  structure(
    list(
      base_url   = base_url,
      headers    = as_header_vec(headers),
      query      = as_query_list(query),
      timeout    = timeout,
      redirects  = redirects,
      verify     = verify,
      max_body   = max_body,
      user_agent = user_agent,
      check      = check,
      decode     = decode,
      retry      = retry,
      proxy      = proxy,
      transport  = transport,
      pool       = pool,
      # §31.13: NOT policy. Middleware and hooks are user-supplied behaviour
      # and observability; they do not take part in the §31.9 three-state
      # merge, because "reset to the package default" is meaningless for a
      # list of the caller's own functions.
      middleware = check_middleware(middleware),
      hooks      = hooks %||% list()
    ),
    class = "zu_client",
    # §26.5. The live pool is native state, so it does NOT belong in the list
    # the user prints and copies — that list is the client's value, and it has
    # to survive serialization intact. The environment is a cache hung beside
    # it, created empty and filled on the first request. Copies made by
    # zu_client_update() share it, which is safe because the §26.1 key
    # discriminates on everything that must not be shared.
    pool_state = new.env(parent = emptyenv())
  )
}

#' Derive a client from another
#'
#' Returns a copy with the named fields changed. Clients are values: this never
#' mutates `client`, so a derived client cannot surprise code still holding the
#' original (§31.10).
#'
#' @param client A `zu_client`.
#' @param ... Fields to change, named as in [zu_client()].
#' @return A new `zu_client`.
#' @export
#' @examples
#' api <- zu_client(base_url = "https://api.example.com")
#' admin <- zu_client_update(api, headers = c(Authorization = "Bearer xyz"))
#' identical(api$headers, NULL)   # unchanged
zu_client_update <- function(client, ...) {
  stopifnot(inherits(client, "zu_client"))
  changes <- list(...)
  if (length(changes) && (is.null(names(changes)) || any(!nzchar(names(changes)))))
    stop("all arguments to zu_client_update() must be named", call. = FALSE)
  bad <- setdiff(names(changes), names(client))
  if (length(bad))
    stop("not a client setting: ", paste(bad, collapse = ", "),
         "\n  settings are: ", paste(names(client), collapse = ", "),
         call. = FALSE)
  # Derived headers merge with the parent's, which is what makes the
  # base -> authenticated -> admin chain in §31.10 work.
  if (!is.null(changes$headers))
    changes$headers <- merge_headers(client$headers, as_header_vec(changes$headers))
  if (!is.null(changes$query))
    changes$query <- merge_query(client$query, as_query_list(changes$query))
  for (nm in names(changes)) client[[nm]] <- changes[[nm]]
  client
}

as_header_vec <- function(h) {
  if (is.null(h) || !length(h)) return(NULL)
  if (is.list(h)) h <- unlist(h)
  if (is.null(names(h)) || any(is.na(names(h))) || any(!nzchar(names(h))))
    stop("headers must be a named vector, e.g. c(Accept = \"application/json\")",
         call. = FALSE)
  # NA is meaningful (it erases), so it survives as.character() here.
  structure(as.character(h), names = names(h))
}

as_query_list <- function(q) {
  if (is.null(q) || !length(q)) return(NULL)
  q <- as.list(q)
  if (is.null(names(q)) || any(!nzchar(names(q))))
    stop("query parameters must be named, e.g. list(q = \"HTTP\")", call. = FALSE)
  # NULL and NA both mean "erase" (§31.9), and they have to mean the same
  # thing here: list(a = NULL) is a perfectly ordinary way to write it, but a
  # NULL cannot survive being carried through a list, so it becomes NA now.
  for (nm in names(q)) if (is.null(q[[nm]])) q[[nm]] <- NA
  q
}

# §31.9 collection-like. Client headers first, then request headers, with a
# same-name request header replacing rather than duplicating, and NA erasing.
merge_headers <- function(client_h, req_h) {
  out <- if (is.null(client_h)) character() else client_h
  for (nm in names(req_h)) {
    # Case-insensitive, because HTTP field names are (§18.3). Without this a
    # request's c(Accept=) would sit alongside a client's c(accept=) and both
    # would go on the wire.
    hit <- which(tolower(names(out)) == tolower(nm))
    if (length(hit)) out <- out[-hit]
    if (!is.na(req_h[[nm]])) out[[nm]] <- req_h[[nm]]
  }
  out <- out[!is.na(out)]
  if (!length(out)) NULL else out
}

merge_query <- function(client_q, req_q) {
  out <- if (is.null(client_q)) list() else client_q
  for (nm in names(req_q)) {
    v <- req_q[[nm]]
    # NA erases an inherited parameter, as it does for a header. A NULL in the
    # request list has already removed itself by R's own list semantics.
    if (length(v) == 1L && is.na(v)) out[[nm]] <- NULL else out[[nm]] <- v
  }
  if (!length(out)) NULL else out
}

# §31.9 scalar/policy, with the three states described at the top of the file.
merge_policy <- function(field, client, req_policy) {
  if (field %in% names(req_policy)) {
    v <- req_policy[[field]]
    if (inherits(v, "zu_reset")) return(zu_defaults()[[field]])
    return(v)
  }
  if (!is.null(client) && !is.null(client[[field]])) return(client[[field]])
  zu_defaults()[[field]]
}

# --- the default client (§31.3) --------------------------------------------
the_default <- new.env(parent = emptyenv())

#' The package-managed default client
#'
#' Used by any request that does not name a client. It is re-created in a
#' forked child rather than inherited, so a client made in the parent never
#' hands its connections to `parallel::mclapply()` workers (§26.4).
#'
#' @return A `zu_client`.
#' @seealso [zu_set_default_client()]
#' @export
#' @examples
#' zu_default_client()
zu_default_client <- function() {
  pid <- Sys.getpid()
  if (is.null(the_default$client) || !identical(the_default$pid, pid)) {
    the_default$client <- zu_client()
    the_default$pid    <- pid
  }
  the_default$client
}

#' Replace the default client
#'
#' @param client A `zu_client`, or `NULL` to restore the package default.
#' @return The previous default, invisibly.
#' @export
#' @examples
#' old <- zu_set_default_client(zu_client(timeout = 5))
#' zu_set_default_client(old)
zu_set_default_client <- function(client) {
  old <- zu_default_client()
  if (!is.null(client)) stopifnot(inherits(client, "zu_client"))
  the_default$client <- client
  the_default$pid    <- Sys.getpid()
  invisible(old)
}

#' @export
print.zu_client <- function(x, ...) {
  cat("<zu_client>\n")
  if (!is.null(x$base_url)) cat("  base_url:  ", x$base_url, "\n", sep = "")
  # §42.2: printing is an egress, so values are redacted for display.
  h <- zu_redact_headers_for_display(x$headers)
  for (i in seq_along(h)) cat("  ", names(h)[i], ": ", h[[i]], "\n", sep = "")
  if (length(x$query))
    cat("  query:     ", format_query(x$query), "\n", sep = "")
  d <- zu_defaults()
  for (f in policy_fields()) {
    v <- if (is.null(x[[f]])) d[[f]] else x[[f]]
    if (is.null(v)) next
    cat("  ", f, ": ", format(v), if (is.null(x[[f]])) "  (default)" else "",
        "\n", sep = "")
  }
  if (!inherits(x$transport, "zu_native_transport"))
    cat("  transport: ", class(x$transport)[[1]], "\n", sep = "")
  invisible(x)
}

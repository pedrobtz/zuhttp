# §31.2 — API level 1. Syntax, not a second implementation: every helper here
# builds the same zu_request as §31.4's pipeline and hands it to zu_perform()
# (§31.1 principle 3).
#
# Note the shape of every signature: the URL is argument one, and `client` is
# a named argument at the end. Never zu_get(client, url) — §31.3 rejects
# positional polymorphism outright.

one_shot <- function(method, url, query, headers, policy, client,
                     body = NULL, json = NULL, form = NULL, file = NULL,
                     path = NULL, callback = NULL) {
  given <- c(body = !is.null(body), json = !is.null(json),
             form = !is.null(form), file = !is.null(file))
  if (sum(given) > 1L)
    stop("`", paste(names(given)[given], collapse = "`, `"),
         "` are mutually exclusive: a request has one body", call. = FALSE)

  req <- zu_request(method, url)
  if (!is.null(query))   req$query   <- as_query_list(query)
  if (!is.null(headers)) req$headers <- as_header_vec(headers)
  if (!is.null(json))    req <- zu_body_json(req, json)
  if (!is.null(form))    req <- zu_body_form(req, form)
  if (!is.null(body))    req <- zu_body_raw(req, body)
  if (!is.null(file))    req <- zu_body_file(req, file)
  req$policy <- policy
  # §27: not a policy. Where a response goes is a property of this call, not
  # something a client inherits or the §31.9 three-state merge applies to.
  if (!is.null(path)) req <- zu_req_path(req, path)
  if (!is.null(callback)) req <- zu_req_callback(req, callback)
  zu_perform(req, client = client)
}

#' Perform a request in one call
#'
#' The short form. `zu_get(url)` is the whole API for the common case; the
#' arguments below are the same options [zu_client()] takes, applied to this
#' request only.
#'
#' Passing `NULL` for a policy argument resets it to the *package* default
#' rather than to the client's value — that is the documented way to escape a
#' client default (§31.9). Omitting it inherits the client's.
#'
#' @param url An absolute URL, or a path joined to the client's `base_url`.
#' @param query Named list of query parameters. Merged with the client's.
#' @param headers Named character vector. Merged with the client's; `NA`
#'   removes an inherited header.
#' @param body Raw vector or string, sent as-is.
#' @param json An object to serialise as JSON. Sets `Content-Type:
#'   application/json` unless you set that header yourself.
#' @param form A named list, sent as `application/x-www-form-urlencoded`.
#' @param file A path whose contents become the body.
#' @param timeout Total seconds, redirects included.
#' @param redirects Maximum redirects to follow.
#' @param verify Verify the certificate and hostname. Leave this `TRUE`.
#' @param max_body Maximum decoded body size in bytes.
#' @param user_agent `User-Agent` to send.
#' @param retry A [zu_retry()] policy for this request. Overrides the
#'   client's; `NULL` inherits it (§31.9).
#' @param callback A function of one argument called with each decoded chunk
#'   as it arrives (§27). Returning `FALSE` stops the transfer. See
#'   [zu_req_callback()] for what happens when it raises an error.
#' @param path Write the response body to this file instead of holding it in
#'   memory (§27). The download is written beside the destination and renamed
#'   on success, so a failed or interrupted transfer never leaves a truncated
#'   file at `path`. Note the asymmetry with `file`, which is a request *body*
#'   source (§31.6): `path` is where the response goes, `file` is where a
#'   request body comes from.
#' @param check Raise a condition for 4xx and 5xx (§31.14). `FALSE` returns the
#'   response whatever its status.
#' @param decode Decompress transparently. `FALSE` returns the wire bytes and
#'   asks the server not to encode (§21.2).
#' @param client A `zu_client`. Always named.
#' @return A `zu_response`.
#' @seealso [zu_request()] and [zu_perform()] to build a request without
#'   performing it.
#' @name zu_methods
#' @examples
#' \dontrun{
#' zu_get("https://api.example.com/search", query = list(q = "HTTP", limit = 20))
#' zu_post("https://api.example.com/users", json = list(name = "Alice"))
#' }
NULL

#' @rdname zu_methods
#' @export
zu_get <- function(url, query = NULL, headers = NULL, timeout = NULL,
                   redirects = NULL, verify = NULL, max_body = NULL,
                   user_agent = NULL, check = NULL, decode = NULL,
                   retry = NULL, path = NULL, callback = NULL,
                   client = zu_default_client()) {
  one_shot("GET", url, query, headers, collect_policy(environment()), client,
           path = path, callback = callback)
}

#' @rdname zu_methods
#' @export
zu_head <- function(url, query = NULL, headers = NULL, timeout = NULL,
                    redirects = NULL, verify = NULL, max_body = NULL,
                    user_agent = NULL, check = NULL, decode = NULL,
                    retry = NULL, path = NULL, callback = NULL,
                   client = zu_default_client()) {
  one_shot("HEAD", url, query, headers, collect_policy(environment()), client,
           path = path, callback = callback)
}

#' @rdname zu_methods
#' @export
zu_post <- function(url, query = NULL, headers = NULL, body = NULL, json = NULL,
                    form = NULL, file = NULL, timeout = NULL, redirects = NULL,
                    verify = NULL, max_body = NULL, user_agent = NULL,
                    check = NULL, decode = NULL, retry = NULL, path = NULL, callback = NULL,
                   client = zu_default_client()) {
  one_shot("POST", url, query, headers, collect_policy(environment()), client,
           body = body, json = json, form = form, file = file, path = path, callback = callback)
}

#' @rdname zu_methods
#' @export
zu_put <- function(url, query = NULL, headers = NULL, body = NULL, json = NULL,
                   form = NULL, file = NULL, timeout = NULL, redirects = NULL,
                   verify = NULL, max_body = NULL, user_agent = NULL,
                   check = NULL, decode = NULL, retry = NULL, path = NULL, callback = NULL,
                   client = zu_default_client()) {
  one_shot("PUT", url, query, headers, collect_policy(environment()), client,
           body = body, json = json, form = form, file = file, path = path, callback = callback)
}

#' @rdname zu_methods
#' @export
zu_patch <- function(url, query = NULL, headers = NULL, body = NULL, json = NULL,
                     form = NULL, file = NULL, timeout = NULL, redirects = NULL,
                     verify = NULL, max_body = NULL, user_agent = NULL,
                     check = NULL, decode = NULL, retry = NULL, path = NULL, callback = NULL,
                   client = zu_default_client()) {
  one_shot("PATCH", url, query, headers, collect_policy(environment()), client,
           body = body, json = json, form = form, file = file, path = path, callback = callback)
}

#' @rdname zu_methods
#' @export
zu_delete <- function(url, query = NULL, headers = NULL, body = NULL,
                      json = NULL, form = NULL, file = NULL, timeout = NULL,
                      redirects = NULL, verify = NULL, max_body = NULL,
                      user_agent = NULL, check = NULL, decode = NULL,
                      retry = NULL, path = NULL, callback = NULL,
                   client = zu_default_client()) {
  one_shot("DELETE", url, query, headers, collect_policy(environment()), client,
           body = body, json = json, form = form, file = file, path = path, callback = callback)
}

#' Client-first wrappers
#'
#' A thin layer for readers who prefer `api |> zu_client_get("/users")`. These
#' are wrappers, not overloads: [zu_get()] and friends never accept a client
#' as their first argument (§31.3).
#'
#' @param client A `zu_client`.
#' @param url A URL or path.
#' @param ... Passed to [zu_get()] and friends.
#' @return A `zu_response`.
#' @name zu_client_methods
#' @examples
#' fake <- zu_mock_transport(function(req) zu_response(200L, body = "ok"))
#' api <- zu_client(base_url = "https://api.example.com", transport = fake)
#' zu_resp_text(zu_client_get(api, "/users"))
NULL

#' @rdname zu_client_methods
#' @export
zu_client_get <- function(client, url, ...) zu_get(url, ..., client = client)

#' @rdname zu_client_methods
#' @export
zu_client_head <- function(client, url, ...) zu_head(url, ..., client = client)

#' @rdname zu_client_methods
#' @export
zu_client_post <- function(client, url, ...) zu_post(url, ..., client = client)

#' @rdname zu_client_methods
#' @export
zu_client_put <- function(client, url, ...) zu_put(url, ..., client = client)

#' @rdname zu_client_methods
#' @export
zu_client_patch <- function(client, url, ...) zu_patch(url, ..., client = client)

#' @rdname zu_client_methods
#' @export
zu_client_delete <- function(client, url, ...) zu_delete(url, ..., client = client)

#' Which TLS backend was this build linked against?
#'
#' @return A short backend identifier, e.g. `"openssl"`, `"schannel"`,
#'   `"sectransport"`.
#' @export
#' @examples
#' zu_tls_backend()
zu_tls_backend <- function() .Call(C_zu_tls_backend)

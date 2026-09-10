# §31.4 — explicit request composition.
#
# A request is a value: building one performs no I/O, and every transformer
# returns a new request rather than modifying its argument. That separation is
# the point (§31.1 principle 2) — a package author can construct, inspect and
# hand around a request, and the network is touched only at zu_perform().
#
# §31.1 principle 3: the one-shot helpers in methods.R lower to exactly this
# object. There is one request model, not two.

#' Build a request without performing it
#'
#' Method and URL are request identity, so both are given here rather than
#' configured later (§31.5). The result is an inert value; [zu_perform()] is
#' the only thing that touches the network.
#'
#' @param method HTTP method. Any token is allowed — `"PROPFIND"` works —
#'   and it is upper-cased.
#' @param url An absolute URL, or a path to be joined to a client's `base_url`
#'   at perform time.
#' @return A `zu_request`.
#' @seealso [zu_headers()], [zu_query()], [zu_body_json()], [zu_perform()]
#' @export
#' @examples
#' req <- zu_request("POST", "https://api.example.com/users")
#' req <- zu_body_json(req, list(name = "Alice"))
#' req
zu_request <- function(method, url) {
  stopifnot(is.character(method), length(method) == 1L, !is.na(method))
  stopifnot(is.character(url), length(url) == 1L, !is.na(url))
  if (!grepl("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$", method))
    stop("`", method, "` is not a valid HTTP method token", call. = FALSE)
  structure(
    list(
      method       = toupper(method),
      url          = url,
      query        = NULL,
      headers      = NULL,
      body         = NULL,
      body_kind    = NULL,   # for printing: "JSON", "form", "raw", "file"
      content_type = NULL,   # implied by the body; a header still wins
      policy       = list()
    ),
    class = "zu_request"
  )
}

#' Stream the response body to a file
#'
#' The composable equivalent of `zu_get(url, path = )`. The body is written to
#' a temporary file in the same directory as `path` and renamed once it has
#' arrived whole (§27.1), so a failed, cancelled or interrupted transfer never
#' leaves a truncated file where the caller will find it and trust it.
#'
#' The same directory, rather than `tempdir()`: `rename()` is atomic only
#' within a filesystem, and a temporary directory on another mount turns the
#' commit into a copy that can itself fail halfway.
#'
#' An existing file at `path` is **replaced**, and only at that final step —
#' so a download that fails leaves whatever was already there untouched.
#' Setting both this and [zu_req_callback()] is an error, raised when the
#' request is performed: a response body has one destination.
#'
#' @param req A `zu_request`.
#' @param path Destination path.
#' @return The request, modified.
#' @seealso [zu_body_file()], which is the opposite direction — a request body
#'   read *from* a file.
#' @export
#' @examples
#' req <- zu_req_path(zu_request("GET", "https://x.test/big.bin"),
#'                    file.path(tempdir(), "big.bin"))
zu_req_path <- function(req, path) {
  req <- check_req(req)
  if (!is.character(path) || length(path) != 1L || is.na(path) || !nzchar(path))
    stop("`path` must be a single non-empty file path", call. = FALSE)
  req$path <- path.expand(path)
  req
}

#' Stream the response body to a callback
#'
#' `f` is called with each decoded chunk as a raw vector, as it arrives.
#' Returning `FALSE` stops the transfer cleanly (§27.2); the connection is
#' then not reused, because its framing position is no longer known (§26.3).
#'
#' @section If your callback raises an error:
#' You get *your* error, not a transport error wrapping it (§27.3). The
#' callback runs inside `R_tryCatch()`, the native read loop unwinds normally
#' so the socket and decompressor are released, and only then is the original
#' condition re-signalled. That ordering is the whole point: a longjmp
#' straight out of the read loop would leak the connection.
#'
#' @section What you may not do inside it:
#' Issue another request on the **same** client (§27.4). That would deadlock
#' on a pool slot or interleave writes onto the connection currently being
#' read, so it raises an error naming the problem instead. A request through a
#' *different* client is unrestricted.
#'
#' @param req A `zu_request`.
#' @param f A function of one argument (a raw vector). Return `FALSE` to stop.
#' @return The request, modified.
#' @seealso [zu_req_path()] to stream to a file instead.
#' @export
#' @examples
#' total <- 0
#' req <- zu_req_callback(zu_request("GET", "https://x.test/big"),
#'                        function(chunk) total <<- total + length(chunk))
zu_req_callback <- function(req, f) {
  req <- check_req(req)
  if (!is.function(f))
    stop("`callback` must be a function of one argument (a raw vector)",
         call. = FALSE)
  req$callback <- f
  req
}

#' Record a §35.3 event trace for this request
#'
#' @param req A `zu_request`.
#' @param trace `TRUE` to collect the trace; `FALSE` (the default) to not.
#' @return The request, modified.
#' @seealso [zu_resp_trace()] to read it back.
#' @export
#' @examples
#' zu_req_trace(zu_request("GET", "https://example.com"))
zu_req_trace <- function(req, trace = TRUE) {
  req <- check_req(req)
  req$trace <- isTRUE(trace)
  req
}

check_req <- function(req) {
  if (!inherits(req, "zu_request"))
    stop("expected a request from zu_request(); got ", class(req)[[1]],
         call. = FALSE)
  req
}

#' Add query parameters
#'
#' @param req A `zu_request`.
#' @param ... Named parameters. A value of length > 1 repeats the key
#'   (`id = c(1, 2)` becomes `id=1&id=2`); `NULL` or `NA` removes a parameter
#'   inherited from the client (§31.9).
#' @return A `zu_request`.
#' @export
#' @examples
#' zu_query(zu_request("GET", "https://example.com"), q = "HTTP", limit = 20)
zu_query <- function(req, ...) {
  req <- check_req(req)
  q <- as_query_list(list(...))
  out <- if (is.null(req$query)) list() else req$query
  # Not merge_query(): an NA here is an instruction to erase a parameter the
  # *client* supplies, and it has to survive on the request until that merge
  # happens at perform time. Applying it now would erase nothing.
  for (nm in names(q)) out[[nm]] <- q[[nm]]
  req$query <- if (length(out)) out else NULL
  req
}

#' Add headers
#'
#' @param req A `zu_request`.
#' @param ... Named header values. A value of `NA` removes a header inherited
#'   from the client (§31.9); a same-name value replaces it, case-insensitively.
#' @return A `zu_request`.
#' @export
#' @examples
#' zu_headers(zu_request("GET", "https://example.com"), Accept = "text/plain")
zu_headers <- function(req, ...) {
  req <- check_req(req)
  h <- list(...)
  if (length(h) == 1L && is.null(names(h))) h <- h[[1]]   # a bare named vector
  h <- as_header_vec(h)
  out <- if (is.null(req$headers)) character() else req$headers
  # As in zu_query(): an NA is carried, not applied, because what it erases is
  # a client header that this request has not met yet.
  for (nm in names(h)) {
    hit <- which(tolower(names(out)) == tolower(nm))
    if (length(hit)) out <- out[-hit]
    out[[nm]] <- h[[nm]]
  }
  req$headers <- if (length(out)) out else NULL
  req
}

#' Set the request body
#'
#' `zu_body_json()` serialises with the JSON backend (see
#' [zu_set_json_backend()]) and sets `Content-Type: application/json`.
#' `zu_body_form()` URL-encodes and sets
#' `application/x-www-form-urlencoded`. `zu_body_raw()` sends bytes as given.
#' `zu_body_file()` sends a file's contents.
#'
#' The implied content type is only a default: a header set on the request or
#' the client always wins (§31.2).
#'
#' @param req A `zu_request`.
#' @param x For `zu_body_json()`, any object the backend can serialise; for
#'   `zu_body_form()`, a named list; for `zu_body_raw()`, a raw vector or a
#'   string.
#' @param auto_unbox Passed to the JSON backend. `TRUE` sends `list(a = 1)` as
#'   `{"a":1}` rather than `{"a":[1]}`, which is what R users nearly always
#'   mean.
#' @param type Content type to declare.
#' @param path A file path. The file is read into memory; streaming request
#'   bodies are §27's, not this stage's.
#' @return A `zu_request`.
#' @name zu_body
#' @examples
#' req <- zu_request("POST", "https://example.com/upload")
#' zu_body_raw(req, charToRaw("hello"))
NULL

#' @rdname zu_body
#' @export
zu_body_json <- function(req, x, auto_unbox = TRUE) {
  req <- check_req(req)
  set_body(req, charToRaw(json_encode(x, auto_unbox = auto_unbox)),
           "JSON", "application/json")
}

#' @rdname zu_body
#' @export
zu_body_form <- function(req, x) {
  req <- check_req(req)
  body <- build_query(as_query_list(x))
  set_body(req, charToRaw(if (is.null(body)) "" else body),
           "form", "application/x-www-form-urlencoded")
}

#' @rdname zu_body
#' @export
zu_body_raw <- function(req, x, type = NULL) {
  req <- check_req(req)
  if (is.character(x)) {
    if (length(x) != 1L || is.na(x))
      stop("a character body must be a single non-NA string", call. = FALSE)
    x <- charToRaw(enc2utf8(x))
    if (is.null(type)) type <- "text/plain; charset=UTF-8"
  }
  if (!is.raw(x)) stop("body must be a raw vector or a string", call. = FALSE)
  set_body(req, x, "raw", type)
}

#' @rdname zu_body
#' @export
zu_body_file <- function(req, path, type = "application/octet-stream") {
  req <- check_req(req)
  if (!file.exists(path)) stop("no such file: ", path, call. = FALSE)
  n <- file.info(path)$size
  set_body(req, readBin(path, "raw", n = n), "file", type)
}

set_body <- function(req, bytes, kind, type) {
  req$body         <- bytes
  req$body_kind    <- kind
  req$content_type <- type
  req
}

#' Set request policy
#'
#' Per-request overrides of the client's policy defaults. Passing `NULL` resets
#' to the *package* default rather than the client's value (§31.9) — which is
#' the only way to escape a client default at the request level.
#'
#' @param req A `zu_request`.
#' @param total Total seconds for the request, redirects included. A single
#'   number today; the phase-specific model of §24 will accept richer values
#'   through the same argument.
#' @param max Maximum redirects to follow. `0` returns the 3xx response itself.
#' @param check Raise a condition for 4xx and 5xx (§31.14).
#' @return A `zu_request`.
#' @name zu_req_policy
#' @examples
#' zu_req_timeout(zu_request("GET", "https://example.com"), total = 5)
NULL

#' @rdname zu_req_policy
#' @export
zu_req_timeout <- function(req, total) {
  req <- check_req(req)
  req$policy[["timeout"]] <- if (missing(total) || is.null(total)) .zu_reset else total
  req
}

#' @rdname zu_req_policy
#' @export
zu_req_redirects <- function(req, max) {
  req <- check_req(req)
  req$policy[["redirects"]] <- if (missing(max) || is.null(max)) .zu_reset else max
  req
}

#' @rdname zu_req_policy
#' @export
zu_req_check <- function(req, check = TRUE) {
  req <- check_req(req)
  req$policy[["check"]] <- if (is.null(check)) .zu_reset else check
  req
}

#' @export
print.zu_request <- function(x, ...) {
  # §42.2: a printed request is an egress like any other, so the URL and the
  # header values go through the redaction filter first.
  cat("<zu_request>\n")
  cat(x$method, " ", zu_redact_url(url_with_query(x$url, x$query)), "\n", sep = "")
  h <- zu_redact_headers_for_display(x$headers)
  for (i in seq_along(h)) cat(names(h)[i], ": ", h[[i]], "\n", sep = "")
  if (!is.null(x$content_type) &&
      !any(tolower(names(x$headers)) == "content-type"))
    cat("Content-Type: ", x$content_type, "\n", sep = "")
  if (!is.null(x$body))
    cat("Body: ", x$body_kind, ", ", length(x$body), " bytes\n", sep = "")
  # A resolved request (one that has been through zu_perform) knows every
  # policy value, not just the ones the caller named; show those instead.
  pol <- if (!is.null(x$resolved)) x$resolved else x$policy
  for (f in names(pol)) {
    v <- pol[[f]]
    if (is.null(v)) next
    cat(f, ": ", if (inherits(v, "zu_reset")) "package default" else format(v),
        "\n", sep = "")
  }
  invisible(x)
}

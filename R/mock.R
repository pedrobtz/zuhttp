# §37 mock matching.
#
# §36.1 is what makes this worth having: a transport is a function of one
# request returning one response, and it implements network semantics ONLY.
# Redirects, retries and policy merging sit above it. So a mock substituted
# here exercises the same merging, the same redaction and the same response
# accessors as the native transport — it is a stand-in, not a parallel
# implementation, and a test written against it is testing real code.
#
# zu_mock_transport() keeps accepting a bare function, which is the form §36
# documents and the rest of this suite already uses. Stubs are the addition:
# §37 asks for matching on method, URL, headers and body, and a handler that
# has to `if` its way through those by hand is where mock code starts drifting
# from the thing it stands in for.

#' Match a request and return a canned response
#'
#' A stub pairs a matcher with a response. Every supplied criterion must match
#' (they are ANDed); an omitted criterion matches anything.
#'
#' @param response A [zu_response()], or a function of one request returning
#'   one. The function form is for stubs whose reply depends on the request.
#' @param method HTTP method to match, case-insensitive. `NULL` matches any.
#' @param url URL to match. A plain string must match exactly *after* client
#'   merging — that is, the absolute URL with the query attached. Use `regex`
#'   for anything looser.
#' @param regex A regular expression matched against the URL, as an
#'   alternative to `url`.
#' @param headers Named character vector of headers that must be present with
#'   these values. Names are matched case-insensitively (§18.3); headers not
#'   named here are ignored.
#' @param body Raw or character body that must match exactly.
#' @param times Maximum number of times this stub may match; `Inf` by default.
#'   A stub with `times = 1` is how you assert a request is not retried.
#' @return A `zu_stub`, for [zu_mock_transport()].
#' @seealso [zu_mock_transport()]
#' @export
#' @examples
#' stub <- zu_stub(zu_response(201L), method = "POST", regex = "/users$")
#' api  <- zu_client(transport = zu_mock_transport(stub))
#' zu_resp_status(zu_perform(zu_request("POST", "https://x.test/users"),
#'                           client = api))
zu_stub <- function(response, method = NULL, url = NULL, regex = NULL,
                    headers = NULL, body = NULL, times = Inf) {
  if (!is.function(response) && !inherits(response, "zu_response"))
    stop("`response` must be a zu_response() or a function returning one",
         call. = FALSE)
  if (!is.null(url) && !is.null(regex))
    stop("give `url` or `regex`, not both", call. = FALSE)
  if (is.character(body)) body <- charToRaw(enc2utf8(paste0(body, collapse = "")))
  structure(
    list(response = response,
         method   = if (!is.null(method)) toupper(method),
         url      = url,
         regex    = regex,
         headers  = as_header_vec(headers),
         body     = body,
         times    = times,
         matched  = 0L),
    class = "zu_stub"
  )
}

#' @export
print.zu_stub <- function(x, ...) {
  crit <- c(
    if (!is.null(x$method))  paste("method", x$method),
    if (!is.null(x$url))     paste("url", x$url),
    if (!is.null(x$regex))   paste("regex", x$regex),
    if (length(x$headers))   paste(length(x$headers), "header(s)"),
    if (!is.null(x$body))    "body",
    if (is.finite(x$times))  paste("times", x$times)
  )
  cat("<zu_stub", if (length(crit)) paste0(": ", paste(crit, collapse = ", ")),
      ">\n", sep = "")
  invisible(x)
}

# Does `req` satisfy every criterion this stub names? An absent criterion is
# not a criterion — it must not narrow the match, or a stub with no matchers
# would match nothing instead of everything.
stub_matches <- function(stub, req) {
  if (stub$matched >= stub$times) return(FALSE)
  if (!is.null(stub$method) && !identical(toupper(req$method), stub$method))
    return(FALSE)
  if (!is.null(stub$url) && !identical(req$url, stub$url)) return(FALSE)
  if (!is.null(stub$regex) && !grepl(stub$regex, req$url)) return(FALSE)
  if (length(stub$headers)) {
    have <- req$headers
    hn   <- tolower(names(have) %||% character())
    for (i in seq_along(stub$headers)) {
      j <- match(tolower(names(stub$headers)[i]), hn)
      if (is.na(j) || !identical(unname(have[j]), unname(stub$headers[i])))
        return(FALSE)
    }
  }
  if (!is.null(stub$body) && !identical(as.raw(req$body %||% raw()), stub$body))
    return(FALSE)
  TRUE
}

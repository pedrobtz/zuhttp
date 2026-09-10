# §31.7's JSON decision: jsonlite in Suggests, not Imports.
#
# The hard-dependency count stays at zero (§1). Everything except the two JSON
# helpers works without jsonlite, including sending a JSON body the caller has
# already serialised — and a package author who prefers another implementation
# can swap it in rather than taking jsonlite transitively.

json_state <- new.env(parent = emptyenv())

#' Choose the JSON implementation
#'
#' `zuhttp` has no hard dependencies. [zu_body_json()] and [zu_resp_json()]
#' use `jsonlite` if it is installed, and this replaces it with anything else.
#'
#' @param encode A function `(x, ...)` returning a single JSON string. Must
#'   accept `...`, since request-level options are forwarded to it.
#' @param decode A function `(txt, ...)` returning an R object.
#' @return The previous backend, invisibly.
#' @export
#' @examples
#' \dontrun{
#' zu_set_json_backend(
#'   encode = function(x, ...) RcppSimdJson::serialize(x),
#'   decode = function(txt, ...) RcppSimdJson::fparse(txt)
#' )
#' }
zu_set_json_backend <- function(encode = NULL, decode = NULL) {
  old <- list(encode = json_state$encode, decode = json_state$decode)
  if (!is.null(encode)) stopifnot(is.function(encode))
  if (!is.null(decode)) stopifnot(is.function(decode))
  json_state$encode <- encode
  json_state$decode <- decode
  invisible(old)
}

# Split out so tests can replace it, and so the error message below has one
# place to come from.
has_jsonlite <- function() requireNamespace("jsonlite", quietly = TRUE)

need_jsonlite <- function(what) {
  if (has_jsonlite()) return(invisible(TRUE))
  stop("`", what, "` needs a JSON implementation, and jsonlite is not installed.\n",
       "  zuhttp has no hard dependencies, so JSON support is optional.\n",
       "  * install.packages(\"jsonlite\")\n",
       "  * or supply your own: zu_set_json_backend(encode = , decode = )\n",
       "  Everything else in zuhttp works without it, including sending a\n",
       "  JSON string you have already serialised, with zu_body_raw().",
       call. = FALSE)
}

json_encode <- function(x, ...) {
  if (!is.null(json_state$encode)) {
    out <- json_state$encode(x, ...)
  } else {
    need_jsonlite("zu_body_json()")
    # digits = NA keeps full double precision; null = "null" stops NULL from
    # silently becoming {} inside a list.
    out <- as.character(jsonlite::toJSON(x, null = "null", digits = NA, ...))
  }
  if (!is.character(out) || length(out) != 1L || is.na(out))
    stop("the JSON backend's encode() must return a single string", call. = FALSE)
  out
}

json_decode <- function(txt, ...) {
  if (!is.null(json_state$decode)) return(json_state$decode(txt, ...))
  need_jsonlite("zu_resp_json()")
  jsonlite::fromJSON(txt, ...)
}

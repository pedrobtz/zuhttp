# §31.7's JSON decision (D-88): zujson, the zu* sibling written for exactly
# these two jobs, in Imports. It has no R dependencies of its own and vendors
# its parser, so JSON works with nothing else installed. zu_set_json_backend()
# still swaps in any other implementation.

the_json <- new.env(parent = emptyenv())

#' Choose the JSON implementation
#'
#' [zu_body_json()] and [zu_resp_json()] use `zujson` by default
#' ([zujson::json_write()] and [zujson::json_parse()]); this replaces it with
#' anything else, `jsonlite` included.
#'
#' @param encode A function `(x, ...)` returning a single JSON string. Must
#'   accept `...`, since request-level options are forwarded to it.
#' @param decode A function `(txt, ...)` returning an R object.
#' @return The previous backend, invisibly.
#' @export
#' @examples
#' # Any pair of functions will do; a real one would wrap a JSON package,
#' # e.g. encode = function(x, ...) RcppSimdJson::serialize(x).
#' old <- zu_set_json_backend(
#'   encode = function(x, ...) sprintf('{"n":%d}', length(x)),
#'   decode = function(txt, ...) list(text = txt)
#' )
#' req <- zu_body_json(zu_request("POST", "https://api.example.com"), list(1, 2))
#' rawToChar(req$body)
#'
#' zu_set_json_backend(old$encode, old$decode)   # restore
zu_set_json_backend <- function(encode = NULL, decode = NULL) {
  old <- list(encode = the_json$encode, decode = the_json$decode)
  if (!is.null(encode)) {
    stopifnot(is.function(encode))
  }
  if (!is.null(decode)) {
    stopifnot(is.function(decode))
  }
  the_json$encode <- encode
  the_json$decode <- decode
  invisible(old)
}

json_encode <- function(x, ...) {
  out <- if (!is.null(the_json$encode)) {
    the_json$encode(x, ...)
  } else {
    zujson::json_write(x, ...)
  }
  if (!is.character(out) || length(out) != 1L || is.na(out)) {
    stop(
      "the JSON backend's encode() must return a single string",
      call. = FALSE
    )
  }
  out
}

json_decode <- function(txt, ...) {
  if (!is.null(the_json$decode)) {
    return(the_json$decode(txt, ...))
  }
  zujson::json_parse(txt, ...)
}

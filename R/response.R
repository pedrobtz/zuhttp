# §31.7 — responses.
#
# The accessor functions are the stable contract; `$status` and `$body` are
# not. That is not pedantry: §31.8 leaves room for a response whose body is a
# live stream rather than a vector, and code reaching into the list would break
# the day that lands.

#' Construct a response
#'
#' Mostly for mock transports (§31.12) and for tests. Real responses come back
#' from [zu_perform()].
#'
#' @param status Integer HTTP status.
#' @param headers Named character vector. Repeated names are allowed and are
#'   preserved (§18.3).
#' @param body A raw vector, or a string (encoded as UTF-8).
#' @param url The final URL.
#' @param tls_version TLS version string, or `NULL` for plain HTTP.
#' @param redirects Number of redirects followed.
#' @return A `zu_response`.
#' @export
#' @examples
#' zu_response(200L, c("Content-Type" = "text/plain"), "hello")
zu_response <- function(status = 200L, headers = NULL, body = raw(),
                        url = NULL, tls_version = NULL, redirects = 0L) {
  if (is.character(body)) body <- charToRaw(enc2utf8(paste0(body, collapse = "")))
  structure(
    list(status = as.integer(status), headers = as_header_vec(headers),
         body = body, url = url, tls_version = tls_version,
         redirects = as.integer(redirects), method = NULL,
         timings = c(total = NA_real_), request = NULL),
    class = "zu_response"
  )
}

#' Response accessors
#'
#' @param resp A `zu_response`.
#' @param name A header name. Matching is case-insensitive (§18.3).
#' @return `zu_resp_status()` an integer; `zu_resp_ok()` a logical;
#'   `zu_resp_headers()` a named character vector; `zu_resp_header()` a
#'   character vector, length 0 when the header is absent and longer than 1
#'   when it repeats; `zu_resp_url()` the final URL after redirects, with any
#'   credentials removed (§42); `zu_resp_method()` the method actually sent,
#'   which a 303 may have rewritten to `GET`; `zu_resp_timings()` a named
#'   numeric vector of seconds.
#' @name zu_resp
#' @examples
#' r <- zu_response(200L, c("Set-Cookie" = "a=1", "Set-Cookie" = "b=2"))
#' zu_resp_header(r, "set-cookie")
NULL

#' @rdname zu_resp
#' @export
zu_resp_status <- function(resp) resp$status

#' @rdname zu_resp
#' @export
zu_resp_ok <- function(resp) resp$status >= 200L && resp$status < 400L

#' @rdname zu_resp
#' @export
zu_resp_headers <- function(resp) resp$headers

#' @rdname zu_resp
#' @export
zu_resp_header <- function(resp, name) {
  h <- resp$headers
  if (is.null(h)) return(character())
  # A character vector, never a comma-joined scalar: Set-Cookie is why (§18.3).
  unname(h[tolower(names(h)) == tolower(name)])
}

#' @rdname zu_resp
#' @export
zu_resp_url <- function(resp) resp$url

#' @rdname zu_resp
#' @export
zu_resp_method <- function(resp) resp$method

#' Connection metadata
#'
#' §35.2: what actually happened at the transport layer for this response.
#' Reported for the **final** hop — after a redirect chain the earlier
#' connections are gone, and describing one of those would answer a question
#' nobody asked.
#'
#' @param resp A `zu_response`.
#' @return A named list: `reused_connection`, `remote_ip`, `tls_protocol`,
#'   `tls_cipher`, `trust_backend`, `http_version`, `proxy_used`,
#'   `retries_performed` and `redirect_count`.
#'
#' @section Why the cipher is named and not numbered:
#' `tls_cipher` reads `"ECDHE-ECDSA-CHACHA20-POLY1305"`, not `"0xcca9"`. The
#' question someone opens this list to ask is whether the connection has
#' forward secrecy and an AEAD mode, and the name answers it while the number
#' does not. Secure Transport and Schannel both report a numeric suite code;
#' it is mapped in C so all three backends say the same kind of thing.
#'
#' `trust_backend` is separate from the TLS engine because §13.1 splits them —
#' on macOS the protocol is Secure Transport and the trust decision is
#' SecTrust, and "which store trusted this?" is a question users genuinely
#' arrive with.
#'
#' @seealso [zu_resp_timings()], [zu_info()] for what the build can do.
#' @export
#' @examples
#' r <- zu_response(200L)
#' zu_resp_connection(r)
zu_resp_connection <- function(resp) {
  v <- resp$http_minor
  list(
    reused_connection = isTRUE(resp$reused_connection),
    remote_ip         = resp$remote_ip,
    tls_protocol      = resp$tls_version,
    tls_cipher        = resp$tls_cipher,
    trust_backend     = resp$trust_backend,
    http_version      = if (is.null(v) || is.na(v)) NULL else paste0("HTTP/1.", v),
    proxy_used        = isTRUE(resp$proxy_used),
    # Filled by the retry layer (§33) and the engine respectively, so a
    # response that went through neither still answers 1 and 0 rather than
    # NULL — "how many attempts?" always has an answer.
    retries_performed = max(0L, (resp$attempts %||% 1L) - 1L),
    redirect_count    = resp$redirects %||% 0L
  )
}

#' @rdname zu_resp
#' @export
zu_resp_timings <- function(resp) {
  # Total only for now; the per-phase breakdown (dns, connect, tls, ttfb) is
  # §35's, and reporting NA for phases we have not measured would be worse
  # than not reporting them.
  resp$timings
}

#' The response body, decoded
#'
#' `zu_resp_raw()` returns the **decoded** bytes. Because `Accept-Encoding:
#' gzip` is sent by default and decompression is transparent (§21.2), these are
#' not the bytes that crossed the wire; if you are checksumming against a
#' server-side hash, perform the request with `decode = FALSE` and the body
#' will be exactly what the server sent.
#'
#' @param resp A `zu_response`.
#' @return A raw vector.
#' @export
zu_resp_raw <- function(resp) resp$body

#' The response body as text
#'
#' Character encoding is decided by this chain (§31.7):
#'
#' 1. `encoding` if you pass one;
#' 2. the `charset` parameter of `Content-Type`, if `iconv()` knows it;
#' 3. a UTF-8, UTF-16LE or UTF-16BE byte-order mark, which is then stripped;
#' 4. otherwise **UTF-8** — not the ISO-8859-1 that RFC 7231 nominally implies.
#'    That default is a historical artefact; UTF-8 is right far more often, and
#'    being wrong the other way produces mojibake users blame on the server.
#'
#' For `application/json`, RFC 8259 mandates UTF-8, so steps 2–4 are skipped.
#'
#' The result is always marked UTF-8.
#'
#' @param resp A `zu_response`.
#' @param encoding Encoding to assume, overriding the chain above.
#' @param on_invalid `"error"` raises `zu_body_decode_error` on bytes that are
#'   not valid in the chosen encoding; `"substitute"` opts into lossy
#'   conversion. Silent corruption is not on the menu.
#' @return A single UTF-8 string.
#' @export
#' @examples
#' zu_resp_text(zu_response(200L, c("Content-Type" = "text/plain"), "hi"))
zu_resp_text <- function(resp, encoding = NULL, on_invalid = c("error", "substitute")) {
  on_invalid <- match.arg(on_invalid)
  b  <- resp$body
  if (is.null(b) || !length(b)) return("")
  ct <- content_type_of(resp)

  enc <- NULL
  if (!is.null(encoding)) {
    enc <- encoding
  } else if (identical(ct$type, "application/json")) {
    enc <- "UTF-8"                                   # step 5: RFC 8259
  } else {
    cs <- ct$params[["charset"]]
    if (!is.null(cs) && nzchar(cs) && iconv_knows(cs)) enc <- cs
  }

  bom <- bom_of(b)
  if (is.null(enc)) enc <- if (is.null(bom)) "UTF-8" else bom$encoding
  # A BOM is a signature, not content: strip it whenever it matches what we
  # are about to decode as, however we arrived at that encoding.
  if (!is.null(bom) && sub("-BE$|-LE$", "", toupper(enc)) ==
                       sub("-BE$|-LE$", "", bom$encoding))
    b <- b[-seq_len(bom$n)]

  out <- try_iconv(b, enc)
  if (is.na(out)) {
    if (on_invalid == "error")
      zu_stop("zu_body_decode_error",
              paste0("the response body is not valid ", enc, ".\n",
                     "  * If the server's charset is wrong, say so: ",
                     "zu_resp_text(resp, encoding = \"...\")\n",
                     "  * To accept lossy conversion: ",
                     "zu_resp_text(resp, on_invalid = \"substitute\")"),
              url = resp$url, phase = "decode", response = resp)
    out <- try_iconv(b, enc, sub = "byte")
  }
  if (is.na(out))
    zu_stop("zu_body_decode_error",
            paste0("could not decode the response body as ", enc),
            url = resp$url, phase = "decode", response = resp)
  Encoding(out) <- "UTF-8"
  out
}

# sub defaults to NA, iconv()'s own "report failure" mode. Passing sub = NULL
# instead makes iconv() return NA for perfectly valid input, which reads as a
# decoding failure for every response.
try_iconv <- function(bytes, from, sub = NA_character_) {
  out <- tryCatch(
    suppressWarnings(iconv(list(bytes), from = from, to = "UTF-8", sub = sub)),
    error = function(e) NA_character_
  )
  if (length(out) != 1L) NA_character_ else out
}

iconv_knows <- function(enc) !is.na(try_iconv(charToRaw("a"), enc))

bom_of <- function(b) {
  if (length(b) >= 3 && all(b[1:3] == as.raw(c(0xEF, 0xBB, 0xBF))))
    return(list(encoding = "UTF-8", n = 3L))
  # UTF-16 must be tested after UTF-8 and, between themselves, either order:
  # the two 2-byte marks are distinct sequences, not prefixes of each other.
  if (length(b) >= 2 && all(b[1:2] == as.raw(c(0xFF, 0xFE))))
    return(list(encoding = "UTF-16LE", n = 2L))
  if (length(b) >= 2 && all(b[1:2] == as.raw(c(0xFE, 0xFF))))
    return(list(encoding = "UTF-16BE", n = 2L))
  NULL
}

#' The response body as parsed JSON
#'
#' @param resp A `zu_response`.
#' @param ... Passed to the JSON backend's parser.
#' @return Whatever the backend returns, by default a list.
#' @seealso [zu_set_json_backend()] if you would rather not use `jsonlite`.
#' @export
zu_resp_json <- function(resp, ...) {
  txt <- zu_resp_text(resp, encoding = "UTF-8")
  if (!nzchar(trimws(txt)))
    zu_stop("zu_body_decode_error",
            paste0("the response body is empty, so there is no JSON to parse",
                   " (HTTP ", resp$status, ").\n",
                   "  A 204 or an empty 200 is a valid response; check",
                   " zu_resp_status() before decoding."),
            url = resp$url, phase = "decode", response = redact_response(resp))
  # §34.4: the backend's own complaint is useful but is not a first line. A
  # user seeing "premature EOF (right here) ---^" has to work out that it came
  # from their HTTP call at all.
  tryCatch(json_decode(txt, ...), error = function(e) {
    if (inherits(e, "zu_error")) stop(e)
    zu_stop("zu_body_decode_error",
            paste0("the response body is not valid JSON (HTTP ", resp$status,
                   ", ", length(resp$body), " bytes).\n",
                   "  * If the server sent something else, zu_resp_text()",
                   " shows what.\n",
                   "  * Parser: ", conditionMessage(e)),
            url = resp$url, phase = "decode", response = redact_response(resp))
  })
}

#' Raise a condition for an error status
#'
#' A 4xx raises `zu_http_client_error`, a 5xx raises `zu_http_server_error`,
#' and both inherit `zu_http_status_error` and `zu_error` (§34.1). This is what
#' requests do by default; `check = FALSE` returns the response instead, and
#' this function then lets you decide later (§31.14).
#'
#' A transport failure and an error status are deliberately different things:
#' a 404 is a successful HTTP exchange whose answer is "no".
#'
#' @param resp A `zu_response`.
#' @return `resp`, invisibly, if the status is not an error.
#' @export
#' @examples
#' r <- zu_response(404L, url = "https://example.com/missing")
#' tryCatch(zu_resp_check(r), zu_http_client_error = function(e) conditionMessage(e))
zu_resp_check <- function(resp) {
  if (zu_resp_ok(resp)) return(invisible(resp))
  code <- if (resp$status < 500L) "zu_http_client_error" else "zu_http_server_error"
  msg <- paste0(
    if (!is.null(resp$method)) paste0(resp$method, " ") else "",
    resp$url %||% "request", " failed: HTTP ", resp$status,
    if (nzchar(status_text(resp$status))) paste0(" ", status_text(resp$status)) else ""
  )
  hint <- status_hint(resp$status)
  if (nzchar(hint)) msg <- paste0(msg, "\n  ", hint)
  excerpt <- body_excerpt(resp)
  if (nzchar(excerpt)) msg <- paste0(msg, "\n  Server said: ", excerpt)
  # The stored request and response are display artefacts (§42.3), so they are
  # redacted copies. The originals stay executable in the caller's hands.
  zu_stop(code, msg, url = resp$url, response = redact_response(resp),
          request = redact_request(resp$request), call = sys.call(-1))
}

`%||%` <- function(a, b) if (is.null(a)) b else a

# A short piece of the server's own error text. Worth having: "HTTP 422" alone
# sends people to a browser, and the body usually says exactly what was wrong.
body_excerpt <- function(resp, n = 200L) {
  ct <- content_type_of(resp)
  if (is.null(ct$type)) return("")
  if (!grepl("^text/", ct$type) &&
      !ct$type %in% c("application/json", "application/problem+json",
                      "application/xml", "application/x-www-form-urlencoded"))
    return("")
  txt <- tryCatch(zu_resp_text(resp, on_invalid = "substitute"),
                  error = function(e) "")
  txt <- gsub("[[:space:]]+", " ", trimws(txt))
  if (!nzchar(txt)) return("")
  if (nchar(txt) > n) paste0(substr(txt, 1L, n), "...") else txt
}

status_text <- function(s) {
  known <- c(
    "200" = "OK", "201" = "Created", "202" = "Accepted", "204" = "No Content",
    "301" = "Moved Permanently", "302" = "Found", "303" = "See Other",
    "304" = "Not Modified", "307" = "Temporary Redirect",
    "308" = "Permanent Redirect",
    "400" = "Bad Request", "401" = "Unauthorized", "402" = "Payment Required",
    "403" = "Forbidden", "404" = "Not Found", "405" = "Method Not Allowed",
    "406" = "Not Acceptable", "408" = "Request Timeout", "409" = "Conflict",
    "410" = "Gone", "413" = "Payload Too Large", "415" = "Unsupported Media Type",
    "418" = "I'm a teapot", "422" = "Unprocessable Content",
    "429" = "Too Many Requests",
    "500" = "Internal Server Error", "501" = "Not Implemented",
    "502" = "Bad Gateway", "503" = "Service Unavailable",
    "504" = "Gateway Timeout"
  )
  v <- known[[as.character(s)]]
  if (is.null(v)) "" else v
}

# §34.4: what was attempted, what failed, and the most likely fix. The fix is
# the part a bare status code cannot give.
status_hint <- function(s) {
  switch(as.character(s),
    "401" = "The request was not authenticated. Check the credential you sent, and that it goes in the header the API expects.",
    "403" = "Authenticated but not permitted. The credential is valid and lacks this scope, or the resource belongs to someone else.",
    "404" = "The server has no such resource. If you are using a client base_url, check the join: base_url and path are concatenated, not resolved.",
    "405" = "The path exists but not for this method.",
    "413" = "The request body was too large for the server.",
    "415" = "The server rejected the body's Content-Type.",
    "429" = "Rate limited. Any Retry-After header is in zu_resp_header(resp, \"retry-after\").",
    "500" = , "502" = , "503" = , "504" =
      "A server-side failure, not a request the server rejected. Retrying is often reasonable for an idempotent request.",
    ""
  )
}

# --- Content-Type ----------------------------------------------------------
# Enough of RFC 9110 5.6.6 to read a charset out of a real header, including
# the quoted form that servers do send: text/plain; charset="utf-8".
parse_content_type <- function(v) {
  if (is.null(v) || !length(v) || is.na(v[[1]]) || !nzchar(v[[1]]))
    return(list(type = NULL, params = list()))
  v <- v[[1]]
  parts <- strsplit(v, ";", fixed = TRUE)[[1]]
  type <- tolower(trimws(parts[[1]]))
  params <- list()
  for (p in parts[-1]) {
    kv <- regmatches(p, regexpr("=", p, fixed = TRUE), invert = TRUE)[[1]]
    if (length(kv) != 2L) next
    k <- tolower(trimws(kv[[1]]))
    val <- trimws(kv[[2]])
    if (startsWith(val, "\"")) val <- gsub("\\\\(.)", "\\1", sub("\"$", "", sub("^\"", "", val)))
    params[[k]] <- val
  }
  list(type = type, params = params)
}

content_type_of <- function(resp) parse_content_type(zu_resp_header(resp, "content-type"))

# --- redaction for display (§42.2) -----------------------------------------
redact_response <- function(resp) {
  if (is.null(resp)) return(NULL)
  resp$headers <- zu_redact_headers_for_display(resp$headers)
  if (!is.null(resp$url)) resp$url <- zu_redact_url(resp$url)
  resp$request <- redact_request(resp$request)
  resp
}

redact_request <- function(req) {
  if (is.null(req)) return(NULL)
  req$headers <- zu_redact_headers_for_display(req$headers)
  req$url     <- zu_redact_url(req$url)
  # A form body carries credentials as often as a header does.
  if (identical(req$body_kind, "form") && !is.null(req$body))
    req$body <- charToRaw(zu_redact_form(rawToChar(req$body)))
  req
}

#' @export
print.zu_response <- function(x, ...) {
  st <- status_text(x$status)
  cat("<zu_response [", x$status, if (nzchar(st)) paste0(" ", st), "]>\n", sep = "")
  # A hand-built response may have neither, and an empty line reads as a bug.
  if (!is.null(x$method) || !is.null(x$url))
    cat(x$method %||% "", if (!is.null(x$method)) " ", zu_redact_url(x$url %||% ""),
        "\n", sep = "")
  h <- zu_redact_headers_for_display(x$headers)
  if (length(h)) {
    n <- min(length(h), 8L)
    for (i in seq_len(n)) cat(names(h)[i], ": ", h[[i]], "\n", sep = "")
    if (length(h) > n) cat("... and ", length(h) - n, " more headers\n", sep = "")
  }
  cat("Body: ", format_bytes(length(x$body)), " in memory\n", sep = "")
  if (!is.na(x$timings[["total"]]))
    cat("Total: ", round(x$timings[["total"]] * 1000), " ms\n", sep = "")
  if (!is.null(x$tls_version)) cat("TLS: ", x$tls_version, "\n", sep = "")
  if (!is.null(x$redirects) && x$redirects > 0L)
    cat("Redirects: ", x$redirects, "\n", sep = "")
  invisible(x)
}

format_bytes <- function(n) {
  if (n < 1000) return(paste0(n, " B"))
  if (n < 1000^2) return(paste0(format(round(n / 1000, 1), trim = TRUE), " kB"))
  paste0(format(round(n / 1000^2, 1), trim = TRUE), " MB")
}

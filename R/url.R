# URL assembly for the R layer. Parsing and validation stay in C (src/zuh_uri.c,
# §8) — this is only what has to happen before a URL can be handed over: the
# base_url join and query-string encoding.

# Both checks below run on every request, and both were once regexes. Under
# memory pressure R's TRE regex engine can report "no match" with only a
# warning, or crash (#282): a valid `GET` was refused as an invalid method,
# and an absolute URL read as relative would be joined onto base_url. They
# are character-set checks, so they need no regex. tests/testthat/test-url.R
# holds them to the regexes they replace.
is_absolute_url <- function(x) {
  vapply(x, is_absolute_url1, logical(1), USE.NAMES = FALSE)
}

is_absolute_url1 <- function(s) {
  if (is.na(s)) {
    return(FALSE)
  }
  at <- regexpr("://", s, fixed = TRUE)
  if (at < 2L) {
    return(FALSE)
  }
  cp <- utf8ToInt(substr(s, 1L, at - 1L))
  # RFC 3986 §3.1: scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
  !anyNA(cp) && cp[1L] %in% ascii_alpha && all(cp %in% scheme_chars)
}

# RFC 9110 §5.6.2: token = 1*tchar.
is_token <- function(s) {
  if (is.na(s) || !nzchar(s)) {
    return(FALSE)
  }
  cp <- utf8ToInt(s)
  !anyNA(cp) && all(cp %in% tchar)
}

ascii_alpha <- c(65:90, 97:122)
scheme_chars <- c(ascii_alpha, 48:57, utf8ToInt("+-."))
tchar <- c(ascii_alpha, 48:57, utf8ToInt("!#$%&'*+-.^_`|~"))

# §31.3's base_url. Textual join, not RFC 3986 resolution — see the note in
# zu_client(): resolution would drop the "/v1" from a versioned base URL,
# which is never what someone setting base_url meant.
join_url <- function(base, path) {
  if (is.null(base) || !nzchar(base)) {
    zu_stop(
      "zu_url_error",
      paste0(
        "`",
        path,
        "` is not an absolute URL and no client base_url is set.\n",
        "  Either pass a full URL, or set one:\n",
        "    api <- zu_client(base_url = \"https://api.example.com\")\n",
        "    zu_get(\"",
        path,
        "\", client = api)"
      )
    )
  }
  # A query or fragment on the base would end up in the middle of the joined
  # URL, where it means something entirely different.
  base <- sub("[?#].*$", "", base)
  paste0(sub("/+$", "", base), "/", sub("^/+", "", path))
}

# RFC 3986 unreserved: ALPHA / DIGIT / "-" / "." / "_" / "~". Everything else
# is percent-encoded from its UTF-8 bytes. utils::URLencode() is not used: it
# works on characters rather than bytes, and its `reserved` handling has caught
# people out often enough that a 10-line loop is the better trade.
# Text as UTF-8 bytes for the wire. enc2utf8() reads an "unknown" string as
# the native encoding, and in a C locale that is ASCII, so "café" from a
# script became "caf<c3><a9>". Convert only what is marked latin1, or native
# text in a non-UTF-8 locale that is not already valid UTF-8.
to_utf8 <- function(x) {
  x <- as.character(x)
  enc <- Encoding(x)
  need <- enc == "latin1" |
    (enc == "unknown" & !l10n_info()[["UTF-8"]] & !validUTF8(x))
  x[need] <- enc2utf8(x[need])
  x
}

pct_encode <- function(x) {
  vapply(
    to_utf8(x),
    function(s) {
      if (is.na(s)) {
        return(NA_character_)
      }
      b <- charToRaw(s)
      ok <- (b >= as.raw(0x41) & b <= as.raw(0x5A)) | # A-Z
        (b >= as.raw(0x61) & b <= as.raw(0x7A)) | # a-z
        (b >= as.raw(0x30) & b <= as.raw(0x39)) | # 0-9
        b %in% as.raw(c(0x2D, 0x2E, 0x5F, 0x7E)) # - . _ ~
      out <- ifelse(
        ok,
        rawToChar(b, multiple = TRUE),
        toupper(paste0("%", format(b)))
      )
      paste0(out, collapse = "")
    },
    character(1),
    USE.NAMES = FALSE
  )
}

# R values on the wire. TRUE/FALSE become "true"/"false" rather than R's
# "TRUE"/"FALSE", because the receiving end is almost never R.
# One value per element, each formatted on its own. format() on the whole
# vector padded character values to a common width ("a  "), rounded doubles
# to 7 significant digits and gave them their neighbours' format ("1.0"), and
# in a C locale escaped non-ASCII bytes to "<c3><a9>" before pct_encode()
# saw them (the bug-hunt emit slice). Doubles get the shortest decimal that
# reads back as the same number, which is what zu_body_json() sends.
query_atom <- function(v) {
  if (is.logical(v)) {
    return(ifelse(v, "true", "false"))
  }
  if (inherits(v, "POSIXt")) {
    return(format(v, "%Y-%m-%dT%H:%M:%SZ", tz = "UTC"))
  }
  if (is.factor(v)) {
    v <- as.character(v)
  }
  if (is.character(v)) {
    return(to_utf8(v))
  }
  if (is.double(v)) {
    return(vapply(v, num_atom, ""))
  }
  as.character(v)
}

num_atom <- function(x) {
  if (!is.finite(x)) {
    return(as.character(x))
  }
  x <- x + 0 # -0 is 0
  if (x == trunc(x) && abs(x) < 2^53) {
    return(sprintf("%.0f", x))
  }
  for (d in 15:17) {
    s <- sprintf("%.*g", d, x)
    if (as.numeric(s) == x) break
  }
  s
}

# A length > 1 value repeats the key: list(id = c(1, 2)) -> "id=1&id=2". This
# is the form nearly every server framework parses into a list. Walked by
# position, not name: q[[nm]] returns the first of a repeated name each time,
# so list(a = "1", a = "2") sent "a=1&a=1".
build_query <- function(q) {
  if (is.null(q) || !length(q)) {
    return(NULL)
  }
  parts <- character()
  nms <- names(q)
  for (i in seq_along(q)) {
    v <- q[[i]]
    if (is.null(v) || !length(v)) {
      next
    }
    v <- v[!is.na(v)]
    if (!length(v)) {
      next
    }
    parts <- c(
      parts,
      paste0(pct_encode(nms[[i]]), "=", pct_encode(query_atom(v)))
    )
  }
  if (!length(parts)) NULL else paste0(parts, collapse = "&")
}

url_with_query <- function(url, q) {
  qs <- build_query(q)
  if (is.null(qs)) {
    return(url)
  }
  # The fragment comes last (RFC 3986 §3.5), so the parameters go before
  # it: appended after it, they were part of the fragment, which the URI
  # parser drops, and they vanished without an error (#219). A `?` inside
  # the fragment is not a query either.
  hash <- regexpr("#", url, fixed = TRUE)
  frag <- if (hash > 0L) substring(url, hash) else ""
  base <- if (hash > 0L) substr(url, 1L, hash - 1L) else url
  # A URL that already carries a query keeps it; the merged parameters are
  # appended rather than replacing what the caller wrote.
  sep <- if (grepl("?", base, fixed = TRUE)) "&" else "?"
  paste0(base, sep, qs, frag)
}

# For printing only, so it goes through the §42 redaction filter like any
# other egress; the throwaway origin exists because the filter works on URLs.
format_query <- function(q) {
  qs <- build_query(q)
  if (is.null(qs)) {
    return("")
  }
  sub("^http://x/\\?", "", zu_redact_url(paste0("http://x/?", qs)))
}

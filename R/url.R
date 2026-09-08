# URL assembly for the R layer. Parsing and validation stay in C (src/zu_uri.c,
# §8) — this is only what has to happen before a URL can be handed over: the
# base_url join and query-string encoding.

is_absolute_url <- function(x) grepl("^[A-Za-z][A-Za-z0-9+.-]*://", x)

# §31.3's base_url. Textual join, not RFC 3986 resolution — see the note in
# zu_client(): resolution would drop the "/v1" from a versioned base URL,
# which is never what someone setting base_url meant.
join_url <- function(base, path) {
  if (is.null(base) || !nzchar(base))
    zu_stop("zu_url_error",
            paste0("`", path, "` is not an absolute URL and no client base_url is set.\n",
                   "  Either pass a full URL, or set one:\n",
                   "    api <- zu_client(base_url = \"https://api.example.com\")\n",
                   "    zu_get(\"", path, "\", client = api)"))
  # A query or fragment on the base would end up in the middle of the joined
  # URL, where it means something entirely different.
  base <- sub("[?#].*$", "", base)
  paste0(sub("/+$", "", base), "/", sub("^/+", "", path))
}

# RFC 3986 unreserved: ALPHA / DIGIT / "-" / "." / "_" / "~". Everything else
# is percent-encoded from its UTF-8 bytes. utils::URLencode() is not used: it
# works on characters rather than bytes, and its `reserved` handling has caught
# people out often enough that a 10-line loop is the better trade.
pct_encode <- function(x) {
  vapply(enc2utf8(as.character(x)), function(s) {
    if (is.na(s)) return(NA_character_)
    b <- charToRaw(s)
    ok <- (b >= as.raw(0x41) & b <= as.raw(0x5A)) |    # A-Z
          (b >= as.raw(0x61) & b <= as.raw(0x7A)) |    # a-z
          (b >= as.raw(0x30) & b <= as.raw(0x39)) |    # 0-9
          b %in% as.raw(c(0x2D, 0x2E, 0x5F, 0x7E))     # - . _ ~
    out <- ifelse(ok, rawToChar(b, multiple = TRUE), toupper(paste0("%", format(b))))
    paste0(out, collapse = "")
  }, character(1), USE.NAMES = FALSE)
}

# R values on the wire. TRUE/FALSE become "true"/"false" rather than R's
# "TRUE"/"FALSE", because the receiving end is almost never R.
query_atom <- function(v) {
  if (is.logical(v)) return(ifelse(v, "true", "false"))
  if (inherits(v, "POSIXt")) return(format(v, "%Y-%m-%dT%H:%M:%SZ", tz = "UTC"))
  format(v, scientific = FALSE, trim = TRUE)
}

# A length > 1 value repeats the key: list(id = c(1, 2)) -> "id=1&id=2". This
# is the form nearly every server framework parses into a list.
build_query <- function(q) {
  if (is.null(q) || !length(q)) return(NULL)
  parts <- character()
  for (nm in names(q)) {
    v <- q[[nm]]
    if (is.null(v) || !length(v)) next
    v <- v[!is.na(v)]
    if (!length(v)) next
    parts <- c(parts, paste0(pct_encode(nm), "=", pct_encode(query_atom(v))))
  }
  if (!length(parts)) NULL else paste0(parts, collapse = "&")
}

url_with_query <- function(url, q) {
  qs <- build_query(q)
  if (is.null(qs)) return(url)
  # A URL that already carries a query keeps it; the merged parameters are
  # appended rather than replacing what the caller wrote.
  sep <- if (grepl("?", url, fixed = TRUE)) "&" else "?"
  paste0(url, sep, qs)
}

# For printing only, so it goes through the §42 redaction filter like any
# other egress; the throwaway origin exists because the filter works on URLs.
format_query <- function(q) {
  qs <- build_query(q)
  if (is.null(qs)) return("")
  sub("^http://x/\\?", "", zu_redact_url(paste0("http://x/?", qs)))
}

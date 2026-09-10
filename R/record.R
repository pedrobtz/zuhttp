# §37 record/replay.
#
# A cassette is a list of interactions in one uncompressed .rds file. Three
# decisions shape the file, and each is a trap avoided rather than a taste:
#
# 1. WHAT IS ON DISK IS ALREADY REDACTED. Not redacted on read, not redacted
#    on print — redacted before the bytes are written, because the failure
#    mode §42 exists to prevent is a credential committed to a repository in
#    a test fixture. A cassette is the one egress that outlives the session.
#
# 2. THE MATCH KEY IS COMPUTED FROM THE REDACTED REQUEST. The obvious design
#    keys on the real URL and stores only a hash of it, but a hash of a URL
#    whose shape is known is brute-forceable, and "we only stored the hash"
#    is how credentials leak from fixtures. Keying on the redacted form means
#    two requests differing only in their secret collapse to one interaction
#    — which is also the behaviour a test wants, since the secret is not
#    supposed to change the response.
#
# 3. THE FILE IS UNCOMPRESSED. A compressed cassette would hide a plaintext
#    credential from a byte-level scan, which would make the §42.4 canary
#    weaker than it looks while appearing to pass. The canary greps the file
#    itself, so the file has to be greppable.

cassette_file <- function(dir, name) file.path(dir, paste0(name, ".rds"))

cassette_read <- function(dir, name) {
  f <- cassette_file(dir, name)
  if (!file.exists(f)) return(list())
  out <- readRDS(f)
  if (!is.list(out)) list() else out
}

cassette_write <- function(dir, name, interactions) {
  if (!dir.exists(dir)) dir.create(dir, recursive = TRUE)
  saveRDS(interactions, cassette_file(dir, name), compress = FALSE)
  invisible(interactions)
}

# The redacted, storable form of a request, and the key at the same time —
# they are deliberately the same thing, so a key can never carry a secret the
# stored form redacted. See note 2 above.
redacted_request <- function(req) {
  body <- req$body
  ct   <- tolower(paste(req$headers[tolower(names(req$headers) %||% "") ==
                                    "content-type"], collapse = ""))
  if (length(body) && grepl("application/x-www-form-urlencoded", ct, fixed = TRUE)) {
    body <- charToRaw(zu_redact_form(rawToChar(as.raw(body))))
  }
  list(
    method  = toupper(req$method %||% "GET"),
    url     = zu_redact_url(req$url %||% ""),
    headers = zu_redact_headers_for_display(req$headers),
    body    = if (length(body)) as.raw(body) else raw()
  )
}

# Identity of an interaction: method, redacted URL, redacted body. Headers are
# NOT part of the key — they vary with client configuration in ways that have
# nothing to do with which response a server would send, and including them
# makes cassettes miss for reasons a test author cannot see.
interaction_key <- function(rr) {
  paste(rr$method, rr$url,
        if (length(rr$body)) paste(rr$body, collapse = "") else "",
        sep = "\x1f")
}

redacted_response <- function(resp) {
  list(
    status      = zu_resp_status(resp),
    headers     = zu_redact_headers_for_display(resp$headers),
    body        = as.raw(resp$body %||% raw()),
    url         = zu_redact_url(resp$url %||% ""),
    tls_version = resp$tls_version,
    redirects   = resp$redirects %||% 0L
  )
}

replay_response <- function(rec) {
  r <- zu_response(status = rec$status, headers = rec$headers, body = rec$body,
                   url = rec$url, tls_version = rec$tls_version,
                   redirects = rec$redirects %||% 0L)
  r$replayed <- TRUE
  r
}

#' Record and replay HTTP interactions
#'
#' A transport that plays responses back from a cassette on disk, so a
#' downstream package's tests run with no network. In `"auto"` mode it records
#' whatever it has not seen before and replays everything else, which means a
#' test suite is written once against the real service and then runs offline.
#'
#' @param dir Directory holding cassettes. Defaults to a subdirectory of
#'   `tempdir()`, so nothing is written outside the session unless asked.
#' @param name Cassette name; one file, `<name>.rds`, inside `dir`.
#' @param mode `"auto"` records on a miss and replays on a hit; `"replay"`
#'   never touches the network and errors on a miss; `"record"` always
#'   performs the request and overwrites the stored interaction.
#' @param transport The transport used when actually performing a request.
#'   A [zu_mock_transport()] here is how this package tests itself.
#' @return A transport object, for `zu_client(transport = )`.
#'
#' @section What is written:
#' Credentials are removed *before* anything reaches the disk: userinfo and
#' secret query parameters in URLs, secret headers in both directions, and
#' form-encoded bodies, all through the §42 policy that the rest of the
#' package uses. A cassette is the one egress that outlives the session, so
#' this is the egress where redaction matters most.
#'
#' Requests are matched on method, URL and body — not on headers, which vary
#' with client configuration in ways that do not change what a server would
#' reply. The URL and body used for matching are the redacted ones, so a
#' cassette cannot be made to carry a secret by way of its index.
#'
#' @seealso [zu_cassette_interactions()], [zu_cassette_clear()]
#' @export
#' @examples
#' dir <- file.path(tempdir(), "zuhttp-example")
#' live <- zu_mock_transport(function(req) zu_response(200L, body = "hello"))
#'
#' rec <- zu_cassette_transport(dir, "demo", transport = live)
#' zu_resp_text(zu_get("https://x.test/a", client = zu_client(transport = rec)))
#'
#' # Now offline: the same request never reaches `live`.
#' rep <- zu_cassette_transport(dir, "demo", mode = "replay")
#' zu_resp_text(zu_get("https://x.test/a", client = zu_client(transport = rep)))
#' zu_cassette_clear(dir, "demo")
zu_cassette_transport <- function(dir = file.path(tempdir(), "zuhttp-cassettes"),
                                  name = "default",
                                  mode = c("auto", "replay", "record"),
                                  transport = zu_native_transport()) {
  mode <- match.arg(mode)
  if (!is.character(name) || length(name) != 1L || !nzchar(name))
    stop("`name` must be a single non-empty string", call. = FALSE)
  structure(
    list(dir = dir, name = name, mode = mode, transport = transport),
    class = c("zu_cassette_transport", "zu_transport")
  )
}

#' @export
print.zu_cassette_transport <- function(x, ...) {
  n <- length(cassette_read(x$dir, x$name))
  cat("<zu_cassette_transport [", x$mode, "]>\n", sep = "")
  cat("  ", cassette_file(x$dir, x$name), "\n", sep = "")
  cat("  ", n, " interaction(s)\n", sep = "")
  invisible(x)
}

#' @export
zu_transport_perform.zu_cassette_transport <- function(transport, req) {
  rr  <- redacted_request(req)
  key <- interaction_key(rr)
  tape <- cassette_read(transport$dir, transport$name)
  hit  <- Position(function(i) identical(i$key, key), tape, nomatch = 0L)

  if (transport$mode != "record" && hit > 0L)
    return(replay_response(tape[[hit]]$response))

  if (transport$mode == "replay")
    stop("no recorded interaction for ", rr$method, " ", rr$url,
         "\n  cassette: ", cassette_file(transport$dir, transport$name),
         "\n  record it first with mode = \"auto\"", call. = FALSE)

  resp <- zu_transport_perform(transport$transport, req)
  entry <- list(key = key, request = rr, response = redacted_response(resp),
                recorded_at = as.character(Sys.time()))
  if (hit > 0L) tape[[hit]] <- entry else tape[[length(tape) + 1L]] <- entry
  cassette_write(transport$dir, transport$name, tape)
  resp
}

#' Inspect or delete a cassette
#'
#' @param dir,name The cassette's directory and name, as given to
#'   [zu_cassette_transport()].
#' @return `zu_cassette_interactions()` a list of recorded interactions, each
#'   with `request`, `response` and `recorded_at`, all already redacted;
#'   `zu_cassette_clear()` `TRUE` if a file was removed, invisibly.
#' @seealso [zu_cassette_transport()]
#' @export
#' @examples
#' zu_cassette_interactions(tempdir(), "no-such-cassette")
zu_cassette_interactions <- function(dir = file.path(tempdir(), "zuhttp-cassettes"),
                                     name = "default") {
  lapply(cassette_read(dir, name), function(i) i[c("request", "response", "recorded_at")])
}

#' @rdname zu_cassette_interactions
#' @export
zu_cassette_clear <- function(dir = file.path(tempdir(), "zuhttp-cassettes"),
                              name = "default") {
  f <- cassette_file(dir, name)
  invisible(file.exists(f) && file.remove(f))
}

# For test-request.R's percent-encoding properties (#243). Here rather than
# in the test file: tools/ci-run-tests.R shuffles test order.

# Random strings for the encoding properties (#243): ASCII including the
# controls and every reserved character, Latin-1, the BMP above it, and
# astral code points (four UTF-8 bytes). Surrogates are not characters and
# have no UTF-8 encoding, so they are never drawn. The caller seeds.
random_utf8 <- function(n, max_len = 12L) {
  pools <- list(
    1:127,
    128:255,
    c(0x100:0x7FF),
    c(0x800:0xD7FF, 0xE000:0xFFFD),
    0x10000:0x10FFFF
  )
  vapply(
    seq_len(n),
    function(i) {
      len <- sample(0:max_len, 1L)
      cps <- vapply(
        seq_len(len),
        function(j) {
          pool <- pools[[sample(c(1, 1, 1, 2, 3, 4, 5), 1L)]]
          as.integer(pool[sample.int(length(pool), 1L)])
        },
        integer(1)
      )
      enc2utf8(intToUtf8(cps))
    },
    character(1)
  )
}

encoding_inputs <- function() {
  withr::local_seed(243)
  c(
    random_utf8(400),
    "~",
    "*",
    "+",
    " ",
    "",
    "-._~",
    ":/?#[]@!$&'()*+,;=",
    "%",
    "%41",
    "é",
    "€",
    "\U0001F600"
  )
}

# The RFC's rule, from the bytes. Independent of pct_encode(): a loop over
# a byte table, not the vectorised range test the package uses.
rfc3986_encode <- function(s) {
  unreserved <- c(LETTERS, letters, 0:9, "-", ".", "_", "~")
  b <- charToRaw(enc2utf8(s))
  paste0(
    vapply(
      b,
      function(x) {
        ch <- rawToChar(x)
        if (x < as.raw(0x80) && ch %in% unreserved) {
          ch
        } else {
          sprintf("%%%02X", as.integer(x))
        }
      },
      character(1)
    ),
    collapse = ""
  )
}

zu_query_encoded <- function(s) {
  url <- resolved(
    zu_query(zu_request("GET", "https://x/"), k = s),
    zu_client()
  )$url
  sub("^https://x/\\?k=", "", url)
}

zu_form_encoded <- function(s) {
  rawToChar(zu_body_form(zu_request("POST", "https://x/"), list(k = s))$body)
}

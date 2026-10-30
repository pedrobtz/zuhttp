# Does a client inherit the platform's emergency certificate blocks?
#
# The eMudhra test hosts (https://emudhra.we-have-a-problem.com/) serve chains
# through eight intermediate CAs compromised in October 2026, under roots that
# stay trusted. A CA bundle can only list roots, so only a client that asks
# the platform's trust evaluator can refuse them. This requests each host
# with zuhttp and with the curl package and prints which refused.
#
# A refusal is the safe answer. The control host has an ordinary certificate:
# if neither client reaches it, the network is the problem, not trust, and
# the script fails rather than report a result it did not measure.
#
# Run from a file (CLAUDE.md): Rscript tools/check-trust-blocks.R

hosts <- c(
  "emudhra.we-have-a-problem.com", # control: Let's Encrypt
  "dv-g3b-emudhra.we-have-a-problem.com",
  "dv-g3b-aaa-emudhra.we-have-a-problem.com", # via the Sectigo AAA cross-sign
  "dv-g3b-noct-emudhra.we-have-a-problem.com", # leaf never logged to CT
  "dv-g3b-aaa-noct-emudhra.we-have-a-problem.com"
)

library(zuhttp)
have_curl <- requireNamespace("curl", quietly = TRUE)

# The reason is at the END of a TLS message ("... certificate is blocked"),
# so a long one keeps its tail.
one_line <- function(x) {
  x <- gsub("[\r\n|]+", " ", x)
  if (nchar(x) > 90) paste0("...", substring(x, nchar(x) - 80)) else x
}

with_zuhttp <- function(u) {
  tryCatch(
    paste(
      "connected, HTTP",
      zu_resp_status(zu_get(u, timeout = 30, check = FALSE))
    ),
    error = function(e) {
      paste0(
        "**refused** (`",
        class(e)[[1]],
        "`: ",
        one_line(conditionMessage(e)),
        ")"
      )
    }
  )
}
with_curl <- function(u) {
  if (!have_curl) {
    return("curl not installed")
  }
  tryCatch(
    paste(
      "connected, HTTP",
      curl::curl_fetch_memory(
        u,
        handle = curl::new_handle(timeout = 30)
      )$status_code
    ),
    error = function(e) {
      paste0("**refused** (", one_line(conditionMessage(e)), ")")
    }
  )
}

os <- utils::sessionInfo()$running
cv <- if (have_curl) curl::curl_version() else NULL
lines <- c(
  sprintf("### %s, %s", os, format(Sys.Date())),
  "",
  sprintf(
    "zuhttp %s (`%s`); curl package %s (libcurl %s, %s)",
    packageVersion("zuhttp"),
    zu_tls_backend(),
    if (have_curl) packageVersion("curl") else "-",
    if (have_curl) cv$version else "-",
    if (have_curl) cv$ssl_version else "-"
  ),
  "",
  "| Host | zuhttp | curl |",
  "|---|---|---|"
)
control_ok <- FALSE
for (h in hosts) {
  u <- paste0("https://", h, "/")
  z <- with_zuhttp(u)
  k <- with_curl(u)
  if (h == hosts[[1]]) {
    control_ok <- startsWith(z, "connected") || startsWith(k, "connected")
  }
  lines <- c(
    lines,
    sprintf(
      "| `%s`%s | %s | %s |",
      h,
      if (h == hosts[[1]]) " (control)" else "",
      z,
      k
    )
  )
}
writeLines(lines)
summary_file <- Sys.getenv("GITHUB_STEP_SUMMARY")
if (nzchar(summary_file)) {
  cat(lines, sep = "\n", file = summary_file, append = TRUE)
}
if (!control_ok) {
  cat("\nNeither client reached the control host: no result.\n")
  quit(status = 1)
}

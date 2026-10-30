# Success criterion §61.13: zuhttp and httr2 coexist in one session.
#
# test-naming.R compares the two export lists, but skips when httr2 is not
# installed, which on every CRAN-like leg it is not (it is not a Suggests,
# deliberately: §5). This asserts the user-visible half -- that attaching both,
# in the order a user who already has httr2 would, prints no masking message.
# Run from a file, never `Rscript -e` with a multi-line argument (CLAUDE.md).
stopifnot(requireNamespace("httr2", quietly = TRUE))

msgs <- character()
withCallingHandlers(
  {
    library(httr2)
    library(zuhttp)
  },
  packageStartupMessage = function(m) {
    msgs <<- c(msgs, conditionMessage(m))
    invokeRestart("muffleMessage")
  },
  message = function(m) {
    msgs <<- c(msgs, conditionMessage(m))
    invokeRestart("muffleMessage")
  }
)

masked <- grep("masked", msgs, value = TRUE)
cat(
  "attached httr2",
  format(packageVersion("httr2")),
  "then zuhttp;",
  length(msgs),
  "startup message(s)\n"
)
if (length(masked)) {
  cat(masked, sep = "\n")
  stop("attaching zuhttp after httr2 masks something (§61.13)")
}

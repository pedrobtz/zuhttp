# The R suite exactly as CI runs it, from a file: a multi-line `Rscript -e`
# dies on Windows before executing anything (CLAUDE.md; five S8 rounds).
# Differs from R CMD check, which is why CLAUDE.md says to reproduce THIS
# before claiming green.
#
# The tests run in the package's namespace, as under R CMD check, because
# several test internal functions (zu_error_codes(), the redaction helpers):
# W3 made them internal, and an attach-only run then failed to find them.
#
# Shuffled (devtools::test(shuffle = TRUE)'s check, on every run): each file's
# tests run in a random order, so one that leans on another's leftovers fails
# here rather than staying invisible. The seed is printed; ZU_TEST_SEED
# replays an order.
library(testthat)
library(zuhttp)
seed <- suppressWarnings(as.integer(Sys.getenv("ZU_TEST_SEED")))
if (is.na(seed)) {
  seed <- as.integer(Sys.time()) %% 100000L
}
cat("test order seed:", seed, "(ZU_TEST_SEED to replay)\n")
set.seed(seed)
test_dir(
  "tests/testthat",
  package = "zuhttp",
  load_package = "installed",
  reporter = "summary",
  stop_on_failure = TRUE,
  shuffle = TRUE
)

# The R suite exactly as CI runs it, from a file: a multi-line `Rscript -e`
# dies on Windows before executing anything (CLAUDE.md; five S8 rounds).
# Differs from R CMD check, which is why CLAUDE.md says to reproduce THIS
# before claiming green.
#
# The tests run in the package's namespace, as under R CMD check, because
# several test internal functions (zu_error_codes(), the redaction helpers):
# W3 made them internal, and an attach-only run then failed to find them.
library(testthat)
library(zuhttp)
test_dir("tests/testthat", package = "zuhttp", load_package = "installed",
         reporter = "summary", stop_on_failure = TRUE)

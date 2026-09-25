# The R suite exactly as CI runs it, from a file: a multi-line `Rscript -e`
# dies on Windows before executing anything (CLAUDE.md; five S8 rounds).
# Differs from R CMD check, which is why CLAUDE.md says to reproduce THIS
# before claiming green.
library(testthat)
library(zuhttp)
test_dir("tests/testthat", reporter = "summary", stop_on_failure = TRUE)

# The shared object exports R_init_zuhttp and nothing else (D-66, W2).
#
# Everything else is internal: R reaches the C core only through the routines
# R_init_zuhttp registers, with R_useDynamicSymbols(FALSE). An exported
# zuh_*, phr_* or uri* symbol is one another package's shared object can
# collide with when both are loaded -- the vendored picohttpparser and
# uriparser are common enough to make that likely, not hypothetical.

test_that("the shared object exports only R_init_zuhttp (D-66)", {
  skip_on_cran()
  # covr compiles with --coverage, which exports gcov's own symbols: in a
  # coverage build this would measure the instrumentation, not the package.
  skip_if(identical(Sys.getenv("R_COVR"), "true"), "a coverage build")
  dll <- getLoadedDLLs()[["zuhttp"]][["path"]]
  syms <- exported_symbols(dll)

  # Non-vacuous: the entry point must be found, or the parse found nothing.
  expect_true("R_init_zuhttp" %in% syms)
  expect_identical(
    setdiff(syms, "R_init_zuhttp"),
    character(0),
    info = paste(
      "also exported:",
      paste(head(setdiff(syms, "R_init_zuhttp"), 20), collapse = ", ")
    )
  )
})

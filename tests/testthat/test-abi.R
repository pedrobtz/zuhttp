# The shared object exports R_init_zuhttp and nothing else (D-66, W2).
#
# Everything else is internal: R reaches the C core only through the routines
# R_init_zuhttp registers, with R_useDynamicSymbols(FALSE). An exported
# zuh_*, phr_* or uri* symbol is one another package's shared object can
# collide with when both are loaded -- the vendored picohttpparser and
# uriparser are common enough to make that likely, not hypothetical.

exported_symbols <- function(dll) {
  if (.Platform$OS.type == "windows") {
    # A DLL's exports are its export table, which objdump prints between the
    # "[Ordinal/Name Pointer] Table" header and the next blank line, one entry
    # per line that starts with an "[ordinal]". Newer binutils add a column
    # header and a hint ("[   0] +base[   1]  0000 R_init_zuhttp"): the name is
    # the last field either way.
    objdump <- Sys.which("objdump")
    skip_if(objdump == "", "objdump is not on the PATH")
    out <- system2(objdump, c("-p", shQuote(dll)), stdout = TRUE)
    start <- grep("[Ordinal/Name Pointer] Table", out, fixed = TRUE)
    skip_if(length(start) == 0, "objdump printed no export table")
    rest <- out[seq(start[[1]] + 1, length(out))]
    rest <- rest[seq_len(match(TRUE, !nzchar(trimws(rest)), length(rest) + 1) - 1)]
    rest <- trimws(rest[grepl("^\\s*\\[", rest)])
    return(sub("^.*\\s", "", rest))
  }
  nm <- Sys.which("nm")
  skip_if(nm == "", "nm is not on the PATH")
  args <- if (Sys.info()[["sysname"]] == "Darwin") c("-gU") else c("-D", "--defined-only")
  out <- system2(nm, c(args, shQuote(dll)), stdout = TRUE)
  syms <- sub("^.*\\s", "", out[grepl("\\s[TDBRSV]\\s", out)])
  # Mach-O prefixes C symbols with an underscore.
  sub("^_", "", syms)
}

test_that("the shared object exports only R_init_zuhttp (D-66)", {
  skip_on_cran()
  dll <- getLoadedDLLs()[["zuhttp"]][["path"]]
  syms <- exported_symbols(dll)

  # Non-vacuous: the entry point must be found, or the parse found nothing.
  expect_true("R_init_zuhttp" %in% syms)
  expect_identical(
    setdiff(syms, "R_init_zuhttp"), character(0),
    info = paste("also exported:", paste(head(setdiff(syms, "R_init_zuhttp"), 20), collapse = ", "))
  )
})

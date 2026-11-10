# Python as a reference implementation (#240, #243): urllib.parse for
# percent-encoding, h11 for HTTP/1.1 response parsing. Both are optional.
# CRAN never runs these tests, and a machine without python3 or the module
# skips them rather than failing: the comparison needs the reference, and
# its absence says nothing about zuhttp. network.yaml installs h11 so that
# CI does run them.
#
# The scripts are files in tests/testthat/python/, run with -I (isolated
# mode: no user site, no script directory on sys.path), never `python3 -c`
# with a multi-line argument, which fails on Windows (CLAUDE.md).

python3_path <- function() {
  p <- Sys.which("python3")
  if (!nzchar(p)) "" else unname(p)
}

skip_unless_python <- function(module = NULL) {
  testthat::skip_on_cran()
  py <- python3_path()
  if (!nzchar(py)) {
    testthat::skip("python3 is not on the PATH")
  }
  if (!is.null(module)) {
    ok <- suppressWarnings(system2(
      py,
      c("-I", "-c", shQuote(paste0("import ", module))),
      stdout = FALSE,
      stderr = FALSE
    ))
    if (!identical(ok, 0L)) {
      testthat::skip(paste0(
        "the Python module `",
        module,
        "` is not installed"
      ))
    }
  }
  invisible(py)
}

# Runs tests/testthat/python/<script> with `input` (a raw vector) on stdin
# and returns its stdout, parsed as JSON. A script that fails is a test
# error, with its stderr in the message: past skip_unless_python() the
# reference is there, and a crash in it is something to look at.
run_python_json <- function(script, input = raw()) {
  py <- python3_path()
  d <- tempfile("zu-py-")
  dir.create(d)
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  inf <- file.path(d, "in.bin")
  outf <- file.path(d, "out.json")
  errf <- file.path(d, "err.txt")
  writeBin(input, inf)
  status <- system2(
    py,
    c("-I", shQuote(testthat::test_path("python", script))),
    stdin = inf,
    stdout = outf,
    stderr = errf
  )
  if (!identical(status, 0L)) {
    stop(
      script,
      " exited with status ",
      status,
      ":\n",
      paste(readLines(errf, warn = FALSE), collapse = "\n"),
      call. = FALSE
    )
  }
  zujson::json_parse(paste(
    readLines(outf, warn = FALSE, encoding = "UTF-8"),
    collapse = "\n"
  ))
}

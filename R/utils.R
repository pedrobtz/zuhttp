# Small helpers used across the package.

# Base R has %||% only from 4.4, and DESCRIPTION says R (>= 3.5).
`%||%` <- function(a, b) if (is.null(a)) b else a

# One check, one message, for every function that takes a client: a bare
# stopifnot() said `inherits(client, "zu_client") is not TRUE`.
check_client <- function(client, arg = "client") {
  if (!inherits(client, "zu_client")) {
    stop(
      "`",
      arg,
      "` must be a zu_client(); got ",
      class(client)[[1]],
      call. = FALSE
    )
  }
  invisible(client)
}

# One check for every argument that reaches as.integer() (#232). That
# conversion turns anything past .Machine$integer.max, and Inf, into NA with
# only a warning, and a fraction into its floor without one; C then reads NA
# as INT_MIN. #221 and #222 were this twice, so no integer argument gets its
# own check. `n = 1` is a scalar; `n = NA` any length, element by element.
check_whole <- function(
  x,
  arg,
  min,
  max = .Machine$integer.max,
  n = 1L,
  note = NULL
) {
  ok <- is.numeric(x) &&
    (is.na(n) || length(x) == n) &&
    all(is.finite(x)) &&
    all(x == trunc(x)) &&
    all(x >= min) &&
    all(x <= max)
  if (!isTRUE(ok)) {
    hi <- if (max == .Machine$integer.max) ".Machine$integer.max" else max
    stop(
      "`",
      arg,
      "` must be ",
      if (is.na(n)) "whole numbers" else "a single whole number",
      ", at least ",
      min,
      " and at most ",
      hi,
      if (!is.null(note)) paste0(" ", note),
      call. = FALSE
    )
  }
  as.integer(x)
}

# Remove every header named `name`, case-insensitively, as HTTP field names
# are (§18.3), so a request's c(Accept=) replaces a client's c(accept=)
# rather than sitting beside it.
drop_header <- function(h, name) {
  hit <- which(tolower(names(h)) == tolower(name))
  if (length(hit)) h[-hit] else h
}

# Split out so a test can pretend a package is missing.
has_package <- function(pkg) requireNamespace(pkg, quietly = TRUE)

# A package zuhttp suggests rather than imports, for the one function that
# needs it: name the function, the package and the fix.
need_suggested <- function(pkg, what) {
  if (has_package(pkg)) {
    return(invisible(TRUE))
  }
  stop(
    "`",
    what,
    "` needs the ",
    pkg,
    " package, which zuhttp suggests but does not require.\n",
    "  install.packages(\"",
    pkg,
    "\")",
    call. = FALSE
  )
}

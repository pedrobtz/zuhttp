# §42.4's canary: a credential string no output may ever contain, and the
# helpers that search for it. Shared by test-redact.R's arms; here so that
# each arm stands alone, in any order.

CANARY <- "hunter2-DO-NOT-LEAK"

# A byte-level search, so a scan of a file on disk cannot be defeated by an
# encoding or a locale: grepRaw() takes a raw pattern and never converts.
raw_contains <- function(haystack, needle) {
  n <- charToRaw(needle)
  length(haystack) >= length(n) &&
    length(grepRaw(n, haystack, fixed = TRUE, all = FALSE)) > 0
}

# Every string reachable from `x`, at any depth, plus the names along the way.
#
# The shallow version of this walked one level and leaned on print(), which is
# how the hook-payload arm below came to pass while redaction was disabled: a
# payload is list(request = <zu_request>, ...), the request is not atomic so
# the one-level unlist() skipped it, and print() of a zu_request redacts on
# the way out. The canary was inspecting the redacted rendering of the thing
# it was supposed to be checking. Depth is not a refinement here — without it
# the assertion does not touch the value at all.
deep_strings <- function(x) {
  if (is.function(x) || is.environment(x) || is.null(x)) {
    return(character())
  }
  if (is.raw(x)) {
    # Raw bodies may hold NULs, which rawToChar() refuses; drop them rather
    # than lose the whole vector, since a credential is never a NUL.
    return(rawToChar(x[x != as.raw(0)]))
  }
  if (is.atomic(x)) {
    return(c(names(x), as.character(x)))
  }
  if (is.list(x)) {
    return(c(names(x), unlist(lapply(x, deep_strings), use.names = FALSE)))
  }
  character()
}

expect_no_canary <- function(x, label) {
  txt <- c(utils::capture.output(print(x)), deep_strings(x))
  expect_false(
    any(grepl(CANARY, txt, fixed = TRUE)),
    info = paste("canary leaked via", label)
  )
}

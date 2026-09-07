# Executable form of the naming decisions in zuhttp-design.md §1.1 (D-1, D-2).
#
# These have teeth from the first exported function onward, and they guard a
# mistake that is cheap now and expensive after release: an export that masks
# an httr2 function, or one that drifts from the zu_ prefix.

test_that("every export uses the zu_ prefix (D-1)", {
  exports <- getNamespaceExports("zuhttp")
  # S3 methods registered for generics are exempt; user-facing functions are not.
  exports <- exports[!grepl("[.]", exports, fixed = FALSE)]
  skip_if(length(exports) == 0, "no exports yet")

  expect_true(
    all(grepl("^zu_", exports)),
    info = paste("non-conforming:", paste(setdiff(exports, grep("^zu_", exports, value = TRUE)), collapse = ", "))
  )
})

test_that("no export masks an httr2 export (D-2, success criterion 61.13)", {
  skip_if_not_installed("httr2")

  ours <- getNamespaceExports("zuhttp")
  theirs <- getNamespaceExports("httr2")
  skip_if(length(ours) == 0, "no exports yet")

  collisions <- intersect(ours, theirs)
  expect_identical(
    collisions, character(0),
    info = paste(
      "zuhttp and httr2 are expected to coexist in one session (design 5).",
      "Colliding:", paste(collisions, collapse = ", ")
    )
  )
})

test_that("response accessors use the zu_resp_ prefix (D-1)", {
  # The concern D-1 actually names is a BARE response property at top level:
  # zu_status() should be zu_resp_status(). An earlier version of this test
  # matched "^zu_.*(url|headers?|...)$", which also flagged zu_redact_url()
  # and zu_is_secret_header() — neither of which is a response accessor. The
  # anchored form below tests the rule rather than the spelling.
  exports <- getNamespaceExports("zuhttp")
  bare <- grep("^zu_(status|headers?|body|json|text|raw|url|timings)$",
               exports, value = TRUE)

  expect_identical(
    bare, character(0),
    info = paste("these read as response accessors and should be zu_resp_*:",
                 paste(bare, collapse = ", "))
  )

  # And anything that IS a response accessor must use the prefix.
  resp <- grep("^zu_resp_", exports, value = TRUE)
  skip_if(length(resp) == 0, "no response accessors yet")
  expect_true(all(grepl("^zu_resp_[a-z_]+$", resp)))
})

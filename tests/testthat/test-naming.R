# Executable form of the naming decisions in .agents/zuhttp-design.md §1.1 (D-1, D-2).
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

  # §31.11 names zu_headers() and zu_query() as REQUEST transformers, and they
  # take a request as argument one: zu_headers(req, Accept = "..."). They are
  # not response accessors and are exempt by name rather than by accident --
  # the rule being enforced here is about a bare *response* property, e.g.
  # zu_status() where zu_resp_status() is meant.
  bare <- setdiff(bare, "zu_headers")

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

test_that("the export surface is D-65's: 61 functions, none of the 14 removed", {
  # From 0.1.0 on, an export goes only through a deprecation release (§53), so
  # an accidental @export is a commitment. This makes adding one a decision.
  exports <- getNamespaceExports("zuhttp")
  exports <- exports[!grepl(".", exports, fixed = TRUE)]
  expect_length(exports, 61L)

  removed <- c(paste0("zu_client_", c("get", "head", "post", "put", "patch", "delete")),
               "zu_transport_perform", "zu_native_transport", "zu_error_codes",
               "zu_code_retryable", "zu_is_secret_header", "zu_is_secret_param",
               "zu_redact_form", "zu_redact_headers_for_display")
  expect_identical(intersect(removed, exports), character(0))
  # Kept by the maintainer's amendment: each is the only supported way to do it.
  expect_true(all(c("zu_redact_headers", "zu_redact_params", "zu_set_json_backend") %in% exports))
})

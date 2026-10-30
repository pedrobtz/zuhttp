# §25 cancellation and unwind.
#
# What can and cannot be tested here is worth stating, because the gap is real.
#
# Here: that a request completes with the checkpoint installed (online), and
# that an interrupt is classified apart from a programmatic cancel and is not
# retried. A real Ctrl-C delivered to the checking process, and the 200 ms
# bound, are measured in test-engine-live.R against a local server; Rgui and
# RStudio deliver interrupts differently and stay a manual measurement (W11).
# That the unwind frees C memory is the C suite's allocation accounting.

test_that("a request completes with the interrupt checkpoint installed", {
  skip_unless_online()
  # The checkpoint runs every ~100ms for the life of the request (§25.1). If
  # installing it broke the poll loop, this is where that shows.
  r <- zu_get("https://example.com")
  expect_identical(zu_resp_status(r), 200L)
  expect_gt(length(zu_resp_raw(r)), 0)
})

test_that("repeated requests do not accumulate state", {
  skip_unless_online()
  # R_UnwindProtect runs its cleanup on the normal path too. If it did not,
  # or ran twice, this would surface as a crash or a double free rather than
  # as a wrong value.
  for (i in 1:5) {
    r <- zu_get("https://example.com")
    expect_identical(zu_resp_status(r), 200L)
  }
})

test_that("zu_interrupted_error is a distinct, catchable class (§34.1)", {
  # A person pressing Ctrl-C and a programmatic cancellation want different
  # handling, which is why these are separate classes rather than one.
  e <- tryCatch(stop(zu_condition("zu_interrupted_error", "interrupted")),
                zu_cancelled_error = function(e) e)
  expect_s3_class(e, "zu_interrupted_error")
  expect_s3_class(e, "zu_cancelled_error")
  expect_s3_class(e, "zu_error")

  # And catching the specific class does not catch its parent.
  expect_error(
    tryCatch(stop(zu_condition("zu_cancelled_error", "cancelled")),
             zu_interrupted_error = function(e) "wrong"),
    class = "zu_cancelled_error"
  )
})

test_that("an interrupt and a cancel are distinct classes, and neither is retried", {
  # The mapping C_zu_perform applies: our tick returns 1 only for a user interrupt,
  # so ZUH_ERR_CANCELLED arriving from the engine means exactly that. This tests
  # the classification, which is the part that does not need a real signal.
  expect_true(zu_code_retryable("zu_connect_error"))
  expect_false(zu_code_retryable("zu_interrupted_error"))
  expect_false(zu_code_retryable("zu_cancelled_error"))
})

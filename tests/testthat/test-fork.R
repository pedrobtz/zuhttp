# §26.4 hazard 2 / D-32 / R-12 — HTTPS in a forked child on macOS.
#
# Network.framework runs on libdispatch, which refuses to run after fork():
# the child dies with SIGILL rather than failing (F-19; Security.framework's
# trustd connection did the same with SIGSEGV, S0 F-5). The PID guard in
# zuh_tls_dial() cannot make forked HTTPS work; it converts an un-catchable
# crash into a named condition.
# So this file asserts two things, and the first one is the point:
#
#   1. the worker SURVIVES  — mccollect() gets a value back, not a dead child;
#   2. what it gets back inherits zu_fork_error, with the canonical message.
#
# Non-vacuity: comment out the zuh_fork_guard_tripped() branch in
# src/zuh_tls_nw.c and assertion 1 fails — mccollect() returns NULL
# for a child killed by a signal. That is what makes this a test of the
# mechanism rather than of the error text.

test_that("HTTPS in a forked child raises zu_fork_error and does not kill the worker", {
  skip_unless_forked_https_is_testable()

  # Arms the guard in the parent (see above).
  expect_identical(zu_resp_status(zu_get("https://example.com")), 200L)

  # Two children, not one: R-12 is about the trust evaluator being dead in
  # every child, so "every child raised it" is the claim worth asserting.
  res <- parallel::mclapply(
    1:2,
    function(i) {
      tryCatch(
        {
          zu_get("https://example.com")
          "UNEXPECTED SUCCESS"
        },
        condition = function(e) {
          list(classes = class(e), message = conditionMessage(e))
        }
      )
    },
    mc.cores = 2,
    mc.cleanup = FALSE
  )

  for (r in res) {
    # (1) The worker came back at all. NULL here means it died on a signal.
    expect_false(is.null(r))
    expect_type(r, "list")

    # (2) ...with the §34.1 class and the one canonical wording (§6.1).
    expect_true("zu_fork_error" %in% r$classes)
    expect_true("zu_error" %in% r$classes)
    expect_true("error" %in% r$classes)
    expect_match(r$message, "fork", ignore.case = TRUE)
  }
})

test_that("the parent's own requests still work after a child has tripped the guard", {
  skip_unless_forked_https_is_testable()

  expect_identical(zu_resp_status(zu_get("https://example.com")), 200L)
  parallel::mclapply(
    1,
    function(i) {
      tryCatch(zu_get("https://example.com"), condition = function(e) "tripped")
    },
    mc.cores = 1,
    mc.cleanup = FALSE
  )

  # The guard is per-process state; a child tripping it must not disarm the
  # parent, which never forked and whose trustd connection is intact.
  expect_identical(zu_resp_status(zu_get("https://example.com")), 200L)
})

# §26.4 hazard 1 for a connection checked out into a streamed response
# (#209, #250). The body records the PID that opened it: in a forked child
# a read raises zu_fork_error, an abort does nothing, and the finalizer
# drops the child's copy without a close. The parent's view is the oracle:
# a child that read from the socket would take bytes from the middle of the
# parent's body, and one that closed it would cut the body short.
#
# Non-vacuity: removing the zuh_fork_guard_tripped() check from
# open_body_fill() in src/zuh_engine.c makes the child's reads succeed and
# leaves the parent a body with a hole in it, failing both halves.
test_that("a forked child cannot read an open zu_stream, and the parent reads it whole (#250)", {
  testthat::skip_if_not_installed("parallel")
  body <- as.raw(seq_len(300000) %% 251)
  head <- sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", length(body))
  with_raw_server(c(charToRaw(head), body), function(url) {
    r <- zu_perform(zu_request("GET", url), stream = TRUE)
    first <- zu_resp_read(r, 1000)
    expect_length(first, 1000)

    job <- parallel::mcparallel(
      {
        # Read well past what the parent has already staged in memory, so
        # an unguarded read would reach the socket the two processes share.
        attempt <- function() {
          tryCatch(
            {
              for (i in 1:50) {
                if (length(zu_resp_read(r, 65536)) == 0L) break
              }
              "read"
            },
            error = function(e) class(e)
          )
        }
        out <- list(first = attempt(), second = attempt())
        zu_resp_abort(r) # a no-op in a child: the connection is the parent's
        rm(r)
        gc() # the finalizer, in the child
        out
      },
      silent = TRUE
    )
    child <- parallel::mccollect(job, wait = TRUE)[[1]]

    # The child came back, with the documented terminal state.
    expect_type(child, "list")
    expect_true("zu_fork_error" %in% child$first)
    expect_true("zu_fork_error" %in% child$second)

    # The parent's body is intact: every byte, in order, after the child
    # tried to read, aborted and finalised it.
    rest <- list()
    repeat {
      piece <- zu_resp_read(r, 65536)
      if (length(piece) == 0L) {
        break
      }
      rest[[length(rest) + 1L]] <- piece
    }
    got <- c(first, unlist(rest))
    expect_identical(length(got), length(body))
    expect_identical(got, body)
  })
})

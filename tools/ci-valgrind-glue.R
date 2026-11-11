# The R glue under valgrind, on every pull request (review #164).
#
# src/init.c is the one file ctest and the fuzzers cannot reach: it needs R.
# It is also where the PROTECT stack, the unwinding of R callbacks (D-99),
# external-pointer finalizers and the pool's configuration cross from R into
# C, and W21's uninitialised keepalive fields there reached main on the quick
# profile and were found only by the full profile's valgrind (#136). This
# script drives each of those paths a few times, against a local webfakes
# server in a child process that is not itself under valgrind, and asserts
# what it can; tools/ci-valgrind-glue.sh runs it under valgrind and fails on
# any memory error whose stack passes through zuhttp.
#
# Run from the package root, with the package installed:
#   tools/ci-valgrind-glue.sh
suppressPackageStartupMessages(library(zuhttp))
check <- function(ok, what) {
  if (!isTRUE(ok)) {
    stop("check failed: ", what, call. = FALSE)
  }
  cat("ok   ", what, "\n")
}
web <- webfakes::local_app_process(webfakes::httpbin_app())
api <- zu_client(
  base_url = web$url(),
  pool = zu_pool(keepalive_time = 30, keepalive_timeout = 5)
)

# The pool and its configuration (#136, #152).
pc <- .Call(zuhttp:::C_zu_pool_config, zuhttp:::client_pool(api))
check(pc[["keepalive_time_ms"]] == 30000, "keepalive reaches C")
plain <- zu_client(base_url = web$url(), pool = zu_pool())
pc <- .Call(zuhttp:::C_zu_pool_config, zuhttp:::client_pool(plain))
check(pc[["keepalive_time_ms"]] == 0, "unset keepalive is zero in C")
for (i in 1:3) {
  invisible(zu_get("get", client = plain))
}

# A pulled body: read to the end, aborted, dropped unread, outliving its
# client (§65.4, the stream finalizer).
for (i in 1:3) {
  r <- zu_perform(zu_request("GET", "range/20000"), client = api, stream = TRUE)
  n <- 0
  while (length(p <- zu_resp_read(r, 3000))) {
    n <- n + length(p)
  }
  check(n == 20000, "a pulled body reads to its end")
  r <- zu_perform(zu_request("GET", "range/20000"), client = api, stream = TRUE)
  invisible(zu_resp_read(r, 10))
  zu_resp_abort(r)
  check(is.null(zu_resp_trailers(r)), "trailers unknown after abort")
  local(zu_resp_read(
    zu_perform(
      zu_request("GET", "range/20000"),
      client = api,
      stream = TRUE
    ),
    10
  ))
}
r <- local({
  tmp <- zu_client(base_url = web$url())
  zu_perform(zu_request("GET", "range/5000"), client = tmp, stream = TRUE)
})
invisible(gc())
check(
  length(zu_resp_read(r, 10000)) == 5000,
  "a pulled body outlives its client"
)
r2 <- unserialize(serialize(r, NULL))
e <- tryCatch(zu_resp_read(r2), error = function(e) e)
check(inherits(e, "zu_io_error"), "a dead stream pointer is zu_io_error")

# Callbacks and body functions that leave non-locally (D-99, §27.3).
for (i in 1:3) {
  v <- tryCatch(
    zu_get("stream/3", client = api, callback = function(x) warning("w")),
    warning = function(w) "caught"
  )
  check(
    identical(v, "caught"),
    "a callback's warning reaches the caller's handler"
  )
  v <- withRestarts(
    zu_get("stream/3", client = api, callback = function(x) {
      invokeRestart("out", 1L)
    }),
    out = function(x) x
  )
  check(identical(v, 1L), "a callback's restart is resumed")
  e <- tryCatch(
    zu_get("stream/3", client = api, callback = function(x) stop("boom")),
    error = function(e) e
  )
  check(
    identical(conditionMessage(e), "boom"),
    "a callback's error is the caller's"
  )
  k <- 0L
  f <- function() {
    k <<- k + 1L
    if (k < 50L) {
      raw()
    } else if (k == 50L) {
      charToRaw("body")
    } else {
      NULL
    }
  }
  r <- zu_perform(zu_body_stream(zu_request("POST", "post"), f), client = api)
  check(zu_resp_status(r) == 200L, "a chunked body with empty pieces is sent")
  v <- tryCatch(
    zu_perform(
      zu_body_stream(zu_request("POST", "post"), function() warning("w")),
      client = api
    ),
    warning = function(w) "caught"
  )
  check(identical(v, "caught"), "a body function's warning reaches the handler")
  req <- zu_req_path(
    zu_body_stream(zu_request("POST", "post"), function() NULL),
    file.path(tempdir(), "no", "such", "dir", "x")
  )
  check(
    inherits(
      tryCatch(zu_perform(req, client = api), error = function(e) e),
      "error"
    ),
    "an error before the engine runs"
  )
}
# A download whose commit fails after the engine succeeded: the target is a
# directory, so the final rename fails. init.c raised with the engine's
# result still owning its headers and strings, which valgrind reports as
# definitely lost through zuhttp (the bug hunt's ownership slice).
target <- file.path(tempdir(), "zu-valgrind-target")
dir.create(target, showWarnings = FALSE)
for (k in 1:3) {
  e <- tryCatch(
    zu_get("get", path = target, client = api),
    error = function(e) e
  )
  check(inherits(e, "zu_io_error"), "a download whose commit fails")
}
invisible(gc())
check(
  zu_resp_status(zu_get("get", client = api)) == 200L,
  "the client still works"
)
cat("done\n")

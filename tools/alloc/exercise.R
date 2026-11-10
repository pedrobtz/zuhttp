# The allocation-failure sweep's workload (#237; r-actions alloc-failure.yml).
#
# The sweep runs this once per allocation, failing a different one each time,
# R's own included. It is the one check that reaches native memory held
# across an R allocation that can longjmp: #214 leaked `got` in
# C_zu_stream_read exactly that way, past every C-only sweep, because those
# fail zuhttp's allocator and never R's.
#
# The workload is short, because the sweep multiplies it: one buffered
# Content-Length body, one chunked gzip body read through a stream in
# pieces (the #214 path), and one upload, against a loopback server started
# without the interposer. Every result is checked: a request that succeeds
# with the wrong bytes exits 3, which matches no expect-pattern, so the sweep
# reports it as a silent failure. A request that fails prints its condition
# class and exits 1.
#
#   Rscript tools/alloc/exercise.R             # the workload
#   Rscript tools/alloc/exercise.R --baseline  # everything up to the first request
suppressPackageStartupMessages(library(zuhttp))
baseline <- "--baseline" %in% commandArgs(TRUE)

# The server must not run under the interposer: a failure there is not ours.
portf <- tempfile("zu-alloc-")
system2(
  "env",
  c(
    "-u",
    "LD_PRELOAD",
    "-u",
    "ALLOC_FAIL_AT",
    "-u",
    "ALLOC_COUNT_FILE",
    "python3",
    "tools/alloc/server.py",
    portf
  ),
  wait = FALSE
)
for (i in 1:200) {
  if (file.exists(portf)) {
    break
  }
  Sys.sleep(0.05)
}
if (!file.exists(portf)) {
  cat("the loopback server did not start\n")
  quit(status = 2)
}
info <- scan(portf, quiet = TRUE)
on.exit(tools::pskill(info[2]), add = TRUE)
base <- sprintf("http://127.0.0.1:%d", info[1])
want <- as.raw((0:49999 * 7 + 3) %% 251)

done <- function(status) {
  tools::pskill(info[2])
  quit(status = status, save = "no")
}
if (baseline) {
  done(0)
}

run <- function(what, expr) {
  got <- tryCatch(expr, error = function(e) e)
  if (inherits(got, "error")) {
    cat(what, ": ", class(got)[1], ": ", conditionMessage(got), "\n", sep = "")
    done(1)
  }
  if (!identical(got, want)) {
    cat(what, ": WRONG RESULT, ", length(got), " bytes\n", sep = "")
    done(3)
  }
}

run("buffered", zu_resp_raw(zu_get(paste0(base, "/len"))))
run("streamed", {
  r <- zu_perform(zu_request("GET", paste0(base, "/chunked")), stream = TRUE)
  out <- raw()
  repeat {
    b <- zu_resp_read(r, 7000)
    if (!length(b)) {
      break
    }
    out <- c(out, b)
  }
  out
})
run("upload", zu_resp_raw(zu_post(paste0(base, "/echo"), body = want)))
cat("ok\n")
done(0)

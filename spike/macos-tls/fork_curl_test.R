suppressMessages(library(parallel))
ok <- function(lbl, expr) {
  r <- tryCatch(expr, error=function(e) paste("ERROR:", conditionMessage(e)))
  cat(sprintf("%-34s %s\n", lbl, if (is.character(r)) substr(r,1,60) else "ok"))
}
# 1. parent makes an HTTPS request first
ok("parent https request", { curl::curl_fetch_memory("https://example.com")$status_code; "ok" })
# 2. then fork
res <- tryCatch(
  mclapply(1:2, function(i) {
    tryCatch(curl::curl_fetch_memory("https://example.com")$status_code,
             error=function(e) paste("ERR:", conditionMessage(e)))
  }, mc.cores=2),
  error=function(e) paste("mclapply ERROR:", conditionMessage(e)))
cat("mclapply after parent request ->", paste(unlist(lapply(res, as.character)), collapse=" | "), "\n")

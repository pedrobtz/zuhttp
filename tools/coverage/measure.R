# Honest coverage: the R suite (with the local-server tests on) merged, line by
# line, with the offline C suite. See .github/workflows/coverage-union.yaml.
#
# The coverage badge measures only how much of the C core the R suite reaches,
# with NOT_CRAN unset — so every loopback test is skipped and the C suite,
# which exercises most of the core, is not counted at all. This counts both,
# per file, and fails when a figure falls below its committed floor.
#
# Usage: Rscript tools/coverage/measure.R CTEST.lcov
args <- commandArgs(TRUE)
lcov_path <- if (length(args)) args[[1]] else stop("usage: measure.R CTEST.lcov")
Sys.setenv(NOT_CRAN = "true")

cov <- covr::package_coverage(".", type = "tests", quiet = TRUE)
t <- covr::tally_coverage(cov, by = "line")
t$hit <- t$value > 0
key <- function(file, line) paste(basename(file), line)

# covr: one row per (file, line); a line counts if any expression on it ran.
r_hit <- tapply(t$hit, key(t$filename, t$line), any)
kind  <- ifelse(grepl("^R/", t$filename), "R",
         ifelse(grepl("^src/(zu_[^/]+|init)\\.c$", t$filename), "own C", "vendored C"))
kinds <- tapply(kind, key(t$filename, t$line), `[`, 1)

# ctest's lcov: DA:<line>,<count> per source file.
c_hit <- list()
cur <- NULL
for (l in readLines(lcov_path)) {
  if (startsWith(l, "SF:")) cur <- basename(sub("^SF:", "", l))
  else if (startsWith(l, "DA:") && !is.null(cur)) {
    p <- as.integer(strsplit(sub("^DA:", "", l), ",")[[1]])
    k <- paste(cur, p[1])
    c_hit[[k]] <- isTRUE(c_hit[[k]]) || p[2] > 0
  }
}

keys <- names(r_hit)
hit  <- vapply(keys, function(k) isTRUE(r_hit[[k]]) || isTRUE(c_hit[[k]]), logical(1))
d <- data.frame(file = sub(" .*", "", keys), kind = unname(kinds[keys]),
                r = unname(r_hit), hit = unname(hit), stringsAsFactors = FALSE)

pct <- function(x) round(100 * mean(x), 1)
by_file <- do.call(rbind, lapply(split(d, d$file), function(x) data.frame(
  file = x$file[1], kind = x$kind[1], lines = nrow(x),
  r_suite = pct(x$r), combined = pct(x$hit), missed = sum(!x$hit))))
by_file <- by_file[order(by_file$kind, -by_file$missed), ]

totals <- c(
  own_c    = pct(d$hit[d$kind == "own C"]),
  r        = pct(d$hit[d$kind == "R"]),
  own_c_r_suite_only = pct(d$r[d$kind == "own C"])
)

os <- if (Sys.info()[["sysname"]] == "Darwin") "macos" else tolower(Sys.info()[["sysname"]])
floors <- read.dcf(file.path("tools", "coverage", "floor.dcf"))
floor_of <- function(what) {
  f <- paste0(what, "_", os)
  if (f %in% colnames(floors)) as.numeric(floors[1, f]) else NA_real_
}

lines <- c(
  sprintf("## Coverage (%s)", os), "",
  "| Measure | % | Floor |", "|---|---|---|",
  sprintf("| Own C, R suite + C suite | %.1f | %s |", totals[["own_c"]], floor_of("own_c")),
  sprintf("| R | %.1f | %s |", totals[["r"]], floor_of("r")),
  sprintf("| Own C, R suite only (what the badge measures) | %.1f | — |", totals[["own_c_r_suite_only"]]),
  "", "<details><summary>Per file</summary>", "",
  "| File | Kind | Lines | R suite % | Combined % | Missed |", "|---|---|---|---|---|---|",
  sprintf("| %s | %s | %d | %.1f | %.1f | %d |", by_file$file, by_file$kind, by_file$lines,
          by_file$r_suite, by_file$combined, by_file$missed),
  "", "</details>")
cat(lines, sep = "\n")
summary_file <- Sys.getenv("GITHUB_STEP_SUMMARY")
if (nzchar(summary_file)) cat(lines, sep = "\n", file = summary_file, append = TRUE)

bad <- character()
for (what in c("own_c", "r")) {
  fl <- floor_of(what)
  if (!is.na(fl) && totals[[what]] < fl)
    bad <- c(bad, sprintf("%s coverage %.1f%% is below its floor %.1f%% (tools/coverage/floor.dcf)",
                          what, totals[[what]], fl))
}
if (length(bad)) { message(paste(bad, collapse = "\n")); quit(status = 1) }

#!/bin/sh
# Runs tools/ci-valgrind-glue.R under valgrind and fails on any memory error
# or definite leak whose stack passes through zuhttp (review #164). R itself
# and the libraries it loads have findings of their own that are not ours to
# fix, so the filter is on our frames: zuhttp.so, a zuh_ function, init.c,
# and the vendored nghttp2, picohttpparser and uriparser linked into it.
set -eu
LOG=${1:-valgrind-glue.log}
R -d "valgrind --leak-check=full --show-leak-kinds=definite --num-callers=40 \
      --track-origins=yes --log-file=$LOG" --vanilla -f tools/ci-valgrind-glue.R
awk '
  /^==[0-9]+== (Invalid (read|write|free)|Conditional jump|Use of uninitialised|Mismatched free|Syscall param|Source and destination overlap)|are definitely lost in loss record/ {
    if (blk != "" && ours) { print blk; bad++ }
    blk = $0; ours = 0; next
  }
  /^==[0-9]+== *$/ { if (blk != "" && ours) { print blk; bad++ } blk = ""; ours = 0; next }
  blk != "" { blk = blk "\n" $0; if ($0 ~ /zuhttp\.so|zuh_|init\.c|nghttp2_|phr_|uri[A-Z]/) ours = 1 }
  END { if (blk != "" && ours) { print blk; bad++ }
        if (bad) { printf "%d valgrind finding(s) in zuhttp\n", bad; exit 1 }
        print "valgrind: nothing in zuhttp" }
' "$LOG"

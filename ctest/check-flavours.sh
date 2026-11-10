#!/bin/sh
# #262: each build flavour links its own vendored objects. A plain build
# followed by `make asan` must link ASan-instrumented picohttpparser,
# uriparser and nghttp2 objects, and the other order must not link
# instrumented ones into the plain binary. Before #262 both orders reused
# whatever build/ held, so the vendored code ran unsanitised under `asan`
# and nothing failed.
#
# Reads the objects themselves, not make's plan: an instrumented object
# references the ASan runtime (__asan_*), a plain one does not.
set -eu
cd "$(dirname "$0")"

fail=0
asan_refs() { nm "$1" 2>/dev/null | grep -c '__asan_' || true; }

check() { # dir, want (yes|no)
  for o in "$1"/picohttpparser.o "$1"/UriParse.o "$1"/ng_nghttp2_session.o; do
    if [ ! -f "$o" ]; then
      echo "FAIL: $o was not built"; fail=1; continue
    fi
    n=$(asan_refs "$o")
    if [ "$2" = yes ] && [ "$n" -eq 0 ]; then
      echo "FAIL: $o is not ASan-instrumented"; fail=1
    elif [ "$2" = no ] && [ "$n" -ne 0 ]; then
      echo "FAIL: $o is ASan-instrumented in a plain build"; fail=1
    fi
  done
}

# A plain build first, then asan: the case that silently lost ASan.
make clean >/dev/null
make zuh_ctest >/dev/null
make zuh_ctest_asan >/dev/null
check build no
check build-asan yes
make -n zuh_ctest_asan | grep -q 'build/picohttpparser\.o' &&
  { echo "FAIL: zuh_ctest_asan links build/picohttpparser.o"; fail=1; }

# asan first, then plain: the case that failed to link.
make clean >/dev/null
make zuh_ctest_asan >/dev/null
make zuh_ctest >/dev/null
check build no
check build-asan yes

make clean >/dev/null
[ "$fail" -eq 0 ] && echo "build flavours keep their own vendored objects"
exit "$fail"

#!/bin/sh
# Line coverage of the offline C suite (ctest/zu_ctest), as lcov, for
# tools/coverage/measure.R to merge with the R suite's coverage.
#
# Clang source-based coverage: accurate per line and needs no gcov version
# matching. macOS uses the Xcode tools through xcrun; Linux needs `clang` and
# `llvm` (llvm-profdata, llvm-cov) on PATH.
#
# Usage: tools/coverage/ctest-lcov.sh OUT.lcov
set -eu
out=${1:?usage: ctest-lcov.sh OUT.lcov}
case "$out" in /*) ;; *) out="$(pwd)/$out" ;; esac
cd "$(dirname "$0")/../../ctest"

if [ "$(uname -s)" = "Darwin" ]; then
    cc="xcrun clang"; profdata="xcrun llvm-profdata"; llvmcov="xcrun llvm-cov"
else
    cc=clang; profdata=llvm-profdata; llvmcov=llvm-cov
fi

make clean >/dev/null
make zu_ctest CC="$cc -fprofile-instr-generate -fcoverage-mapping" >/dev/null
raw="$(mktemp -d)/ctest.profraw"
LLVM_PROFILE_FILE="$raw" ./zu_ctest >/dev/null
$profdata merge -sparse "$raw" -o "$raw.profdata"
$llvmcov export ./zu_ctest -instr-profile="$raw.profdata" -format=lcov \
    -ignore-filename-regex='(vendor|ctest)/' > "$out"
make clean >/dev/null
echo "wrote $out"

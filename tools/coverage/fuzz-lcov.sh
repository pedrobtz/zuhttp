#!/bin/sh
# Fuzz reach (#230): line coverage of the C core when every fuzz target
# replays its corpus, as lcov, with the total printed.
#
# A fuzzed line ran on hostile input; it was not checked for being right, so
# this number never joins measure.R's floors. It answers a different
# question: which input-handling code no fuzzer reaches at all. Its own
# floor, fuzz_reach in floor.dcf, catches a harness change that stops
# reaching something.
#
# Clang source-based coverage, as ctest-lcov.sh. The corpus defaults to the
# committed one; pass a soak-grown corpus (the soak job's artifacts) to see
# what longer fuzzing reaches.
#
# Usage: tools/coverage/fuzz-lcov.sh OUT.lcov [CORPUS_DIR] [FLOOR_PERCENT]
set -eu
out=${1:?usage: fuzz-lcov.sh OUT.lcov [CORPUS_DIR] [FLOOR_PERCENT]}
case "$out" in /*) ;; *) out="$(pwd)/$out" ;; esac
corpus=${2:-corpus}
case "$corpus" in /*|corpus) ;; *) corpus="$(pwd)/$corpus" ;; esac
floor=${3:-}
cd "$(dirname "$0")/../../fuzz"

if [ "$(uname -s)" = "Darwin" ]; then
    cc="xcrun clang"; profdata="xcrun llvm-profdata"; llvmcov="xcrun llvm-cov"
else
    cc=clang; profdata=llvm-profdata; llvmcov=llvm-cov
fi

targets=$(sed -n 's/^TARGETS := //p' Makefile)
prof=$(mktemp -d)
make clean-bin >/dev/null
make replay CC="$cc" REPLAY_FLAGS="-fprofile-instr-generate -fcoverage-mapping" >/dev/null
objs=""
for t in $targets; do
    n=$(find "$corpus/$t" -type f 2>/dev/null | wc -l | tr -d ' ')
    if [ "$n" = "0" ]; then echo "no corpus for $t" >&2; exit 1; fi
    find "$corpus/$t" -type f -print0 |
        LLVM_PROFILE_FILE="$prof/$t-%p.profraw" xargs -0 -n 500 ./replay_$t >/dev/null
    objs="$objs -object ./replay_$t"
done
$profdata merge -sparse "$prof"/*.profraw -o "$prof/all.profdata"
# shellcheck disable=SC2086
$llvmcov export $objs -instr-profile="$prof/all.profdata" -format=lcov \
    -ignore-filename-regex='(vendor|ctest|fuzz)/' > "$out"
make clean-bin >/dev/null
rm -rf "$prof"

# Lines with a count, over every source file of the core, as measure.R
# counts them: a line counts once however many targets reach it.
awk -F'[:,]' '
    /^SF:/ { f = $2 }
    /^DA:/ { k = f ":" $2; seen[k] = 1; if ($3 > 0) hit[k] = 1 }
    END {
        for (k in seen) n++; for (k in hit) h++
        printf "fuzz reach: %.1f%% of %d lines\n", 100 * h / n, n
    }' "$out" | tee "$out.summary"
if [ -n "$floor" ]; then
    pct=$(sed -n 's/^fuzz reach: \([0-9.]*\)%.*/\1/p' "$out.summary")
    if awk "BEGIN { exit !($pct < $floor) }"; then
        echo "fuzz reach $pct% is below its floor of $floor%" >&2
        exit 1
    fi
fi
echo "wrote $out"

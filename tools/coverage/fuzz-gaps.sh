#!/bin/sh
# What the fuzzers do not reach, as lists rather than a percentage.
#
# fuzz-lcov.sh prints one number. It cannot say which 34% of the core no
# fuzzer reaches, or which conditions a fuzzer reaches but only ever takes
# one way. #208 was a condition like that: every small upload took the
# combine branch, so the line was covered, and the window between 32 KiB
# and 64 KiB where it went wrong was not. This prints, from the lcov that
# fuzz-lcov.sh writes:
#
#   1. per file: lines, branch outcomes and functions the fuzzers reach;
#   2. functions no fuzzer enters, marked "ctest" when the C suite does;
#   3. one-sided conditions: lines a fuzzer ran where some branch outcome
#      was never taken;
#   4. lines no fuzzer reaches, as ranges, with the C suite's lines marked:
#      a line ctest runs and no fuzzer does is input-handling code that
#      only hand-written cases have tried, and is where a seed or an oracle
#      is missing.
#
# Nothing here fails: the floor is fuzz-lcov.sh's. With GITHUB_STEP_SUMMARY
# set, sections 1 and 2 also go to the job summary.
#
# Usage: tools/coverage/fuzz-gaps.sh FUZZ.lcov [CTEST.lcov]
set -eu
fuzz=${1:?usage: fuzz-gaps.sh FUZZ.lcov [CTEST.lcov]}
ctest=${2:-/dev/null}

# Paths in the two files are absolute and may differ by checkout, so files
# are matched from src/ on.
awk -F'[:,]' -v summary="${GITHUB_STEP_SUMMARY:-}" '
    function rel(p) { sub(/^.*\/src\//, "src/", p); return p }
    # FILENAME, not FNR: an empty ctest file has no first record.
    { pass = FILENAME == ARGV[1] ? 1 : 2 }
    /^SF:/ { f = rel(substr($0, 4)); if (pass == 2) files[f] = 1; next }
    pass == 1 && /^DA:/  { if ($3 > 0) c_line[f ":" $2] = 1; next }
    # A static function is named "file.c:name", so a name is everything
    # after the first comma, colons and all.
    function fname(r) { return substr(r, index(r, ",") + 1) }
    pass == 1 && /^FNDA:/ { if ($2 > 0) c_fn[f ":" fname($0)] = 1; next }
    pass == 1 { next }
    /^DA:/ {
        k = f ":" $2
        if (!(k in line)) { line[k] = 0; nl[f]++; if ($2 > maxl[f]) maxl[f] = $2 }
        if ($3 > 0 && !line[k]) { line[k] = 1; hl[f]++ }
        next
    }
    /^FN:/ {
        k = f ":" fname($0)
        if (!(k in fn)) { fn[k] = 0; nf[f]++; fnl[k] = $2 }
        next
    }
    /^FNDA:/ {
        k = f ":" fname($0)
        if ($2 > 0 && !fn[k]) { fn[k] = 1; hf[f]++ }
        next
    }
    /^BRDA:/ {
        k = f ":" $2 ":" $3 ":" $4
        if (!(k in br)) { br[k] = 0; nb[f]++ }
        if ($5 != "-" && $5 > 0 && !br[k]) { br[k] = 1; hb[f]++ }
        lk = f ":" $2
        if ($5 != "-" && $5 > 0) taken[lk] = 1; else untaken[lk] = 1
        next
    }
    function pct(h, n) { return n ? sprintf("%5.1f%%", 100 * h / n) : "    -" }
    function emit(s) { print s; if (summary != "") print s >> summary }
    END {
        nfiles = 0
        for (f in files) order[++nfiles] = f
        for (i = 2; i <= nfiles; i++)           # insertion sort: awk has none
            for (j = i; j > 1 && order[j - 1] > order[j]; j--) {
                t = order[j]; order[j] = order[j - 1]; order[j - 1] = t
            }

        emit("## Fuzz reach by file")
        emit("")
        emit("| file | lines | branch outcomes | functions |")
        emit("|---|---:|---:|---:|")
        for (i = 1; i <= nfiles; i++) {
            f = order[i]
            emit(sprintf("| %s | %s of %d | %s of %d | %d of %d |", f,
                 pct(hl[f], nl[f]), nl[f], pct(hb[f], nb[f]), nb[f],
                 hf[f], nf[f]))
            TL += nl[f]; TH += hl[f]; TB += nb[f]; TBH += hb[f]
            TF += nf[f]; TFH += hf[f]
        }
        emit(sprintf("| **all** | %s of %d | %s of %d | %d of %d |",
             pct(TH, TL), TL, pct(TBH, TB), TB, TFH, TF))
        emit("")

        emit("## Functions no fuzzer enters")
        emit("")
        emit("\"ctest\" marks the ones the C suite runs.")
        emit("")
        emit("```")
        for (i = 1; i <= nfiles; i++) {
            f = order[i]
            m = 0
            for (k in fn) if (index(k, f ":") == 1 && !fn[k]) miss[++m] = k
            for (a = 2; a <= m; a++)            # by line
                for (b = a; b > 1 && fnl[miss[b - 1]] > fnl[miss[b]]; b--) {
                    t = miss[b]; miss[b] = miss[b - 1]; miss[b - 1] = t
                }
            for (a = 1; a <= m; a++) {
                k = miss[a]
                emit(sprintf("%s:%d %s%s", f, fnl[k], substr(k, length(f) + 2),
                     (k in c_fn) ? "  [ctest]" : ""))
            }
        }
        emit("```")
        emit("")

        print "## One-sided conditions: a fuzzer ran the line, some outcome never"
        for (i = 1; i <= nfiles; i++) {
            f = order[i]; s = ""
            for (n = 1; n <= maxl[f]; n++) {
                lk = f ":" n
                if ((lk in taken) && (lk in untaken)) s = s " " n
            }
            if (s != "") print f ":" s
        }
        print ""

        print "## Lines no fuzzer reaches (* = ctest runs at least one line of the range)"
        for (i = 1; i <= nfiles; i++) {
            f = order[i]; s = ""; a = 0; b = 0; star = 0
            # A range runs over lines with no code (comments, blanks) and
            # ends at the next line a fuzzer reached.
            for (n = 1; n <= maxl[f] + 1; n++) {
                k = f ":" n
                if (n <= maxl[f] && !(k in line)) continue
                if (n <= maxl[f] && !line[k]) {
                    if (!a) { a = n; star = 0 }
                    b = n; star = star || (k in c_line)
                    continue
                }
                if (a) s = s " " (a == b ? a : a "-" b) (star ? "*" : "")
                a = 0
            }
            if (s != "") print f ":" s
        }
    }' "$ctest" "$fuzz"

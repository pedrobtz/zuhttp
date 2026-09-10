#!/bin/sh
# Regenerate the curated seed corpus (design §43, §50.3).
#
#   fuzz/seed-corpus.sh          (or: make -C fuzz reseed)
#
# Every seed is hand-written and explainable: a real protocol sample, a
# specific attack the design names, or a regression input for a bug that was
# actually found. Running libFuzzer locally also writes newly-discovered
# coverage units into corpus/, which is correct behaviour but must not be
# committed — this restores the curated set.
#
# The seeding is done in Python, not in shell. `printf '%b'` with \xNN hex
# escapes is a zsh/bash extension: dash (which is /bin/sh on Debian and
# Ubuntu) emits the four characters "\x00" instead of a NUL byte, so the
# shell version produced DIFFERENT seeds on Linux than on macOS — silently,
# and for exactly the binary seeds that matter most.
set -eu
cd "$(dirname "$0")"
exec python3 seed-corpus.py

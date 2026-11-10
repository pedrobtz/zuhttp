"""Deterministic mutants of the curated corpus (design §43, §50.3).

    python3 mutate-corpus.py [--n 3000] [--seed 0] [--out mut] [--max-bytes 262144]
    make -C fuzz mutate-asan        # generate, then replay under ASan + UBSan

libFuzzer is the tool that finds bugs, but it needs clang and its output
depends on the machine and the clock. This is the cheap, reproducible
complement: every curated seed in corpus/<target>/ is mutated with a PRNG
seeded from (--seed, target, seed-file name), so the same arguments produce
byte-identical mutants on every platform, and a finding can be named by its
file (mut/<target>/<seed>-<k>) and re-run alone with the replay driver.

The operators are the usual ones (bit flips, interesting bytes, insert /
delete / duplicate a span, truncate, splice two seeds) plus two that know
what HTTP looks like: a decimal token is replaced by an integer boundary
(0, -1, 2^31-1, 2^32, 2^64-1, 2^64, a 40-digit number) and a hex token by a
chunk-size boundary. One to four operators per mutant.

Nothing here is committed: mut/ is in .gitignore, and `make -C fuzz mutate`
regenerates it. A mutant that finds a bug is promoted by adding it to
corpus/<target>/regress-<name> through seed-corpus.py, with the explanation
every seed carries.
"""
import argparse
import os
import random
import re
import shutil
import sys

TARGETS = ("response", "chunked", "headers", "uri", "redirect", "inflate",
           "proxy", "redact", "body", "engine", "h2", "pull")

INTERESTING = bytes([0x00, 0x01, 0x7f, 0x80, 0xff, 0x0d, 0x0a, 0x20, 0x09,
                     0x3a, 0x3b, 0x2c, 0x3d, 0x25, 0x2f, 0x3f, 0x23, 0x40,
                     0x30, 0x39, 0x61, 0x66, 0x41, 0x46, 0x2d, 0x2b])

DEC_BOUNDARIES = (b"0", b"-1", b"1", b"2147483647", b"2147483648",
                  b"4294967295", b"4294967296", b"9223372036854775807",
                  b"18446744073709551615", b"18446744073709551616",
                  b"9" * 40, b"00000", b"+5", b"5 5", b"5,5", b"0x10")

HEX_BOUNDARIES = (b"0", b"7fffffff", b"80000000", b"ffffffff",
                  b"ffffffffffffffff", b"10000000000000000", b"f" * 40,
                  b"-1", b"1;a=b", b"1 ", b"G", b"")


def pick_span(rng, n):
    if n == 0:
        return 0, 0
    a = rng.randrange(n)
    b = min(n, a + rng.choice((1, 2, 4, 8, 16, 64, 256)))
    return a, b


def op_bitflip(rng, d, _):
    if not d:
        return d
    i = rng.randrange(len(d))
    d[i] ^= 1 << rng.randrange(8)
    return d


def op_byte(rng, d, _):
    if not d:
        return d
    d[rng.randrange(len(d))] = rng.randrange(256)
    return d


def op_interesting(rng, d, _):
    if not d:
        return d
    d[rng.randrange(len(d))] = rng.choice(INTERESTING)
    return d


def op_insert(rng, d, _):
    i = rng.randrange(len(d) + 1)
    k = rng.choice((1, 2, 4, 16, 64, 256, 1024))
    if d and rng.random() < 0.5:
        a, b = pick_span(rng, len(d))
        ins = d[a:b] * max(1, k // max(1, b - a))
    else:
        ins = bytes(rng.choice(INTERESTING) if rng.random() < 0.5
                    else rng.randrange(256) for _ in range(k))
    d[i:i] = ins
    return d


def op_delete(rng, d, _):
    a, b = pick_span(rng, len(d))
    del d[a:b]
    return d


def op_dup(rng, d, _):
    a, b = pick_span(rng, len(d))
    d[b:b] = d[a:b] * rng.choice((1, 2, 8))
    return d


def op_truncate(rng, d, _):
    if d:
        del d[rng.randrange(len(d)):]
    return d


def op_splice(rng, d, others):
    if not others:
        return d
    o = rng.choice(others)
    i = rng.randrange(len(d) + 1)
    j = rng.randrange(len(o) + 1)
    return bytearray(d[:i] + o[j:])


def _replace_token(rng, d, pattern, choices):
    toks = list(re.finditer(pattern, bytes(d)))
    if not toks:
        return d
    m = rng.choice(toks)
    d[m.start():m.end()] = rng.choice(choices)
    return d


def op_decimal(rng, d, _):
    return _replace_token(rng, d, rb"\d+", DEC_BOUNDARIES)


def op_hex(rng, d, _):
    return _replace_token(rng, d, rb"(?<![A-Za-z])[0-9A-Fa-f]{1,16}(?=\r\n)",
                          HEX_BOUNDARIES)


OPS = (op_bitflip, op_bitflip, op_byte, op_interesting, op_interesting,
       op_insert, op_delete, op_dup, op_truncate, op_splice, op_decimal,
       op_hex)


def mutate(rng, seed, others, max_bytes):
    d = bytearray(seed)
    for _ in range(rng.randint(1, 4)):
        d = rng.choice(OPS)(rng, d, others)
    if len(d) > max_bytes:
        del d[max_bytes:]
    return bytes(d)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=3000, help="mutants per target")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default="mut")
    ap.add_argument("--max-bytes", type=int, default=256 * 1024)
    ap.add_argument("--targets", default=",".join(TARGETS))
    args = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    corpus = os.path.join(here, "corpus")
    out = args.out if os.path.isabs(args.out) else os.path.join(here, args.out)
    total = 0
    for t in args.targets.split(","):
        src = os.path.join(corpus, t)
        names = sorted(f for f in os.listdir(src)
                       if os.path.isfile(os.path.join(src, f)))
        if not names:
            sys.exit("no seeds in %s" % src)
        seeds = {}
        for f in names:
            with open(os.path.join(src, f), "rb") as fh:
                seeds[f] = fh.read()
        dst = os.path.join(out, t)
        shutil.rmtree(dst, ignore_errors=True)
        os.makedirs(dst)
        # Round-robin over the seeds, so every seed gets ~n/len(names)
        # mutants, and one PRNG per seed, so adding a seed to the corpus
        # changes only that seed's mutants.
        rngs = {f: random.Random("%d:%s:%s" % (args.seed, t, f)) for f in names}
        for k in range(args.n):
            f = names[k % len(names)]
            others = [seeds[g] for g in names if g != f]
            data = mutate(rngs[f], seeds[f], others, args.max_bytes)
            name = "%s-%d" % (f, k // len(names))
            with open(os.path.join(dst, name), "wb") as fh:
                fh.write(data)
        total += args.n
        print("%-9s %5d mutants of %2d seeds -> %s" % (t, args.n, len(names), dst))
    print("%d mutants (seed %d)" % (total, args.seed))


if __name__ == "__main__":
    main()

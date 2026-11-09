<!-- Synced from pedrobtz/packages:claude/shared/correctness.md. Do not edit it
here: change it there, and the sync opens a pull request in every package. -->

# Bug families, and the tests that catch them

Rules for code that crosses a boundary it does not control: a wire protocol,
a file format, a vendored decoder, a subprocess, a C core under R. They come
from a measured gap. On 2026-11-09 three outside reviews of zuhttp found 16
wrong-result bugs, three of them release blockers, in code that had passed a
whole-package review, 2,500 C checks, its full R suite and 33,000 sanitised
fuzz inputs. None was upstream. Every one fell into one of four shapes, and
each shape names a test the suite did not have. Write that test first.

## The four families

1. **One variable, two meanings.** A value read after something else
   redefined it. A buffer length compared in an `else if` after the `if`
   condition grew it, so a 40 KB upload went out twice. A length that is
   "wire bytes" before a decoder runs and "decoded bytes" after, unless the
   decoder failed, so framing bytes reached the caller. A limit that means
   "decompressed" in one component and "compressed" in another. A flag that
   means "received" where "delivered to the caller" is needed. No side
   effects inside a condition; when a helper fails, state what its
   out-parameters mean afterwards, and check the result before using them.
2. **A resource outliving its owner.** A pointer, handle, socket, secret or
   deadline that lives longer than the frame, process or R call that made
   it. A struct keeping a pointer into a caller's stack frame that a
   callback reads later (stack-use-after-return). A connection inherited
   across `fork()`. Native memory held across an R allocation that can
   longjmp. A deadline the outer loop checks but an inner loop never sees.
   The guard usually exists on a sibling path already (a fork guard here,
   an unwind cleanup there, a PID on one backend): every pointer or handle
   a long-lived object retains states who owns it and how long it lives,
   and a new long-lived object gets every guard its siblings have, in the
   same pull request.
3. **The class fixed as an instance.** A guard present at one site and
   missing at its siblings: `x > .Machine$integer.max` checked for one
   count argument and not the others that go through `as.integer()`; a cap
   enforced under one framing and not the other. When a bug is fixed, grep
   for its siblings in the same commit, and the R layer validates whatever
   the C layer will coerce.
4. **The spec's second case.** The simple case handled, the specification's
   next case not: a header that may repeat (two `Content-Encoding` fields
   are a stack, not a duplicate); an identity of a different type (an IP
   literal is not a DNS name to X.509); a component the code forgets (a
   query appended after `#fragment`); a step that rewrites state (a 303
   changes the method the caller is later told). Refuse what is not
   supported, with a classed error. Silently handling the first half of a
   case and stripping the evidence is the bug.

## The tests these imply

- **Assert the other side.** For anything the package sends or writes, the
  test records what arrived and asserts on those bytes. A real server reads
  `Content-Length` and discards the rest; a real reader stops at the
  declared size. The client's or writer's own view proves nothing.
- **Straddle every threshold.** For each constant in the code (a combine
  limit, a header cap, a chunk size, a decompressed-size cap) test
  `limit - 1`, `limit` and `limit + 1`, and the sizes where two limits
  interact. Round numbers miss the window.
- **Differential.** Two inputs the specification calls equivalent (the same
  payload under two framings, an encoding spelled two ways, a URL with and
  without a fragment, a gzip stream with one member or two) must give the
  same result. A difference is a finding before anyone knows which side is
  right.
- **State-transition sequences.** Every object with a lifecycle (a stream, a
  connection, a parser handle, a retry loop) gets the out-of-order
  sequences: read then abort then read, abort after the input ended but
  before the caller had everything, fork with it open, a retry decision
  after the budget is spent. Assert the documented terminal state, not
  "no crash".
- **What the caller got before the error.** Feed the parsers input that
  fails mid-way and assert what was delivered before the error: a callback
  that saw framing bytes, a sink holding half a body, a data frame with a
  partial row. "It raised" is not the test; "it raised and delivered
  nothing" is.
- **A limit, a count or a state needs an oracle.** Fuzzing, mutation runs
  and sanitizers prove "no crash". A doubled byte count, an inconsistent
  limit or a readable aborted stream never trips them. Offer a fuzz run as
  evidence of robustness, never of correctness; the correctness claim needs
  a comparison.
- **Sanitise every backend you ship.** If the package selects a library or
  backend per platform, each one builds under ASan + UBSan somewhere in CI,
  and the ones that cannot are listed as unverified, not as passed.
  Peer-initiated behaviour (renegotiation, early close, an interleaved
  message) comes from a scripted loopback counterpart, since no real
  counterpart does it on demand.

## Reviews

A code-reading review is not an adversarial one. A stage that touches a
boundary or a lifetime is reviewed by running a byte-scripted counterpart
against it, not only by reading the diff. `pkg-critical-review`'s behaviour
pass does this for the whole package at the Review stage; a stage pull
request does it for what the stage added. "The tests pass" is where the
review starts, not what it finds.

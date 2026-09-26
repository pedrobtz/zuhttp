# zuhttp 0.1.0 — architecture review

**Date:** 2026-09-26
**Question asked:** is the approach sound and correct, and is the architecture
flexible enough to absorb the features planned for later releases?
**Scope:** every file under `src/`, `R/`, `ctest/`, `fuzz/`, `tools/`,
`.github/workflows/`, the `configure` scripts, and design edition 2 with its
Decision Register and the roadmap. Claims about C behaviour were checked by
running the C suites in this container (below). R is not installed here, so
R-level findings come from reading the code, not from executing it; each cites
the line it rests on.
**Companion:** this file records the findings. It changes neither the design
nor the roadmap; the "Recommended changes to the roadmap" section lists what
should move into them, so that the append-only findings log gets one dated
entry pointing here.

---

## 1. Verdict

The architecture is sound, and it is the right shape for what the design says
zuhttp will become. The four load-bearing choices are correct and already
tested where they matter:

1. **The stream vtable (§9)** is five functions with a deadline and an error
   on every call. Nothing above it names a socket or a TLS type, nothing below
   it knows HTTP, and TLS *wraps* a stream rather than owning a file
   descriptor, so the CONNECT tunnel, the mock and the planned dialled backend
   (D-71) all sit on the same seam.
2. **Engine and trust are separated (§13.1)** on all three backends, and the
   D-56 refusal is one function called before any I/O from both R and every
   `zu_tls_connect`.
3. **The dial seam (D-72)** drives the whole engine, proxy routing and pool
   included, offline and under the fuzzer. That is what makes the C core
   testable without R and is the single best property the codebase has.
4. **The R layer is thin and policy lives in R.** One request model behind
   three API levels, a three-state merge that is implemented and tested
   non-vacuously, redaction with one definition in C applied at each egress,
   middleware and retry composed as closures, and a transport generic that
   makes mock and cassette first-class.

The weaknesses are real but concentrated. In C they are all in one place: the
hand-rolled per-hop cleanup in `zu_engine_perform`, which has thirteen exit
paths and, as its own comment predicts, one of them leaks. In R they are
contract gaps in what a middleware or a derived client may do, plus four
concrete bugs. In CI two gates exist but do not fire. None of it is
structural; none of it needs a redesign.

**Flexibility, plainly stated.** The architecture is designed for synchronous
HTTP/1.1 and is extensible *within* that: phase timeouts, cancellable DNS, a
dialled macOS backend, custom CAs and pinning on the other backends, cookies,
multipart and auth helpers all land as additions to existing seams. Two
features would not be additions. Asynchronous requests would turn the engine
into a resumable state machine, and HTTP/2 would need a protocol layer between
the pool and the engine. The design already says both are out of scope before
1.0 (D-67, §60), and that is the honest position: they are a second engine,
not a feature of this one.

---

## 2. What was verified by running

| Command | Result |
|---|---|
| `make -C ctest strict` | 1630 checks, 0 failures, 0 warnings under `-Werror`; 3907 allocs / 3907 frees / 0 live |
| `make -C ctest asan` | 1630 / 0, no ASan or UBSan report |
| valgrind, as `c-core.yaml` runs it | 0 errors, all heap blocks freed |
| `make -C fuzz replay-run` | 10 targets, 138 seeds, no crash |
| `tools/check-feature-macros`, `check-objects-sync`, `check-vendor-licenses` | all pass |
| `R CMD INSTALL .`, `tools/ci-run-tests.R` | **not run**: no R in this container |
| `make -C fuzz fuzz-run` | not run: the container's clang has no libFuzzer runtime |

The proxy leak in finding C-1 was reproduced with a scratch probe linked
against the ctest objects: a direct request ends with 0 live blocks; the same
request with `proxy = "http://u:p@proxy.test:3128"` ends with 5 live blocks,
including the password.

---

## 3. How each planned feature lands

| Feature | Owner | Where it goes | Invasiveness |
|---|---|---|---|
| Phase timeouts (`connect`, `read`, `write`) | W7 | `zu_get_opts` fields, per-hop deadline in `open_stream`, `zu_net_opts` | Low, once the hop cleanup (C-4) is done first |
| Network.framework dialling on macOS | W13 | ~15-line branch in `open_stream` before the TCP connect, plus resolving C-3 | Low |
| Cancellable DNS on a helper thread | W14 | `zu_net.c` only: `wait_ready` generalised to poll a pipe | Low; watch the non-atomic `zu_alloc` counters (C-7) |
| Windows custom CAs, pinning on macOS/Windows | W8, W9 | inside the backend files; the D-56 caps mask already gates them | Low |
| `zuhttp_error` root, export trim | W3 | `zu_error.c` class chain (bump `ZU_CLASS_CHAIN_MAX`), NAMESPACE | Low |
| Cookies, multipart, auth helpers | later | new request fields + `zu_req_*` transformers; the accessors are the contract | Low |
| Streaming request bodies | post-1.0 | needs a body-source vtable in C mirroring `zu_sink`; today a "file" body is a raw vector (R-10) | Medium |
| HTTP/2 | §60, not planned | a protocol layer between pool and engine; the pool hands out connections, not streams | High: a second engine |
| Async via `later` | D-67, post-1.0 | the vtable permits it (`WOULDBLOCK` means retry); the engine's per-hop stack state does not | High: a rewrite of `zu_engine.c` |

Two flexibility costs are worth naming because they grow with every feature:

- **The R↔C boundary is one `.Call` with 18 positional arguments**
  (`src/init.c:590-595`, `R/perform.R:79-98`). W7 alone adds three. A single
  named-list `options` argument decoded in C would stop each feature from
  widening the ABI and re-ordering call sites.
- **`zu_get_opts` is a flat struct of 20 fields.** That is fine in C because
  `zu_get_opts_init()` zeroes it and a zeroed field means "default", but the
  same discipline has to hold for every addition.

---

## 4. Findings

Severity is about consequence for a user of 0.1.0, not about effort. Every
finding names the line it rests on and what it would take to fix.

### Fix before tagging 0.1.0

These are small, and each is either a credential exposure, a leak, or a
correctness claim the package makes and does not keep.

**C-1 (Medium, confirmed) — every successful proxied request leaks the `zu_proxy`, password included.**
`px` is initialised per hop (`src/zu_engine.c:549`) and freed on every error
path and on the redirect `continue` (`:847`), but not on the final `break`
(`:861`), the flush-failure return (`:859`), the no-`Location` break (`:802`)
or the unresolvable-`Location` return (`:807-810`). The offline suite misses
it because its proxied successes end on a `NO_PROXY` host. Beyond the leak,
proxy credentials left on the heap are a §42 concern.
*Fix:* `zu_proxy_free(&px)` before the final `break` and on the two early
returns; a mock test whose final hop is proxied asserting `live_blocks == 0`.

**C-2 (Medium) — the OpenSSL pool liveness probe cannot see unprocessed ciphertext.**
`tls_readable` (`src/zu_tls_openssl.c:272-278`) checks `SSL_pending()` then
the socket. `fill_in` reads 16 KiB at a time, so a `close_notify` that
arrived in the same segment as the last body record sits in `rbio`, invisible
to both. The pool then reuses a dead connection and the next request fails
with `zu_http_parse_error` instead of being retried transparently. Schannel
gets this right (`src/zu_tls_schannel.c:461`).
*Fix:* `|| BIO_ctrl_pending(t->rbio) > 0`. One line.

**R-1 (High) — proxy credentials print unredacted from three egresses.**
`print.zu_client` formats every policy field including `proxy`
(`R/client.R:313-318`); `print.zu_request` does the same for
`x$resolved$proxy` (`R/request.R:324-330`); a condition's
`request$resolved$proxy` is stored as-is because `redact_request()` touches
only headers, URL and form body (`R/response.R:507-515`).
`zu_get(url, proxy = "http://u:hunter2@corp:3128")` prints the password.
`default_client_report()` in `R/info.R:216` already redacts it, so the
pattern exists.
*Fix:* redact `proxy` in those three places; add a proxy arm to the
`test-redact.R` canaries.

**R-2 (High) — `timeout` is not the total budget D-18 promises.**
Each retry attempt is handed the full `p$timeout` (`R/perform.R:87`); only
the sleep between attempts is budget-checked (`:319-320`). With a slow origin,
`timeout = 30, attempts = 3` can run past 90 s. `attempt_timeout` in
`zu_retry()` is validated and printed (`R/retry.R:45-91`) and never read
anywhere else. `test-retry.R:237` passes because the mock returns instantly,
which is exactly the vacuous pass rule 6 warns about.
*Fix:* pass `min(remaining budget, attempt_timeout)` to the transport per
attempt; a W4 slow-server test that fails without it.

**R-3 (Medium) — `zu_client_update(x, field = NULL)` deletes the field.**
`client[[nm]] <- changes[[nm]]` (`R/client.R:200`) removes the element when
the value is `NULL`; the next `zu_client_update(x2, timeout = 5)` then fails
at the `setdiff(names(changes), names(client))` check (`:189`) with "not a
client setting: timeout".
*Fix:* `client[nm] <- list(changes[[nm]])`, and validate against
`names(formals(zu_client))` rather than `names(client)`.

**R-4 (Medium) — derived clients with a different pool config thrash one pool slot.**
`zu_client_update()` shares the `pool_state` environment (`R/client.R:166`),
and `client_pool()` recreates the pool whenever the stored config is not
`identical()` to the client's (`R/pool.R:96-103`). After
`zu_client_update(api, pool = zu_pool(max_idle = 2))`, parent and child
alternately overwrite the pointer, each request opens a fresh pool and orphans
the old one until GC. `zu_pool_stats()` would show it.
*Fix:* a derived client whose `pool` changed gets its own environment, or the
environment keys pools by config.

**CI-1 (High) — the `--as-cran` gate is vacuous.**
`R-CMD-check.yaml:126-129` runs the check with `|| true` and then greps for
`^(WARNING|ERROR)`. `00check.log` puts the status at the *end* of a line
(`* checking ... WARNING`) and the summary as `Status: 1 WARNING`, so the
pattern never matches and the job is green on any warning or error. The
comment above it says "the guard is vacuous"; it still is.
*Fix:* `grep -E '\.\.\. (WARNING|ERROR)$|^Status:.*(WARNING|ERROR)'`, and
break it once to see it fail.

**CI-2 (Medium) — a floating tag with write permission.**
`coverage.yaml:53` uses `pedrobtz/r-actions/...@v1` with `contents: write`;
a moved tag in another repository can commit to this one. W1 lists the SHA
pin; it is one line and belongs before the tag.

### W1: CI on pull requests

**CI-3 (High, confirmed) — five of seven workflows skip same-repo pull requests.**
`R-CMD-check.yaml:29,90`, `c-core.yaml:34,130`, `fuzz.yaml:45,85`,
`coverage.yaml:52` and nine jobs in `tls-spike.yaml` carry the fork-only
`if:`, and `push` fires only on `main`/`develop`, where `develop` does not
exist on the remote. `coverage-union.yaml` and `pkgdown.yaml` do run on PRs,
so CLAUDE.md's "every job skips" is slightly overstated. The double-run the
guard was added for is already prevented by the `concurrency` groups.
*Fix:* delete the `if:` lines. Nothing else in W1 needs to land first.

**CI-4 (Medium) — no job runs the R network suite on Windows.**
The `slice-r` matrix in `tls-spike.yaml:263` is ubuntu and macOS;
`slice-schannel` runs a three-assertion script (`:437-461`). The §50.5
certificate matrix and the proxy helper skip on Windows. W8 ports the matrix,
but no package owns proxy, redirect, pool or interrupt on Schannel.
*Fix:* add `windows-latest` to `slice-r` now, independent of W8.

**CI-5 (Medium) — `tls-spike.yaml` breaks the repo's own rules.**
`:73` carries `continue-on-error: true`, which CLAUDE.md forbids; the S0/S1
spike probes re-run on every push to `main` though their findings are
recorded; eight jobs depend on example.com and badssl.com, so third-party
flakiness reddens `main`.
*Fix:* S0/S1 to `workflow_dispatch` only; drop the `continue-on-error`.

**CI-6 (Low) — "verify non-vacuously" is enforced mechanically in three places only.**
`ci-fork-guard.R`, the empty-corpus check and the stray-objects check each
fail on a skip; nothing else does, and CI-1 is what that looks like.
*Fix:* a floor on check counts (ctest's `checks` line, testthat per-file
counts) beside the coverage floors.

### W2 and W3: while nothing depends on the package

**C-4 (Medium, structural) — `zu_engine_perform` is a 330-line loop with thirteen hand-copied cleanup sequences.**
`src/zu_engine.c:552-682` repeat `zu_request_free; zu_stream_free;
zu_uri_free; zu_result_free; zu_proxy_free` in varying order; the comment at
`:210-215` predicts that "the thirteenth path leaks", and C-1 is that path.
Redirect decision, credential stripping, proxy header injection, redirect-body
drain, reuse decision and sink flush are all inline. The *modules* compose
well (proxy, redirect, body, pool, sink are separate and mock-tested); the
orchestration does not. W7, W13 and any future retry-in-C each add paths here.
*Fix:* a `hop` struct owning `px, rq, resp, raw, wire, absform, pipe, s` with
one `hop_free()` and a single exit label. About a day, no behaviour change,
and the mock suite already covers it. Do it right after W2, not before, to
avoid a two-way merge with the rename.

**C-3 (Medium, contract) — the stream header and the pool disagree on `readable == -1`.**
`src/zu_stream.h:52` says callers must treat `-1` as "unknown, never fine to
reuse"; `src/zu_pool.c:222-236` treats `-1` as not stale and reuses, and
design §26.2 blesses that for dialled streams. With W13 this becomes the live
path on macOS.
*Fix:* make the header match §26.2, or give the vtable an explicit "no probe,
trust the idle timeout" flag rather than inferring it from `-1`.

**R-5 (Medium, contract) — middleware receives a resolved request on which the public transformers silently no-op.**
The transport reads `req$resolved`, `req$url` (query already folded),
`req$pool` and `req$path` (`R/perform.R:79-98`). A middleware that calls
`zu_req_timeout()` or `zu_query()` mutates `policy` and `query`, which
nothing reads after `resolve_request()`. `test-retry.R:289` only exercises
header and URL mutation. The same undocumented fields are what a third-party
transport would depend on, which is why D-65's move of the transport generic
to internal is right.
*Fix:* document that middleware may change `url`, `headers` and `body` only
and enforce it, or re-resolve the middleware's output; keep
`zu_transport_perform` unexported until the contract is written down.

**R-6 (Medium) — form bodies reach hook payloads unredacted.**
`redact_payload()` (`R/middleware.R:74-89`) redacts URL and headers but not
`p$request$body`; `redact_request()` in `R/response.R:512` does. The hook
canary in `test-redact.R:262` uses a GET with no body, so the gap is
untested, which is the §42.4 "new egress without a canary arm" defect.
*Fix:* call `redact_request()` from `redact_payload()`; add a form-body arm.

**R-7 (Medium) — cassettes store JSON request bodies and every response body verbatim.**
Only `x-www-form-urlencoded` bodies are redacted (`R/record.R:266-270`). A
token endpoint's `{"access_token": …}` response or a JSON login body is
written to a fixture meant to be committed. This is spec-compliant (§42.1
lists query and form only) and it is the highest-value leak in the package.
`.rds` cassettes are also not human-diffable, which weakens "review the
fixture before committing".
*Fix:* a `filter = function(interaction)` argument on
`zu_cassette_transport()`, and say the JSON gap out loud in the docs.

**R-8 (Low) — level-3 composition cannot set what level 1 can.**
`zu_get()` accepts `verify`, `max_body`, `user_agent`, `decode`, `proxy` and
`tls`; there is no `zu_req_*` transformer for any of them
(`R/request.R:285-307` has timeout, redirects and check only). `zu_query()`
and `zu_headers()` also lack the `zu_req_` prefix every other transformer
carries, and `R/redact.R:122` documents a `zu_req_headers()` that does not
exist.
*Fix:* one `zu_req_policy(req, ...)` taking the same names as `zu_get()`
through `collect_policy()`; fix the doc.

**R-9 (Low) — export surface.**
75 exports is large for a 0.1.0 and D-65's 17 cuts are right. Candidates to
add to the list: `zu_body_rewindable` and `zu_req_replay_safe` (retry
internals surfaced because §33.1 names them), `zu_tls_backend` (subsumed by
`zu_info()`), `zu_default_client`. `zu_error_codes()` also exposes `zu_ok`,
`zu_closed` and `zu_wouldblock` (`src/init.c:260-271`), so
`zu_condition("zu_ok", …)` builds a nonsense condition. Codes are enum
positions with no test pinning the numbers.
*Fix:* stop the export at `ZU_ERR_IO`; pin a golden code table in a test.

**C-6 (Low) — the error-code table has no size guard and a tight chain limit.**
`k_class[ZU_CODE_COUNT]` (`src/zu_error.c:136`) is positional; a missing
entry compiles and yields NULL, which `Rf_mkChar` will crash on.
`ZU_CLASS_CHAIN_MAX 4` (`src/zu_error.h:96`) is exactly leaf, parent,
`zu_error`, `zuhttp_error` once W3 lands; anything deeper truncates silently.
*Fix:* designated initialisers with a static assert; chain max 8.

### Later, or as the owning work package reaches them

**C-5 (Low) — observability fields are stale on pooled connections.**
`open_stream` returns on a pool hit (`src/zu_engine.c:341-355`) before
`proxy_used` and `remote_ip` are set (`:375-387`), so a reused connection
reports the previous hop's proxy flag and a stale or NULL address. Timings
are handled honestly (`-1`); these two are not.
*Fix:* store both in the pool entry.

**C-7 (Low, forward-looking) — `zu_alloc` counters are non-atomic globals.**
Fine today. D-59's DNS helper thread "frees its own block"; if that block
comes from `zu_alloc`, W14 introduces a data race on the stats. Also,
`SSL_CTX_new` plus `SSL_CTX_set_default_verify_paths` run per connection
(`src/zu_tls_openssl.c:141,317`), re-parsing the system store on every
handshake; pooling hides it and W18's benchmark will not.
*Fix:* the helper thread uses raw `malloc`; cache the `SSL_CTX` per trust
configuration.

**C-8 — D-69 confirmed.** The ratio limit is implemented
(`src/zu_inflate.c:341-355`) and passed as `0` at `src/zu_body.c:35`. W6.

**BUILD-1 (Medium) — `configure` does not do what §47.3 says, and has no override.**
The design says it "respects `PKG_CPPFLAGS`/`PKG_LIBS`"; `configure:63-76`
reads neither, nor R-exts' `INCLUDE_DIR`/`LIB_DIR`, and a user cannot pick
the backend (OpenSSL on macOS for conda R, say). `pkg-config --exists
openssl` accepts 1.0.2 and LibreSSL; only the `SSL_set1_host` probe stands
between the build and a stack `SystemRequirements` does not promise. zlib is
never probed.
*Fix:* honour `INCLUDE_DIR`/`LIB_DIR`; `pkg-config --atleast-version=1.1.1`;
a `ZUHTTP_TLS=openssl` escape hatch; rewrite §47.3 to match.

**BUILD-2 (Low) — `Depends: R (>= 3.5)` is untested and probably false for the suite.**
The matrix bottoms at `oldrel-1`; the test helpers spawn `serverSocket()`,
which is R 4.0 (`tests/testthat/helper-origin.R:25`).
*Fix:* raise to R >= 4.0 or add an `oldrel-4` leg.

**BUILD-3 (Low) — hand-maintained source lists.**
`check-objects-sync` compares only the two Makevars; `ctest/Makefile:43-50`,
`fuzz/Makefile:187-196` and `tools/update-uriparser:27` can drift silently.
`.gitignore` covers six of the ten `fuzz_*` binaries. `.Rbuildignore:10-13`
carries `#` comment lines in a file with no comment syntax (they happen to
match nothing).
*Fix:* derive the lists from `$(wildcard ../src/zu_*.c)` minus backends.

**R-10 (Low, forward-looking) — a "file" body is a raw vector.**
`zu_body_file()` reads the whole file into memory (`R/request.R:252-257`)
while §28.1 and §28.2 describe a stat-ed, rewindable file source; `body_kind
= "file"` on a raw body is a label the `body_rewindable` field will have to
unpick when streaming bodies arrive. Streaming uploads need a body-source
vtable in C mirroring `zu_sink`.

**R-11 (Low) — smaller R items.**
`R/methods.R:391-392` says `retry = NULL` inherits; it resets.
`backoff_delay()` uses `stats::runif` (`R/retry.R:354`) and perturbs the
user's RNG stream. `parse_retry_after()` flips `LC_TIME` globally
(`R/retry.R:332-335`). `url_with_query()` appends after a `#fragment`
(`R/url.R:213`); `join_url()` drops a query on `base_url` (`R/url.R:164`).
`print.zu_response` on a response from calling
`zu_transport_perform.zu_native_transport` directly, as the exported example
invites, errors on `is.na(NULL[["total"]])` (`R/response.R:532`).
`zu_redact_headers()` and `zu_redact_params()` replace the previous extras
rather than accumulate (`R/redact.R:447-451`), contrary to their wording.

**DOC-1 — drift.**
`src/zu_engine.h:1-20` still describes the §63.2 slice ("GET only, one
redirect; not here: proxies, retries, streaming sinks") while the struct
below it carries proxy, pool, sink and dial. CLAUDE.md says six workflows;
there are seven. Design §47.2's `SystemRequirements` text differs from
`DESCRIPTION`. In a codebase whose comments cite the design 1,100 times,
stale citations cost more than in most.

---

## 5. Recommended changes to the roadmap

- **M0, before the tag:** C-1, C-2, R-1, R-2, R-3, R-4, CI-1, CI-2. All are
  small; R-1 and C-1 are credential exposures, and R-2 is a promise the
  README makes.
- **W1:** add CI-1 and CI-2 to its exit criteria explicitly; CI-3 is its
  first step and needs nothing else first. Add CI-4 (a Windows leg for the R
  network suite) and CI-5.
- **W2:** the rename also hits `tools/check-feature-macros:21`,
  `tools/coverage/measure.R:22`, `.gitignore`, `tools/update-uriparser:78` and
  both test Makefiles; list them in the exit criteria or the coverage
  classification breaks silently. Measured size: 426 unique identifiers,
  about 7,700 occurrences, 51 files named `zu_*`, 15 `C_zu_*` `.Call` names.
- **New, right after W2:** the hop-struct refactor (C-4) and C-3, before W7
  and W13 add paths to the same loop. Consider folding the 18-argument
  `.Call` into a named-list options argument in the same package, since W7
  is the next thing that widens it.
- **W3:** R-5 (write the middleware contract), R-6, R-9's extra removals,
  C-6.
- **W4/W7:** R-2's slow-server test is the first W4 test to write.
- **W13:** `ctest/Makefile:140-147` (`engine-st`), `tls-spike.yaml:320-357`
  and `ci-fork-guard.R:18` are keyed to Secure Transport; name their
  replacement in the exit criteria.
- **W16:** §52 lists Linux arm64 and CRAN's non-x86_64 platforms; no leg or
  R-hub run exists. BUILD-1 and BUILD-2 belong here too.
- **Cassettes (R-7):** either the `filter` argument lands in W3 or the
  roadmap's scope cut 4 (unexported, experimental) is taken now, before
  anyone commits a fixture.

---

## 6. What this review did not do

It did not run the R suite, so R-1 to R-11 are readings of the code with the
line cited, not observed failures. It did not run libFuzzer. It did not
measure anything §51 asks for. It did not review the macOS or Windows
backends on their own platforms; those files were read for structure and for
the D-56 gate only.

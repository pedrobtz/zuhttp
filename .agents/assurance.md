# Assurance

How this package meets `.claude/shared/assurance.md`. CI checks this
file (r-actions `assurance.yml`), so keep the headings and table
columns as they are.

- **Statuses:** a cell is a fact, `gap #<issue>` or `n/a: <reason>`.
- Written 2026-11-10 by `pkg-assurance` from the code at `eb94958`. Every
  row names a test that was read for its assertion; a design section that
  promises a check is not counted.

## Kinds

`compiled` `untrusted-input` `spec` `lifecycle` `emits`

The evidence for each kind is in the pull request that added this file
(the C core, server bytes, the RFCs it implements, pools and pulled
bodies, requests and cassettes).

## Required checks

`Where` names the workflow file under `.github/workflows/` that runs the
check. Add `(own)` when that workflow is the package's own rather than a
call to r-actions.

<!-- markdownlint-disable MD013 -->
| Check         | Status   | Where                                                                                                                                                                                                                       |
| ------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| sanitizers    | done     | native-checks.yaml                                                                                                                                                                                                          |
| valgrind      | done     | native-checks.yaml                                                                                                                                                                                                          |
| rchk          | done     | native-checks.yaml                                                                                                                                                                                                          |
| gctorture     | done     | native-checks.yaml                                                                                                                                                                                                          |
| analyzers     | done     | native-checks.yaml                                                                                                                                                                                                          |
| alloc-failure | gap #237 | ctest sweeps `zuh_alloc_fail_after()` over the C core (#107, #188), but no workflow fails R's allocations under `C_zu_perform`; #214 was one                                                                                |
| mutation      | gap #238 | not called: `ctest/Makefile` builds `zuh_ctest` in one compile command, and Mull needs one `-c` per source                                                                                                                  |
| fuzz          | gap #239 | fuzz.yaml (own): 12 targets, corpus replay on every OS, libFuzzer smoke, weekly soak. Nine targets carry oracles; `fuzz_response`, `fuzz_chunked` and `fuzz_headers` fail only on a crash                                   |
| fuzz-reach    | done     | coverage-union.yaml (own): `tools/coverage/fuzz-lcov.sh` over the committed corpus against `fuzz_reach` in `tools/coverage/floor.dcf` (64%), and `tools/coverage/fuzz-gaps.sh` uploads the gap lists, on every pull request |
<!-- markdownlint-enable MD013 -->

## Boundaries

One row per boundary the package crosses. An oracle knows the answer:

- a conformance suite or test vectors;
- a reference implementation;
- a round trip;
- equivalent inputs compared;
- the bytes the other side received.

Hand-written expected values are listed where they are what there is;
they know the answer only for the cases someone thought of.

<!-- markdownlint-disable MD013 -->
| Boundary                                   | Oracle                                                                                                           | Carried by                                                            |
| ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| HTTP/1.1 response head, decode             | hand-written cases; one-shot and byte-at-a-time parses compared                                                  | ctest/test_response.c, tests/testthat/test-engine-live.R              |
| HTTP/1.1 response head and chunked, decode | Python `h11` parses the same bytes; status, fields, body and accept/reject compared                              | gap #240                                                              |
| HTTP/1.1 response, decode                  | libcurl (R `curl`) fetches the same raw-server script; status, headers and body compared                         | gap #241                                                              |
| Response framing decision                  | the RFC 9112 §6.3 table, one hand-written case per row                                                           | ctest/test_framing.c                                                  |
| Chunked response body and trailers, decode | the same payload under Content-Length, chunked and close compared; whole and byte-wise reads compared            | fuzz/fuzz_body.c, ctest/test_body.c, ctest/test_response.c            |
| HTTP/1.1 request and upload, emit          | the bytes on the mock wire, at sizes straddling the 64 KiB combine (#208)                                        | ctest/test_engine_mock.c, fuzz/fuzz_engine.c                          |
| HTTP/1.1 request, emit                     | libcurl sends the same request to the raw server; the recorded bytes compared                                    | gap #241                                                              |
| Chunked upload, emit                       | `h11` (hypercorn) parses it; `/check` asserts byte count and order                                               | tests/testthat/test-http2.R, ctest/test_engine_mock.c                 |
| Header field validation (CR, LF, NUL)      | hand-written cases                                                                                               | ctest/test_headers.c                                                  |
| Header field validation (CR, LF, NUL)      | an accepted field re-serialises byte-identical; the RFC 9110 token and field-value grammar as a second validator | gap #239                                                              |
| gzip, zlib and raw deflate, decode         | round trip with system zlib `deflate()`; split at every byte boundary; bomb caps                                 | ctest/test_inflate.c, fuzz/fuzz_body.c                                |
| Multi-member gzip, decode                  | two members decode as their concatenation, as `gzip -dc` does                                                    | gap #242                                                              |
| Repeated or stacked Content-Encoding       | refused with a classed error (#211), hand-written                                                                | ctest/test_body.c, ctest/test_inflate.c                               |
| HTTP/2 frames and HPACK, emit              | python-h2 (hypercorn) receives the requests; `/check` asserts body bytes and order                               | tests/testthat/test-http2.R, tools/h2-test-server.py                  |
| HTTP/2 frames and HPACK, decode            | python-h2 (hypercorn) serves the responses: bodies, trailers, flow control                                       | tests/testthat/test-http2.R, ctest/test_h2.c                          |
| ALPN protocol list, emit                   | RFC 7301 §3.1 wire form, hand-written                                                                            | ctest/test_h2.c                                                       |
| URI parse                                  | hand-written policy cases; fuzz invariants (scheme and host present, path starts `/`, origin has no `@`)         | ctest/test_uri.c, fuzz/fuzz_uri.c                                     |
| Relative reference resolution              | RFC 3986 §5.4 examples, 10 of the RFC's 42                                                                       | ctest/test_uri.c                                                      |
| Relative reference resolution              | every RFC 3986 §5.4.1 and §5.4.2 example                                                                         | gap #245                                                              |
| Redirect method and credential policy      | §19 cases; fuzz asserts credentials are stripped cross-origin and never appear                                   | ctest/test_redirect.c, fuzz/fuzz_redirect.c                           |
| Proxy URL, environment and `NO_PROXY`      | hand-written cases; fuzz invariants (host present, no `@`, never downgraded)                                     | ctest/test_proxy.c, fuzz/fuzz_proxy.c                                 |
| Proxy URL, environment and `NO_PROXY`      | libcurl's proxy choice for the same (environment, URL) pairs                                                     | gap #244                                                              |
| Proxy CONNECT and absolute-form, emit      | the bytes the helper proxy received: request line and `Proxy-Authorization`                                      | tests/testthat/test-proxy.R, tests/testthat/helper-proxy.R            |
| Proxy CONNECT reply, decode                | hand-written cases: 2xx, 407, other, malformed, incomplete                                                       | ctest/test_proxy.c, tests/testthat/test-proxy.R                       |
| Proxy-Authorization base64, emit           | RFC 4648 §10 test vectors                                                                                        | ctest/test_proxy.c                                                    |
| TLS chain and host name verification       | local `openssl s_server` fixtures: good, untrusted, wrong host, expired, not yet valid                           | tests/testthat/test-certs.R, tools/make-tls-fixture, ctest/test_tls.c |
| TLS IP-literal verification                | a certificate naming only `IP:127.0.0.1` verifies (#216)                                                         | ctest/tls_eof/run.sh                                                  |
| TLS IP-literal verification                | a mismatched IP and a DNS-only SAN are refused, on every backend                                                 | gap #246                                                              |
| TLS revocation and the badssl.com rows     | badssl.com's revoked and broken hosts, replaced by local fixtures                                                | gap #63                                                               |
| SPKI pin digest                            | the `openssl` CLI computes the expected pin                                                                      | tests/testthat/helper-tlsfixture.R, tests/testthat/test-certs.R       |
| Query and form percent-encoding, emit      | two hand-written strings                                                                                         | tests/testthat/test-merge.R, tests/testthat/test-request.R            |
| Query and form percent-encoding, emit      | `curl::curl_escape()` and Python `urllib.parse.quote()` over random UTF-8                                        | gap #243                                                              |
| JSON body (zujson), both directions        | round trip through a mock echo transport                                                                         | tests/testthat/test-json.R                                            |
| Response text charset, decode              | the §31.7 chain against known Latin-1 bytes, hand-written                                                        | tests/testthat/test-response.R                                        |
| Cassette (`zu_record()`), write and read   | round trip: record, replay in a fresh session                                                                    | tests/testthat/test-record.R                                          |
| Redaction, every §42.2 egress              | a canary credential is absent from every egress; fuzz asserts no userinfo survives                               | tests/testthat/test-redact.R, ctest/test_redact.c, fuzz/fuzz_redact.c |
| Trace output                               | hand-written cases: truncation marker, UTF-8-safe cut, redaction                                                 | ctest/test_trace.c, tests/testthat/test-trace.R                       |
<!-- markdownlint-enable MD013 -->

## Objects

One row per object that outlives the call that made it. "Sequences" is
the test of its out-of-order use (abort then read, use after end, use
after free). The guard columns name the test, or say why the guard
cannot apply.

<!-- markdownlint-disable MD013 -->
| Object                                       | Sequences                                                                                                                  | Fork                                                                                                        | Unwind                                                                                                       | Owner                                                                                              |
| -------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------- |
| Connection pool (`zu_client()`)              | gap #247: ctest/test_pool.c scripts fixed paths only (expiry, stale, every no-reuse reason, caps, #154 re-entrant release) | PID check on acquire, release and free: ctest/test_pool.c (real `fork()`, #196), tests/testthat/test-pool.R | n/a: holds no R state, and nothing it calls can longjmp                                                      | finalizer, `zu_pool_reset()`, eviction: tests/testthat/test-pool.R                                 |
| Pooled connection, plain TCP                 | use after reset: tests/testthat/test-pool.R; close while checked out cannot happen, acquire hands ownership out            | dropped unclosed in a child: ctest/test_pool.c, tests/testthat/test-pool.R (mclapply)                       | released as CANCELLED after a callback jump: tests/testthat/test-engine-live.R, tests/testthat/test-stream.R | `entry_destroy` on clear, evict, expire, stale, fork; counted in tests/testthat/test-engine-live.R |
| Pooled connection, borrowed request pointers | n/a: no sequence reads them after the call today                                                                           | n/a: plain memory                                                                                           | n/a: plain memory                                                                                            | gap #251: `net_impl.opts.trace` and `h2_impl.body` keep pointers into a finished call              |
| Pooled connection, OpenSSL TLS               | renegotiation and bad close from a scripted server: `make -C ctest tls-eof-asan`                                           | gap #249: the no-close drop is relied on, never tested with a real TLS session in a child                   | n/a: no R calls inside                                                                                       | `tls_destroy`, under `make -C ctest tls-asan`                                                      |
| Pooled connection, Schannel TLS              | gap #249: no scripted-server test on Windows                                                                               | n/a: Windows has no `fork()`                                                                                | n/a: no R calls inside                                                                                       | `tls_destroy`, by the R suite on the Windows legs                                                  |
| Network.framework connection                 | live only, under `make -C ctest engine-nw-asan`                                                                            | per-connection PID and a process guard (D-32): tests/testthat/test-fork.R, gated by tools/ci-fork-guard.R   | n/a: no R code runs inside; cancel stops the tick                                                            | `nw_impl_free` and the `nw_shared` refcount, under `engine-nw-asan`                                |
| HTTP/2 session (nghttp2)                     | abort then read is CANCELLED, second abort a no-op, reuse after abort: ctest/test_h2.c                                     | gap #249: only through the pool's drop, untested with a live h2 session in a child                          | interrupt mid-read (#189): ctest/test_h2.c, tests/testthat/test-http2.R                                      | `h2_destroy`; `hdrs` cleared after begin (#178): ctest/test_h2.c                                   |
| Pulled body (`zu_stream`)                    | model-based: fuzz/fuzz_pull.c (read, peek, consume, abort, done over four framings); ctest/test_engine_mock.c (#213, #214) | `b->guard` (#209): ctest/test_engine_mock.c                                                                 | ownership moves to the external pointer before anything can longjmp; consume after the R copy (#214)         | finalizer, or release at end, abort or failure: tests/testthat/test-engine-live.R, test-pull.R     |
| Pulled body over HTTP/2 or a pool            | gap #248: fuzz_pull.c models one HTTP/1.1 connection, no h2, pool, mid-body failure or timeout                             | gap #250: no R-level test reads a `zu_stream` in a forked child                                             | interrupt mid-read: ctest/test_h2.c                                                                          | released to the pool only after a clean end: ctest/test_h2.c                                       |
| Duplex body source (`src_ctx`)               | refused once, later reads fail, released once: tests/testthat/test-http2.R, ctest/test_h2.c                                | n/a: a child only runs `R_ReleaseObject`, which is safe there                                               | preserved before any C state exists (#142), resumed once: tests/testthat/test-http2.R                        | `src_release` by the engine or the pulled body that inherits it: ctest/test_h2.c                   |
| Download file sink                           | abort, and abandoned without abort: ctest/test_body.c, tests/testthat/test-download.R, tests/testthat/test-stream.R        | n/a: lives within one `.Call`                                                                               | `guard_resume` aborts the sink: tests/testthat/test-stream.R                                                 | finished or aborted inside `C_zu_perform`: ctest/test_body.c                                       |
<!-- markdownlint-enable MD013 -->

## Limits

One row per limit the package enforces. "Straddled by" is the test of
`limit - 1`, `limit` and `limit + 1` on every path that reaches it.

<!-- markdownlint-disable MD013 -->
| Limit                                               | Unit                                     | Straddled by                                                                                                |
| --------------------------------------------------- | ---------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| request header and body combine, 64 KiB and 32 KiB  | wire bytes                               | ctest/test_engine_mock.c: 32767 to 32769 and every size 65236 to 65536, wire asserted (#208)                |
| `max_body`, HTTP/1.1 identity                       | decoded bytes                            | ctest/test_body.c (caps 1 to 30 under close, exactly at cap under Content-Length); fuzz/fuzz_body.c at 8    |
| `max_body`, chunked identity and gzip, HTTP/1.1     | decoded bytes                            | gap #252: ctest/test_body.c straddles gzip under Content-Length and chunked at cap 5 and 4, not under close |
| `max_body`, HTTP/2 and pulled bodies                | decoded bytes                            | gap #252: ctest/test_h2.c and tests/testthat/test-http2.R test far over the cap only                        |
| `max_body` from R                                   | bytes, `>= 1` or `Inf`                   | tests/testthat/test-response.R, tests/testthat/test-merge.R                                                 |
| `ZUH_MAX_HEADER_BYTES`, HTTP/1.1 response head      | wire bytes, and name + value + 4 a field | gap #258: refused only at a read boundary; ctest/test_engine_mock.c tests about 72 KB only                  |
| header bytes, HTTP/1.1 trailers and HTTP/2          | wire bytes; name + value + 32 a field    | gap #259: H1 head, H1 trailers and HTTP/2 count and classify it differently; tests far over only            |
| `ZUH_DEFAULT_MAX_HEADER_COUNT`, name and value caps | count; bytes                             | gap #253: ctest/test_headers.c with limits of 2, 8 and 16; the defaults are never straddled on the wire     |
| proxy CONNECT reply, 64 KiB                         | wire bytes                               | gap #257: ctest/test_engine_mock.c reads 70000 bytes in aligned 16 KiB pieces only                          |
| `ZUH_MAX_REDIRECT_BODY`, 64 KiB                     | wire bytes                               | gap #254: ctest/test_engine_mock.c tests 70000 bytes only                                                   |
| `ZUH_MAX_HOST_LEN`, 253                             | bytes                                    | gap #254: ctest/test_engine_mock.c tests about 315 bytes only                                               |
| `ZUH_MAX_DECOMPRESSION_RATIO`, 1000, after 32 bytes | ratio; compressed bytes                  | gap #255: ctest/test_body.c tests a far-over bomb; ctest/test_inflate.c uses a ratio of 10                  |
| picohttpparser chunk overhead                       | wire bytes                               | gap #256: inherited from the vendored parser, untested                                                      |
| `redirects`, default 10                             | count                                    | gap #254: tests/testthat/test-redirect-live.R tests limit and limit + 1, not limit - 1                      |
| `zu_retry()` attempts and `max_retry_after`         | count; seconds                           | tests/testthat/test-retry.R: success on attempts 1 to 3, exhausted at 3; 60 clamped, 5 kept                 |
| `zu_pool()` `max_per_host` and `max_idle`           | count                                    | gap #254: ctest/test_pool.c tests at the cap and over it, not under                                         |
| HTTP/2 initial window, 4 MiB                        | wire DATA bytes                          | ctest/test_h2.c: the server stops at or under the window                                                    |
<!-- markdownlint-enable MD013 -->

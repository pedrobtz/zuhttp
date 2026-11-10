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
| alloc-failure | done | alloc-failure.yaml (weekly over tools/alloc/exercise.R, R's allocations included (#237); at least 100 failures must reach zu_memory_error; base R's own TRE and gzfile() crashes are listed apart, #282) |
| mutation | done | mutation.yaml (Mull over src/zuh_*.c against zuh_ctest, weekly (#238); survivors triaged in #269-#275) |
| fuzz | done | fuzz.yaml (own): 13 targets, every one with an oracle beyond a crash; `fuzz_response`, `fuzz_chunked` and `fuzz_headers` check against fuzz/http_grammar.h, an independent reading of RFC 9110 and 9112 (#239); corpus replay on every OS, libFuzzer smoke, weekly soak |
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
| HTTP/1.1 response head and chunked, decode | Python `h11` parses the same bytes; status, fields, body and accept/reject compared | tests/testthat/test-h11.R (#240): 48 responses against h11 0.16.0; the deliberate differences are in §18.1 |
| HTTP/1.1 response, decode | libcurl (R `curl`) fetches the same raw-server script; status, headers and body compared | tests/testthat/test-libcurl.R (#241): 15 scripted responses, status, headers, trailers and body |
| Response framing decision                  | the RFC 9112 §6.3 table, one hand-written case per row                                                           | ctest/test_framing.c                                                  |
| Chunked response body and trailers, decode | the same payload under Content-Length, chunked and close compared; whole and byte-wise reads compared            | fuzz/fuzz_body.c, ctest/test_body.c, ctest/test_response.c            |
| HTTP/1.1 request and upload, emit          | the bytes on the mock wire, at sizes straddling the 64 KiB combine (#208)                                        | ctest/test_engine_mock.c, fuzz/fuzz_engine.c                          |
| HTTP/1.1 request, emit | libcurl sends the same request to the raw server; the recorded bytes compared | tests/testthat/test-libcurl.R (#241): 14 requests, the bytes the raw server recorded, uploads either side of 32 and 64 KiB |
| Chunked upload, emit                       | `h11` (hypercorn) parses it; `/check` asserts byte count and order                                               | tests/testthat/test-http2.R, ctest/test_engine_mock.c                 |
| Header field validation (CR, LF, NUL)      | hand-written cases                                                                                               | ctest/test_headers.c                                                  |
| Header field validation (CR, LF, NUL) | an accepted field re-serialises byte-identical; the RFC 9110 token and field-value grammar as a second validator | fuzz/fuzz_headers.c (#239): both validators against the RFC 9110 grammar in fuzz/http_grammar.h; an accepted field is written as `name: value` CRLF and parses back to itself |
| gzip, zlib and raw deflate, decode         | round trip with system zlib `deflate()`; split at every byte boundary; bomb caps                                 | ctest/test_inflate.c, fuzz/fuzz_body.c                                |
| Multi-member gzip, decode                  | two members decode as their concatenation, as `gzip -dc` does                                                    | gap #242                                                              |
| Repeated or stacked Content-Encoding       | refused with a classed error (#211), hand-written                                                                | ctest/test_body.c, ctest/test_inflate.c                               |
| HTTP/2 frames and HPACK, emit              | python-h2 (hypercorn) receives the requests; `/check` asserts body bytes and order                               | tests/testthat/test-http2.R, tools/h2-test-server.py                  |
| HTTP/2 frames and HPACK, decode            | python-h2 (hypercorn) serves the responses: bodies, trailers, flow control                                       | tests/testthat/test-http2.R, ctest/test_h2.c                          |
| HTTP/2 peer misbehaviour mid-body, decode | a scripted peer sends exact frames (RST or GOAWAY mid-body, window held at 0, DATA past the window, a content-length mismatch); the error class and the bytes delivered before it are asserted | gap #264 |
| ALPN protocol list, emit                   | RFC 7301 §3.1 wire form, hand-written                                                                            | ctest/test_h2.c                                                       |
| URI parse                                  | hand-written policy cases; fuzz invariants (scheme and host present, path starts `/`, origin has no `@`)         | ctest/test_uri.c, fuzz/fuzz_uri.c                                     |
| Relative reference resolution | every RFC 3986 §5.4.1 and §5.4.2 example | ctest/test_uri.c (#245): all 42 examples, from ctest/rfc3986_examples.h |
| Redirect method and credential policy      | §19 cases; fuzz asserts credentials are stripped cross-origin and never appear                                   | ctest/test_redirect.c, fuzz/fuzz_redirect.c                           |
| Proxy URL, environment and `NO_PROXY`      | hand-written cases; fuzz invariants (host present, no `@`, never downgraded)                                     | ctest/test_proxy.c, fuzz/fuzz_proxy.c                                 |
| Proxy URL, environment and `NO_PROXY` | libcurl's proxy choice for the same (environment, URL) pairs | tests/testthat/test-proxy.R (#244): 35 (environment, URL) pairs; deliberate differences in §20.2 |
| Proxy CONNECT and absolute-form, emit      | the bytes the helper proxy received: request line and `Proxy-Authorization`                                      | tests/testthat/test-proxy.R, tests/testthat/helper-proxy.R            |
| Proxy CONNECT reply, decode                | hand-written cases: 2xx, 407, other, malformed, incomplete                                                       | ctest/test_proxy.c, tests/testthat/test-proxy.R                       |
| Proxy-Authorization base64, emit           | RFC 4648 §10 test vectors                                                                                        | ctest/test_proxy.c                                                    |
| TLS chain and host name verification       | local `openssl s_server` fixtures: good, untrusted, wrong host, expired, not yet valid                           | tests/testthat/test-certs.R, tools/make-tls-fixture, ctest/test_tls.c |
| TLS IP-literal verification                | a certificate naming only `IP:127.0.0.1` verifies (#216)                                                         | ctest/tls_eof/run.sh, tests/testthat/test-certs.R "#216, #246"        |
| TLS IP-literal verification | a mismatched IP and a DNS-only SAN are refused, on every backend | ctest/tls_eof/run.sh "#246" (OpenSSL, `drive hostname`); tests/testthat/test-certs.R "#246" (OpenSSL, Network.framework); Schannel gap #286 |
| TLS revocation and the badssl.com rows     | badssl.com's revoked and broken hosts, replaced by local fixtures                                                | gap #63                                                               |
| SPKI pin digest                            | the `openssl` CLI computes the expected pin                                                                      | tests/testthat/helper-tlsfixture.R, tests/testthat/test-certs.R       |
| Query and form percent-encoding, emit      | two hand-written strings                                                                                         | tests/testthat/test-merge.R, tests/testthat/test-request.R            |
| Query and form percent-encoding, emit | `curl::curl_escape()` and Python `urllib.parse.quote()` over random UTF-8 | tests/testthat/test-request.R (#243): 413 seeded UTF-8 strings against the unreserved rule, `curl_escape()` and `urllib.parse.quote()`; forms round-trip through `parse_qsl()` |
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
| Connection pool (`zu_client()`)              | model-based: fuzz/fuzz_pool.c against a model of reuse, expiry, caps and the fork drop (#247); fixed paths in ctest/test_pool.c | PID check on acquire, release and free: ctest/test_pool.c (real `fork()`, #196), tests/testthat/test-pool.R | n/a: holds no R state, and nothing it calls can longjmp                                                      | finalizer, `zu_pool_reset()`, eviction: tests/testthat/test-pool.R                                 |
| Pooled connection, plain TCP                 | use after reset: tests/testthat/test-pool.R; close while checked out cannot happen, acquire hands ownership out            | dropped unclosed in a child: ctest/test_pool.c, tests/testthat/test-pool.R (mclapply)                       | released as CANCELLED after a callback jump: tests/testthat/test-engine-live.R, tests/testthat/test-stream.R | `entry_destroy` on clear, evict, expire, stale, fork; counted in tests/testthat/test-engine-live.R |
| Pooled connection, borrowed request pointers | ctest/test_net.c and test_h2.c "#251": the trace and the body are freed after the call and the connection used again under `make -C ctest asan` | n/a: plain memory                                                                                           | n/a: plain memory                                                                                            | cleared when the call ends: `zuh_net_connect()` drops the trace and timings, the stream's close drops the body (#251); `zuh_net_borrowed()` and `zuh_h2_borrowed()` are 0 after it |
| Pooled connection, OpenSSL TLS               | renegotiation and bad close from a scripted server: `make -C ctest tls-eof-asan`                                           | ctest/tls_eof/fork.sh: a child drops two live TLS connections and nothing reaches the server (`make -C ctest tls-eof`, `tls-eof-asan`; network.yaml)                   | n/a: no R calls inside                                                                                       | `tls_destroy`, under `make -C ctest tls-asan`                                                      |
| Pooled connection, Schannel TLS              | gap #286: no scripted-server test on Windows                                                                               | n/a: Windows has no `fork()`                                                                                | n/a: no R calls inside                                                                                       | `tls_destroy`, by the R suite on the Windows legs                                                  |
| Network.framework connection                 | live only, under `make -C ctest engine-nw-asan`                                                                            | per-connection PID and a process guard (D-32): tests/testthat/test-fork.R, gated by tools/ci-fork-guard.R   | n/a: no R code runs inside; cancel stops the tick                                                            | `nw_impl_free` and the `nw_shared` refcount, under `engine-nw-asan`                                |
| HTTP/2 session (nghttp2)                     | abort then read is CANCELLED, second abort a no-op, reuse after abort: ctest/test_h2.c                                     | ctest/test_h2.c "#249: a child drops inherited HTTP/2 connections" (strict and asan, all c-core OSes)                          | interrupt mid-read (#189): ctest/test_h2.c, tests/testthat/test-http2.R                                      | `h2_destroy`; `hdrs` cleared after begin (#178): ctest/test_h2.c                                   |
| Pulled body (`zu_stream`)                    | model-based: fuzz/fuzz_pull.c (read, peek, consume, abort, done over four framings); ctest/test_engine_mock.c (#213, #214) | `b->guard` (#209): ctest/test_engine_mock.c                                                                 | ownership moves to the external pointer before anything can longjmp; consume after the R copy (#214)         | finalizer, or release at end, abort or failure: tests/testthat/test-engine-live.R, test-pull.R     |
| Pulled body over HTTP/2 or a pool            | fuzz/fuzz_pull.c: HTTP/1.1 and HTTP/2, pooled and unpooled, mid-body failure and timeout, against a model (#248)                             | tests/testthat/test-fork.R "a forked child cannot read an open zu_stream" (#250)                                             | interrupt mid-read: ctest/test_h2.c                                                                          | released to the pool only after a clean end: ctest/test_h2.c                                       |
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
| `max_body`, chunked identity and gzip, HTTP/1.1 | decoded bytes | ctest/test_body.c (#252): Content-Length, chunked and close, identity and gzip, at cap - 1, cap and cap + 1 |
| `max_body`, HTTP/2 and pulled bodies | decoded bytes | ctest/test_h2.c (#252): HTTP/1.1 and HTTP/2, buffered and pulled, identity and gzip, at 2999, 3000 and 3001 |
| `max_body` from R                                   | bytes, `>= 1` or `Inf`                   | tests/testthat/test-response.R, tests/testthat/test-merge.R                                                 |
| `ZUH_MAX_HEADER_BYTES`, HTTP/1.1 response head | wire bytes, 64 KiB a head (D-101) | ctest/test_engine_mock.c (#258): over 64 KiB on the wire is refused at every read size |
| header bytes, HTTP/1.1 trailers and HTTP/2 | name + value + 32 a field, pseudo-headers free; `zu_http_parse_error` everywhere (D-101) | ctest/test_h2.c (#259): one field list at 65535, 65536 and 65537 bytes through the H1 head, H1 trailers, H2 headers and H2 trailers, whole and byte-wise |
| `ZUH_DEFAULT_MAX_HEADER_COUNT`, name and value caps | count; bytes | ctest/test_h2.c (#253): the shipped defaults (100 fields, 256-byte names, 8 KiB values) and one more, over HTTP/1.1 and HTTP/2 |
| proxy CONNECT reply, 64 KiB | wire bytes | ctest/test_engine_mock.c (#257): refused past 64 KiB at every read size, as `zu_proxy_error` |
| `ZUH_MAX_REDIRECT_BODY`, 64 KiB | wire bytes | ctest/test_engine_mock.c (#254): 65535 and 65536 bytes drained and the connection reused, 65537 not |
| `ZUH_MAX_HOST_LEN`, 253 | bytes | ctest/test_engine_mock.c (#254): 253 bytes dials, 254 is refused, on a redirect hop too (#277) |
| `ZUH_MAX_DECOMPRESSION_RATIO`, 1000, after 32 bytes | ratio; compressed bytes | ctest/test_inflate.c (#255): 999.999, 1000 and 1000.001 to 1 at the default; the ratio from the 32nd compressed byte, not the 31st |
| picohttpparser chunk overhead | wire bytes | ctest/test_body.c (#256): refused byte-wise and one-shot, at the threshold |
| `redirects`, default 10 | count | ctest/test_engine_mock.c (#254): 9 and 10 followed, the 11th refused |
| `zu_retry()` attempts and `max_retry_after`         | count; seconds                           | tests/testthat/test-retry.R: success on attempts 1 to 3, exhausted at 3; 60 clamped, 5 kept                 |
| `zu_pool()` `max_per_host` and `max_idle` | count | ctest/test_pool.c (#254): cap - 1 and cap kept, cap + 1 evicted |
| HTTP/2 initial window, 4 MiB                        | wire DATA bytes                          | ctest/test_h2.c: the server stops at or under the window                                                    |
<!-- markdownlint-enable MD013 -->

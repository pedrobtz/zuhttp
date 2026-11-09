A senior C/C++ reviewer would probably say: **the package has a solid architectural foundation, but several correctness bugs need fixing before I would trust it as a general-purpose HTTP dependency.**

I reviewed the current checkout (`90832db`) and reproduced **six bugs** against local servers. I also found one cleanup defect by inspection.

1. **High priority: some HTTP/1.1 uploads send the body twice.**  
   [zuh_engine.c:1183](/Users/pbtz/src/github.com/pedrobtz/zuhttp/src/zuh_engine.c:1183)

   A successful `zuh_buf_append()` changes `wire.len` inside an `if` condition. The subsequent `else if` then evaluates the available space using that changed length and can send the body again.

   **Reproduced:** a 40,000-byte upload sent **80,000 body bytes**, with `Content-Length: 40000`, and still returned success. This can corrupt HTTP connection framing, particularly with connection reuse or proxies.

   **Review:** decide whether to combine headers and body before modifying the buffer; make the two send paths explicitly exclusive.

2. **High priority: streamed responses bypass the fork protection.**  
   [zuh_engine.c:811](/Users/pbtz/src/github.com/pedrobtz/zuhttp/src/zuh_engine.c:811)

   Open response bodies hold live connections without checking which process created them before reading. The pool’s fork guard does not protect a connection already checked out into a streamed response.

   **Reproduced:** I opened a streamed response, forked, and read `"hello"` in the child. The parent subsequently failed because its body bytes had been consumed.

   **Review:** record the creating PID on open bodies and refuse inherited reads. Audit aborts and finalizers too, particularly where HTTP/2 cancellation writes to the connection.

3. **Medium priority: malformed chunk framing reaches callbacks as body data.**  
   [zuh_body.c:208](/Users/pbtz/src/github.com/pedrobtz/zuhttp/src/zuh_body.c:208), [zuh_response.c:201](/Users/pbtz/src/github.com/pedrobtz/zuhttp/src/zuh_response.c:201)

   The caller feeds the buffer to the body sink before checking whether chunk decoding failed. On one failure path, the decoder leaves the output length equal to the original wire length.

   **Reproduced:** an invalid chunk beginning `X\r\nATTACK...` was delivered to the callback, including its framing bytes, before the request raised a parse error.

   Callbacks may already have acted on those bytes.

   **Review:** check the decoder’s result before delivery, and define exactly which output bytes remain valid after a decoding error.

4. **Medium priority: repeated `Content-Encoding` headers silently produce incorrectly decoded bodies.**  
   [zuh_body.c:27](/Users/pbtz/src/github.com/pedrobtz/zuhttp/src/zuh_body.c:27)

   The code reads only the first encoding header, decodes once, and then removes every `Content-Encoding` header.

   **Reproduced:** a doubly gzipped response with two `Content-Encoding: gzip` fields returned **still-compressed gzip bytes**, with no encoding header remaining.

   **Review:** interpret all encoding fields together. Since stacked encodings are currently unsupported, reject them explicitly.

5. **Medium priority: `max_body` has inconsistent semantics for compressed responses.**  
   [zuh_body.c:133](/Users/pbtz/src/github.com/pedrobtz/zuhttp/src/zuh_body.c:133)

   The documented limit applies to decoded bytes, but the chunk decoder also applies it to the compressed payload before decompression.

   **Reproduced:** gzip containing `"hello"` succeeds with `max_body = 5` under `Content-Length` framing, but fails under chunked framing.

   **Review:** keep any encoded-byte limit separate from the decoded-body limit. Equivalent response content should behave consistently across framing modes.

6. **Medium priority: aborting a partially read response can leave it readable.**  
   [zuh_engine.c:862](/Users/pbtz/src/github.com/pedrobtz/zuhttp/src/zuh_engine.c:862)

   `zuh_open_body_abort()` returns immediately when the wire transfer has ended, even when buffered bytes remain unread by the caller.

   **Reproduced:** read `"h"` from `"hello"`, call `zu_resp_abort()`, then read again: it returns `"ello"` instead of raising the documented cancellation error.

   **Review:** distinguish “finished receiving” from “finished delivering to the caller” consistently. Your `zuh_open_body_done()` already recognizes that distinction.

7. **Medium priority: an R allocation failure leaks a native read buffer.**  
   [init.c:1396](/Users/pbtz/src/github.com/pedrobtz/zuhttp/src/init.c:1396)

   `got` owns native memory when `Rf_allocVector()` runs. If that allocation raises an R error, its non-local jump skips `zuh_buf_free(&got)`.

   The nearby comment says the buffer is freed on both paths, but this allocation has no unwind cleanup.

   **Review:** protect this conversion with guaranteed cleanup, following the pattern already used for building complete responses. This finding is from inspection; I did not inject an R allocation failure.

The broader engineering concern is **consistency at boundaries**: wire bytes versus decoded bytes, receiving versus delivering, pool ownership versus stream ownership, and C cleanup versus R unwinding. Several individual helpers are carefully implemented, while their composition breaks the intended contract.

The strongest parts are the separation of the C core from R, the transport seam, checked allocation helpers, and the existing fuzzing and failure-injection infrastructure. I would strengthen those tests with assertions about **exact bytes and state transitions**: upload sizes around the combining threshold, equivalent compressed responses under different framing, partial-read/abort sequences, and inherited open streams.

Validation: both strict and ASan/UBSan C runs passed **2,526 checks**. The R suite completed without failures, with **125 skips**. The additional probes exposed the six behaviors above; they are saved in [the reproduction script](/tmp/zuhttp-review-probes.py). No source changes were made. Linux and Windows TLS behavior was not runtime-validated in this review.


Yes. A second pass found **six additional defects**, including a confirmed memory-safety issue. These are separate from the previous seven.

1. **High: OpenSSL retains a pointer to an expired stack object.**  
   [zuh_tls_openssl.c:345](/Users/pbtz/src/github.com/pedrobtz/zuhttp/src/zuh_tls_openssl.c:345), [zuh_engine.c:514](/Users/pbtz/src/github.com/pedrobtz/zuhttp/src/zuh_engine.c:514)

   The engine constructs `zuh_tls_config cfg` on its stack. The TLS connection retains its address, and the certificate-verification callback reads it during subsequent TLS 1.2 renegotiation.

   **Reproduced:** a local server requested renegotiation after the configuration’s stack frame returned. AddressSanitizer reported **`stack-use-after-return` in `verify_cb()`**, and aborted the process.

   This happens even without configured pins: reading `cfg->n_pins` already accesses expired memory. Own the verification data—including referenced pin strings—for the connection’s lifetime, or explicitly disable renegotiation.

2. **Medium: valid certificates for IP-address URLs fail verification under OpenSSL.**  
   [zuh_tls_openssl.c:391](/Users/pbtz/src/github.com/pedrobtz/zuhttp/src/zuh_tls_openssl.c:391)

   Every verification target goes through `X509_VERIFY_PARAM_set1_host()`, including IP addresses. OpenSSL provides separate IP verification functions.

   **Reproduced:** a trusted test certificate containing both `DNS:localhost` and `IP:127.0.0.1` succeeds for `localhost` but fails for `127.0.0.1`.

   Detect IP literals and configure IP verification with `X509_VERIFY_PARAM_set1_ip_asc()`. See [OpenSSL’s verification documentation](https://docs.openssl.org/3.0/man3/X509_VERIFY_PARAM_set_flags/).

3. **Medium: an upload source returning empty pieces can evade the request timeout.**  
   [init.c:138](/Users/pbtz/src/github.com/pedrobtz/zuhttp/src/init.c:138)

   `src_next()` repeatedly calls the R body function until it receives data or `NULL`. It checks interrupts between empty pieces, but never checks the request deadline.

   **Reproduced:** with `timeout = 0.1`, a source returning 100 empty pieces with short pauses ran for approximately **1.2 seconds** and was called 101 times before the timeout surfaced.

   An indefinitely empty source can keep running until interrupted. The deadline needs checking between source calls; this does not require preempting an individual R callback.

4. **Medium: the retry loop destroys a response even when no retry will happen.**  
   [R/perform.R:532](/Users/pbtz/src/github.com/pedrobtz/zuhttp/R/perform.R:532)

   The loop aborts a streamed response **before** checking whether the remaining budget permits the retry delay. If there is insufficient time, it returns that aborted response.

   **Reproduced:** a streamed 503 response, with `check = FALSE`, a one-second timeout and a two-second retry delay, returns after one attempt. Reading its body raises `zu_cancelled_error`; the server’s body is lost.

   Decide whether another attempt will actually happen before aborting the current response.

5. **Medium: adding query parameters to a URL containing a fragment silently loses them.**  
   [R/url.R:93](/Users/pbtz/src/github.com/pedrobtz/zuhttp/R/url.R:93)

   `url_with_query()` appends parameters to the entire URL, including anything after `#`.

   **Reproduced:**
   ```r
   zu_get("http://host/path#section", query = list(x = "hello"))
   ```
   builds `http://host/path#section?x=hello`. The C URI parser correctly removes the fragment, so `x=hello` never reaches the server.

   Insert query parameters before the fragment and inspect only the pre-fragment portion when choosing `?` or `&`.

6. **Low: response metadata reports the wrong method after redirects.**  
   [R/perform.R:445](/Users/pbtz/src/github.com/pedrobtz/zuhttp/R/perform.R:445)

   `resp$method <- r$method` always records the original method, although the documented accessor promises the method actually sent after redirects.

   **Reproduced:** the server received `POST /`, returned 303, then received `GET /final`. `zu_resp_method()` still reported `"POST"`.

   Carry the final method back from the engine rather than reconstructing it from the original request.

The first finding would be a **release blocker** for me. It also suggests a broader ownership audit: every pointer retained by a connection should identify its owner and guaranteed lifetime. That audit should include pointers inside configuration structures, since copying the structure alone does not make its referenced data safe.

All six findings were reproduced. The additional [HTTP/R probes](/tmp/zuhttp-review2.py) and [OpenSSL sanitizer log](/tmp/zuhttp-review2-tls.log) are available locally. No source files were changed.
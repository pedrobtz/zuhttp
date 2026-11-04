/* Target 12 — the engine over HTTP/2 (design §65.8, W20).
 *
 * The client is the whole request path with http2 = "required" on an http://
 * URL, so every connection is prior-knowledge h2c and runs through the
 * vendored nghttp2 session and src/zuh_h2.c. The server is the fuzzer: its
 * bytes are scripted frames, handed out by the §50.1 dial seam as in target
 * 10. HPACK, SETTINGS, flow control, CONTINUATION, RST_STREAM, GOAWAY,
 * trailers, 1xx and DATA after END_STREAM are all reachable from the bytes.
 *
 * Input format: byte 0 picks options; the rest is split on "\0ZU\0" into up
 * to four connection scripts. Two requests are made on one pool, so a second
 * stream on a reused connection is fuzzed too (seeds carry a response on
 * stream 3 for it).
 *
 * Oracles, beyond ASan/UBSan, libFuzzer's leak check and nghttp2's own
 * assert()s (compiled in here, NDEBUG undefined):
 *   - the engine terminates (the mock never blocks; EOF ends every read);
 *   - a body delivered to the caller never exceeds max_body;
 *   - a response's header block never exceeds max_header_bytes (§40);
 *   - every allocation the client made for an input is freed by the end of
 *     it, nghttp2's included, since it allocates through zuh_alloc.
 */
#include "zuh_engine.h"
#include "zuh_mock_stream.h"
#include "zuh_pool.h"
#include "zuh_alloc.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define MAXC     4
#define MAX_BODY (64u * 1024u)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

typedef struct {
    const uint8_t *part[MAXC];
    size_t         len[MAXC];
    size_t         n, next;
    size_t         max_read;
    int            probe_reads;
    zuh_mock_step  step[MAXC];
} dialer;

static zuh_code dial(void *ctx, const char *host, uint16_t port,
                     zuh_stream **out, zuh_error *err) {
    dialer *d = (dialer *)ctx;
    size_t i = d->next;
    (void)host; (void)port;
    if (i >= d->n) {
        zuh_error_set(err, ZUH_ERR_CONNECT, ZUH_PHASE_CONNECT, "no more connections");
        return ZUH_ERR_CONNECT;
    }
    d->next++;
    d->step[i].kind = ZUH_MOCK_DATA;
    d->step[i].data = d->part[i];
    d->step[i].len  = d->len[i];
    *out = zuh_mock_stream_new(&d->step[i], 1, d->max_read, 0);
    if (!*out) return ZUH_ERR_NOMEM;
    /* Option bit 0x40: report the stream readable, so the §26.2 probe on a
     * pooled h2 connection reads ahead and the session decides whether what
     * it read ended the connection; otherwise idle, so the pool keeps it and
     * the second request reads the stream-3 response in order. */
    zuh_mock_stream_set_readable(*out, 1, d->probe_reads);
    return ZUH_OK;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const char *hn[] = { "Authorization", "TE" };
    static const char *hv[] = { "Bearer fuzz-secret", "trailers" };
    dialer d;
    zuh_get_opts o;
    zuh_req_spec spec;
    zuh_pool *pool;
    zuh_result r;
    zuh_error e;
    uint8_t sel;
    size_t i, start;
    int k;
    zuh_alloc_stats before, after;

    if (size < 1 || size > (1u << 18)) return 0;
    zuh_alloc_stats_get(&before);
    sel = data[0];
    memset(&d, 0, sizeof d);
    d.max_read = (sel & 0x3) == 0 ? 1 : (sel & 0x3) == 1 ? 9 : 0;
    d.probe_reads = (sel & 0x40) != 0;

    start = 1;
    for (i = 1; i + 4 <= size && d.n < MAXC - 1; i++) {
        if (data[i] == 0 && data[i + 1] == 'Z' && data[i + 2] == 'U' && data[i + 3] == 0) {
            d.part[d.n] = data + start; d.len[d.n] = i - start; d.n++;
            start = i + 4; i += 3;
        }
    }
    d.part[d.n] = data + start; d.len[d.n] = size - start; d.n++;

    memset(&spec, 0, sizeof spec);
    spec.header_names = hn; spec.header_values = hv; spec.n_headers = 2;
    if (sel & 0x4) { spec.method = "POST"; spec.body = "payload"; spec.body_len = 7; }
    if (sel & 0x8) spec.method = "HEAD";

    pool = zuh_pool_new(NULL);
    zuh_get_opts_init(&o);
    o.dial = dial; o.dial_ctx = &d;
    o.proxy_set = 1;
    o.pool = (sel & 0x10) ? NULL : pool;
    o.max_body = MAX_BODY;
    o.max_redirects = 3;
    o.no_decode = (sel & 0x20) != 0;
    o.http2 = ZUH_H2_REQUIRED;

    /* Option bit 0x80: the body is pulled (§65.4) in small pieces, and the
     * second request's is aborted halfway (§65.5), so the reset and the
     * reuse after it are fuzzed too. */
    o.stream_body = (sel & 0x80) != 0;

    for (k = 0; k < 2; k++) {
        zuh_result_init(&r);
        zuh_error_clear(&e);
        if (zuh_engine_perform(&r, "http://origin.test/start", &spec, &o, &e) == ZUH_OK) {
            size_t j, bytes = 0;
            const char *nm, *v;
            if (r.open) {
                zuh_buffer got;
                int reads = 0;
                if (zuh_buf_init(&got, 0, (size_t)-1)) {
                    while (!zuh_open_body_done(r.open) &&
                           zuh_open_body_read(r.open, &got, 333, &e) == ZUH_OK) {
                        if (k == 1 && ++reads == 3) zuh_open_body_abort(r.open);
                    }
                    if (got.len > MAX_BODY) abort();
                    zuh_buf_free(&got);
                }
            }
            if (r.body.len > MAX_BODY) abort();
            for (j = 0; zuh_headers_at(&r.headers, j, &nm, &v); j++)
                bytes += strlen(nm) + strlen(v) + 32;
            if (bytes > ZUH_DEFAULT_MAX_HEADER_BYTES) abort();
            zuh_result_free(&r);
        }
    }
    zuh_pool_free(pool);
    zuh_alloc_stats_get(&after);
    if (after.live_blocks != before.live_blocks) abort();
    return 0;
}

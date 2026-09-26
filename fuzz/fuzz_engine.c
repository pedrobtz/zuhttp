/* Target 10 — the whole engine (§50.1 dial seam).
 *
 * Every other target fuzzes one component. This one drives zu_engine_perform()
 * — status line, headers, 1xx, framing, chunked, decompression, redirects,
 * the pool, sinks, tracing — with scripted server bytes, through the dial
 * seam added 2026-09-26. The redirect credential leak fixed that day lived in
 * the engine, where no fuzzer reached.
 *
 * Input format: byte 0 picks options; the rest is split on the four-byte
 * marker "\0ZU\0" into up to six connection scripts, handed out in order to
 * the connections the engine opens. Two requests are made on one pool, so
 * reuse, stale connections and surplus bytes are fuzzed too.
 *
 * Oracles, beyond ASan/UBSan and libFuzzer's leak check:
 *   - the engine terminates (the mock never blocks; EOF ends every read);
 *   - a body delivered to the caller never exceeds max_body;
 *   - every allocation the engine made for an input is freed by the end of
 *     it, counted by zu_alloc itself — which works where LeakSanitizer does
 *     not (macOS, Windows under Rtools).
 * What the engine SENDS (credential stripping, request forms) is asserted in
 * ctest/test_engine_mock.c, whose dialer records writes past the stream's
 * lifetime; a fuzzer has no oracle for "the right bytes".
 */
#include "zu_engine.h"
#include "zu_mock_stream.h"
#include "zu_pool.h"
#include "zu_alloc.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define MAXC     6
#define MAX_BODY (64u * 1024u)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

typedef struct {
    const uint8_t *part[MAXC];
    size_t         len[MAXC];
    size_t         n, next;
    size_t         max_read;
    zu_mock_step   step[MAXC];
    zu_stream     *mock[MAXC];
    char           host[MAXC][64];
} dialer;

static zu_code dial(void *ctx, const char *host, uint16_t port,
                    zu_stream **out, zu_error *err) {
    dialer *d = (dialer *)ctx;
    size_t i = d->next;
    (void)port;
    if (i >= d->n) {
        zu_error_set(err, ZU_ERR_CONNECT, ZU_PHASE_CONNECT, "no more connections");
        return ZU_ERR_CONNECT;
    }
    d->next++;
    strncpy(d->host[i], host, sizeof d->host[i] - 1);
    d->step[i].kind = ZU_MOCK_DATA;
    d->step[i].data = d->part[i];
    d->step[i].len  = d->len[i];
    *out = zu_mock_stream_new(&d->step[i], 1, d->max_read, 0);
    if (!*out) return ZU_ERR_NOMEM;
    zu_mock_stream_set_readable(*out, 1, 0);   /* let the pool keep it */
    return ZU_OK;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const char *hn[] = { "Authorization" };
    static const char *hv[] = { "Bearer fuzz-secret" };
    dialer d;
    zu_get_opts o;
    zu_req_spec spec;
    zu_pool *pool;
    zu_result r;
    zu_error e;
    zu_trace tr;
    uint8_t sel;
    size_t i, start;
    int k;

    zu_alloc_stats before, after;

    if (size < 1 || size > (1u << 18)) return 0;
    zu_alloc_stats_get(&before);
    sel = data[0];
    memset(&d, 0, sizeof d);
    d.max_read = (sel & 0x3) == 0 ? 1 : (sel & 0x3) == 1 ? 7 : 0;

    /* Split on "\0ZU\0". */
    start = 1;
    for (i = 1; i + 4 <= size && d.n < MAXC - 1; i++) {
        if (data[i] == 0 && data[i + 1] == 'Z' && data[i + 2] == 'U' && data[i + 3] == 0) {
            d.part[d.n] = data + start; d.len[d.n] = i - start; d.n++;
            start = i + 4; i += 3;
        }
    }
    d.part[d.n] = data + start; d.len[d.n] = size - start; d.n++;

    memset(&spec, 0, sizeof spec);
    spec.header_names = hn; spec.header_values = hv; spec.n_headers = 1;
    if (sel & 0x4) { spec.method = "POST"; spec.body = "payload"; spec.body_len = 7; }
    if (sel & 0x8) spec.method = "HEAD";

    pool = zu_pool_new(NULL);
    zu_get_opts_init(&o);
    o.dial = dial; o.dial_ctx = &d;
    o.proxy_set = 1;
    o.pool = pool;
    o.max_body = MAX_BODY;
    o.max_redirects = (sel & 0x10) ? 0 : 5;
    o.no_decode = (sel & 0x20) != 0;
    zu_trace_init(&tr);
    o.trace = (sel & 0x40) ? &tr : NULL;

    for (k = 0; k < 2; k++) {
        zu_result_init(&r);
        zu_error_clear(&e);
        if (zu_engine_perform(&r, "http://origin.test/start", &spec, &o, &e) == ZU_OK) {
            if (r.body.len > MAX_BODY) abort();
            zu_result_free(&r);
        }
    }
    zu_pool_free(pool);
    zu_alloc_stats_get(&after);
    if (after.live_blocks != before.live_blocks) abort();   /* leaked on this input */
    return 0;
}

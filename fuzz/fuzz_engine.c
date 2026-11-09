/* Target 10 — the whole engine (§50.1 dial seam).
 *
 * Every other target fuzzes one component. This one drives zuh_engine_perform()
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
 * The option byte (review #191 added the last three, inside the bits the
 * format already had, so every seed keeps its meaning):
 *   0x03  reads of 1 byte (0), 7 bytes (1), or whatever is asked (2, 3);
 *         3 also pulls the body (§65.4) in small pieces and aborts the second
 *         request's half-way (§65.5);
 *   0x04  POST with a body; 0x08 HEAD; both at once (0x0C) a streamed body
 *         (§65.7) that fails when 0x01 is also set;
 *   0x10  no redirects; 0x20 no decoding; 0x40 a trace, and the §26.2
 *         liveness probe derived from the script rather than pinned idle, so
 *         the pool's stale path runs.
 *
 * Oracles, beyond ASan/UBSan and libFuzzer's leak check:
 *   - the engine terminates (the mock never blocks; EOF ends every read);
 *   - a body delivered to the caller never exceeds max_body, and a header
 *     or trailer block never exceeds the §40 limit;
 *   - a streamed body source is released exactly once;
 *   - every allocation the engine made for an input is freed by the end of
 *     it, counted by zuh_alloc itself — which works where LeakSanitizer does
 *     not (macOS, Windows under Rtools);
 *   - what each connection was sent frames itself (#228): every request's
 *     body is exactly its Content-Length, followed by the next request or by
 *     nothing. #208 sent uploads of ~32-64 KiB twice, which nothing crashed
 *     on. The POST body's size follows the input's length, since the option
 *     byte has no bit left, so the fuzzer moves it across the engine's
 *     combine-or-send-separately threshold.
 * WHICH bytes the engine should send (credential stripping, request forms)
 * is asserted in ctest/test_engine_mock.c; this checks only that whatever
 * it sent is well framed.
 */
#include "zuh_engine.h"
#include "zuh_mock_stream.h"
#include "zuh_pool.h"
#include "zuh_alloc.h"
#include "zuh_headers.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define MAXC     6
#define MAX_BODY (64u * 1024u)
#define MAX_UPLOAD 100000u

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

typedef struct {
    const uint8_t *part[MAXC];
    size_t         len[MAXC];
    size_t         n, next;
    size_t         max_read;
    int            probe_from_script;
    zuh_mock_step   step[MAXC];
    zuh_stream     *mock[MAXC];
    char           host[MAXC][64];
    zuh_buffer     sent[MAXC];   /* what each connection was written */
} dialer;

/* A mock connection that records what the engine writes, past the stream's
 * life: the engine frees its connections before the checks below run. */
typedef struct { zuh_stream *inner; zuh_buffer *sent; } tap_impl;

static zuh_ssize tap_read(zuh_stream *s, void *b, size_t n, zuh_deadline dl, zuh_error *e) {
    return zuh_stream_read(((tap_impl *)s->impl)->inner, b, n, dl, e);
}
static zuh_ssize tap_write(zuh_stream *s, const void *b, size_t n, zuh_deadline dl,
                           zuh_error *e) {
    tap_impl *t = (tap_impl *)s->impl;
    zuh_ssize w = zuh_stream_write(t->inner, b, n, dl, e);
    if (w > 0 && !zuh_buf_append(t->sent, b, (size_t)w)) abort();   /* harness OOM */
    return w;
}
static void tap_close(zuh_stream *s) { zuh_stream_close(((tap_impl *)s->impl)->inner); }
static int tap_readable(zuh_stream *s, int ms) {
    return zuh_stream_readable(((tap_impl *)s->impl)->inner, ms);
}
static void tap_destroy(zuh_stream *s) {
    tap_impl *t = (tap_impl *)s->impl;
    zuh_stream_free(t->inner);
    zuh_free(t);
    zuh_free(s);
}
static const zuh_stream_vtable k_tap_vt = {
    "tap", tap_read, tap_write, tap_close, tap_destroy, tap_readable
};

static const char *find(const char *p, size_t n, const char *needle) {
    size_t k, nl = strlen(needle);
    for (k = 0; k + nl <= n; k++) if (memcmp(p + k, needle, nl) == 0) return p + k;
    return NULL;
}

/* 1 when every request in `b` is well framed. A header block cut short at
 * the end is allowed: a failed request stops writing. A chunked or HTTP/2
 * stream is not walked; the streamed-body seeds use it, and #208 was about
 * a body with a length. */
static int requests_well_framed(const zuh_buffer *b) {
    static const char *const methods[] = { "GET ", "POST ", "HEAD ", NULL };
    const char *p, *end;
    if (b->len == 0) return 1;          /* a connection never opened */
    p = (const char *)b->data;
    end = p + b->len;
    if (b->len >= 3 && memcmp(p, "PRI", 3) == 0) return 1;
    while (p < end) {
        const char *hdr_end = find(p, (size_t)(end - p), "\r\n\r\n");
        const char *cl, *te;
        unsigned long len = 0;
        int k, known = 0;
        for (k = 0; methods[k]; k++)
            if ((size_t)(end - p) >= strlen(methods[k]) &&
                memcmp(p, methods[k], strlen(methods[k])) == 0) known = 1;
        if (!known) return 0;                     /* not the start of a request */
        if (!hdr_end) return 1;                   /* cut short at the end */
        hdr_end += 4;
        te = find(p, (size_t)(hdr_end - p), "\r\nTransfer-Encoding:");
        if (te) return 1;
        cl = find(p, (size_t)(hdr_end - p), "\r\nContent-Length:");
        if (cl) len = strtoul(cl + 17, NULL, 10);
        if ((size_t)(end - hdr_end) < len) return 0;   /* body short of its length */
        p = hdr_end + len;
    }
    return 1;
}

/* A streamed request body (§65.7): four pieces, or a failure on the third. */
typedef struct { int i, fail, released; } gen;
static zuh_code gen_next(void *ctx, const void **data, size_t *len, zuh_deadline dl,
                         zuh_error *err) {
    gen *g = (gen *)ctx;
    (void)dl;
    static const char piece[] = "piece-of-a-streamed-body";
    if (g->fail && g->i == 2) {
        zuh_error_set(err, ZUH_ERR_CANCELLED, ZUH_PHASE_WRITE, "the source failed");
        return ZUH_ERR_CANCELLED;
    }
    if (g->i >= 4) { *len = 0; return ZUH_OK; }
    g->i++;
    *data = piece; *len = sizeof piece - 1;
    return ZUH_OK;
}
static void gen_release(void *ctx) { ((gen *)ctx)->released++; }

/* §40 as the result reports it: what a header block cost, roughly. */
static size_t block_bytes(const zuh_headers *h) {
    size_t j, bytes = 0;
    const char *nm, *v;
    for (j = 0; h && zuh_headers_at(h, j, &nm, &v); j++)
        bytes += strlen(nm) + strlen(v) + 32;
    return bytes;
}

static zuh_code dial(void *ctx, const char *host, uint16_t port,
                    zuh_stream **out, zuh_error *err) {
    dialer *d = (dialer *)ctx;
    size_t i = d->next;
    (void)port;
    if (i >= d->n) {
        zuh_error_set(err, ZUH_ERR_CONNECT, ZUH_PHASE_CONNECT, "no more connections");
        return ZUH_ERR_CONNECT;
    }
    d->next++;
    strncpy(d->host[i], host, sizeof d->host[i] - 1);
    d->step[i].kind = ZUH_MOCK_DATA;
    d->step[i].data = d->part[i];
    d->step[i].len  = d->len[i];
    {
        tap_impl *t = (tap_impl *)zuh_calloc(1, sizeof *t);
        zuh_stream *s = (zuh_stream *)zuh_calloc(1, sizeof *s);
        if (t) t->inner = zuh_mock_stream_new(&d->step[i], 1, d->max_read, 0);
        if (!t || !s || !t->inner) {
            if (t) zuh_stream_free(t->inner);
            zuh_free(t); zuh_free(s);
            return ZUH_ERR_NOMEM;
        }
        /* Pinned idle, the pool keeps it; derived from the script, unread
         * bytes make it stale (§26.2) and the discard path runs. */
        if (!d->probe_from_script) zuh_mock_stream_set_readable(t->inner, 1, 0);
        t->sent = &d->sent[i];
        s->vt = &k_tap_vt; s->impl = t;
        *out = s;
    }
    return ZUH_OK;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const char *hn[] = { "Authorization" };
    static const char *hv[] = { "Bearer fuzz-secret" };
    static char upload[MAX_UPLOAD];
    dialer d;
    zuh_get_opts o;
    zuh_req_spec spec;
    zuh_pool *pool;
    zuh_result r;
    zuh_error e;
    zuh_trace tr;
    gen g;
    uint8_t sel;
    size_t i, start;
    int k;

    zuh_alloc_stats before, after;

    if (size < 1 || size > (1u << 18)) return 0;
    zuh_alloc_stats_get(&before);
    sel = data[0];
    memset(&d, 0, sizeof d);
    d.max_read = (sel & 0x3) == 0 ? 1 : (sel & 0x3) == 1 ? 7 : 0;
    d.probe_from_script = (sel & 0x40) != 0;
    for (i = 0; i < MAXC; i++)
        if (!zuh_buf_init(&d.sent[i], 0, (size_t)-1)) abort();
    if (!upload[0]) memset(upload, 'u', sizeof upload);

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
    if ((sel & 0xC) == 0xC) {
        spec.method = "POST";               /* a streamed body, below */
    } else {
        if (sel & 0x4) {
            spec.method = "POST"; spec.body = upload;
            spec.body_len = 7 + (size * 1009u) % (MAX_UPLOAD - 7);
        }
        if (sel & 0x8) spec.method = "HEAD";
    }

    pool = zuh_pool_new(NULL);
    zuh_get_opts_init(&o);
    o.dial = dial; o.dial_ctx = &d;
    o.proxy_set = 1;
    o.pool = pool;
    o.max_body = MAX_BODY;
    o.max_redirects = (sel & 0x10) ? 0 : 5;
    o.no_decode = (sel & 0x20) != 0;
    zuh_trace_init(&tr);
    o.trace = (sel & 0x40) ? &tr : NULL;
    o.stream_body = (sel & 0x3) == 3;

    for (k = 0; k < 2; k++) {
        zuh_result_init(&r);
        zuh_error_clear(&e);
        memset(&g, 0, sizeof g);
        if ((sel & 0xC) == 0xC) {
            g.fail = (sel & 0x1) != 0;
            spec.source.next = gen_next; spec.source.release = gen_release; spec.source.ctx = &g;
        }
        if (zuh_engine_perform(&r, "http://origin.test/start", &spec, &o, &e) == ZUH_OK) {
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
                if (block_bytes(zuh_open_body_trailers(r.open)) > ZUH_DEFAULT_MAX_HEADER_BYTES)
                    abort();
            }
            if (r.body.len > MAX_BODY) abort();
            if (block_bytes(&r.headers) > ZUH_DEFAULT_MAX_HEADER_BYTES) abort();
            if (block_bytes(&r.trailers) > ZUH_DEFAULT_MAX_HEADER_BYTES) abort();
            zuh_result_free(&r);
        }
        if (spec.source.ctx && g.released != 1) abort();
        memset(&spec.source, 0, sizeof spec.source);
    }
    zuh_pool_free(pool);
    for (i = 0; i < MAXC; i++) {
        if (!requests_well_framed(&d.sent[i])) abort();
        zuh_buf_free(&d.sent[i]);
    }
    zuh_alloc_stats_get(&after);
    if (after.live_blocks != before.live_blocks) abort();   /* leaked on this input */
    return 0;
}

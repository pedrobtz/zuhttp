/* Target 13 — the pulled body's API, as a state machine (§65.4, §65.5; #229).
 *
 * zuh_open_body is an object with a lifecycle: reads, peeks and consumes,
 * an abort, a free, in any order the caller likes. Every other target reads
 * a body front to back, so a bug that needs an out-of-order sequence is out
 * of their reach: #213 (abort after the wire ended left the staged bytes
 * readable) needed "read one byte, abort, read again", and survived the
 * whole suite and every fuzzer.
 *
 * Here the harness builds a well-formed response around a fuzzed payload,
 * so the body the caller should see is known, and runs a fuzzed sequence of
 * operations on the open body against a model of what each must return:
 *
 *   - what the caller has had is always a prefix of the payload, and a peek
 *     shows the bytes that come next;
 *   - a read that adds nothing and succeeds means the end, and then the
 *     caller has had the whole payload;
 *   - after an abort that left bytes undelivered, every read and peek
 *     raises ZUH_ERR_CANCELLED and delivers nothing; after one with nothing
 *     left to deliver, a read may also report the end;
 *   - zuh_open_body_done() is true once the caller has had everything, and
 *     never before it unless the body was aborted;
 *   - the body frees what it allocated, whatever the sequence.
 *
 * Input: byte 0 picks the framing (bits 0-1: Content-Length, chunked in
 * 5-byte pieces, close-delimited, Content-Length in a 1-byte-per-read
 * connection) and bit 2 sends the body in 7-byte reads; byte 1 is the
 * payload length, up to 255; the payload follows, then one byte per
 * operation: the low two bits pick it (read, peek then consume, abort,
 * check done) and the rest is its size, 1 to 64.
 */
#include "zuh_engine.h"
#include "zuh_mock_stream.h"
#include "zuh_alloc.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

typedef struct {
    zuh_mock_step step;
    size_t        max_read;
    int           used;
} dialer;

static zuh_code dial(void *ctx, const char *host, uint16_t port,
                     zuh_stream **out, zuh_error *err) {
    dialer *d = (dialer *)ctx;
    (void)host; (void)port;
    if (d->used++) {
        zuh_error_set(err, ZUH_ERR_CONNECT, ZUH_PHASE_CONNECT, "one connection only");
        return ZUH_ERR_CONNECT;
    }
    *out = zuh_mock_stream_new(&d->step, 1, d->max_read, 0);
    return *out ? ZUH_OK : ZUH_ERR_NOMEM;
}

/* The wire form of `payload` under framing `f`. */
static int build(zuh_buffer *w, int f, const uint8_t *payload, size_t n) {
    char line[64];
    size_t off;
    if (f == 1) {
        if (!zuh_buf_append_str(w, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"))
            return 0;
        for (off = 0; off < n; off += 5) {
            size_t k = n - off < 5 ? n - off : 5;
            snprintf(line, sizeof line, "%lx\r\n", (unsigned long)k);
            if (!zuh_buf_append_str(w, line) || !zuh_buf_append(w, payload + off, k) ||
                !zuh_buf_append_str(w, "\r\n"))
                return 0;
        }
        return zuh_buf_append_str(w, "0\r\n\r\n");
    }
    if (f == 2)
        snprintf(line, sizeof line, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n");
    else
        snprintf(line, sizeof line, "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\n\r\n",
                 (unsigned long)n);
    return zuh_buf_append_str(w, line) && (n == 0 || zuh_buf_append(w, payload, n));
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    zuh_alloc_stats before, after;
    const uint8_t *payload, *ops;
    size_t n, nops, i, had = 0;
    zuh_buffer wire, got;
    zuh_get_opts o;
    zuh_result r;
    zuh_error e;
    dialer d;
    int f, aborted = 0, ended = 0;

    if (size < 2) return 0;
    f = data[0] & 3;
    n = data[1];
    if (size < 2 + n) n = size - 2;
    payload = data + 2;
    ops = payload + n;
    nops = size - 2 - n;
    if (nops > 256) nops = 256;

    zuh_alloc_stats_get(&before);
    if (!zuh_buf_init(&wire, 0, (size_t)-1)) return 0;
    if (!build(&wire, f == 3 ? 0 : f, payload, n)) { zuh_buf_free(&wire); return 0; }
    memset(&d, 0, sizeof d);
    d.step.kind = ZUH_MOCK_DATA; d.step.data = wire.data; d.step.len = wire.len;
    d.max_read = f == 3 ? 1 : (data[0] & 4) ? 7 : 0;

    zuh_get_opts_init(&o);
    o.dial = dial; o.dial_ctx = &d; o.proxy_set = 1;
    o.stream_body = 1;
    o.max_redirects = 0;
    zuh_result_init(&r);
    zuh_error_clear(&e);
    if (zuh_engine_perform(&r, "http://origin.test/", NULL, &o, &e) != ZUH_OK || !r.open) {
        /* A well-formed 200 must come back with its body open. */
        if (e.code != ZUH_ERR_NOMEM) abort();
        zuh_result_free(&r);
        zuh_buf_free(&wire);
        return 0;
    }
    if (!zuh_buf_init(&got, 0, (size_t)-1)) abort();

    for (i = 0; i < nops; i++) {
        size_t k = (size_t)(ops[i] >> 2) + 1, before_len = got.len;
        zuh_code rc;
        switch (ops[i] & 3) {
        case 0:                                         /* read */
            rc = zuh_open_body_read(r.open, &got, k, &e);
            if (aborted && had < n) {
                if (rc != ZUH_ERR_CANCELLED || got.len != before_len) abort();
                break;
            }
            if (aborted && rc == ZUH_ERR_CANCELLED) break;  /* nothing was left */
            if (rc != ZUH_OK) abort();
            if (got.len - before_len > k) abort();
            had = got.len;
            if (got.len == before_len) ended = 1;
            break;
        case 1: {                                       /* peek, then consume half */
            const void *p = NULL;
            size_t len = 0;
            rc = zuh_open_body_peek(r.open, k, &p, &len, 0, &e);
            if (aborted && had < n) {
                if (rc != ZUH_ERR_CANCELLED || len != 0) abort();
                break;
            }
            if (aborted && rc == ZUH_ERR_CANCELLED) break;
            if (rc != ZUH_OK || len > k) abort();
            if (had + len > n || (len && memcmp(p, payload + had, len) != 0)) abort();
            if (len == 0) { ended = 1; break; }
            if (!zuh_buf_append(&got, p, (len + 1) / 2)) abort();
            zuh_open_body_consume(r.open, (len + 1) / 2);
            had = got.len;
            break;
        }
        case 2:                                         /* abort */
            zuh_open_body_abort(r.open);
            aborted = 1;
            break;
        default:                                        /* done? */
            if (zuh_open_body_done(r.open) && !aborted && had != n) abort();
            break;
        }
        /* What the caller has had is the payload's prefix, always. */
        if (got.len > n || (got.len && memcmp(got.data, payload, got.len) != 0)) abort();
        if (ended && !aborted && had != n) abort();     /* the end came early */
    }
    if (!aborted && had == n && ended && !zuh_open_body_done(r.open)) abort();

    zuh_buf_free(&got);
    zuh_result_free(&r);
    zuh_buf_free(&wire);
    zuh_alloc_stats_get(&after);
    if (after.live_blocks != before.live_blocks) abort();
    return 0;
}

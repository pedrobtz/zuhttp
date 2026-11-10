/* Target 13 — the pulled body's API, as a state machine (§65.4, §65.5; #229,
 * #248).
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
 *     never before it unless the body was aborted or failed;
 *   - the body frees what it allocated, whatever the sequence.
 *
 * #248 adds the paths with their own release code: HTTP/2, through an
 * in-process nghttp2 server session as ctest/test_h2.c has, a pool, and a
 * wire that fails part-way through the body. With a failure:
 *
 *   - the caller never has more than the bytes before the cut, and the end
 *     never comes;
 *   - the read that meets the failure raises and delivers nothing, and so
 *     does every read and peek after it; a silent peer is ZUH_ERR_TIMEOUT;
 *   - a body that failed is done, and its connection is not pooled (§26.3,
 *     §25.3).
 *
 * With a pool, the connection goes back only after a clean end or a clean
 * HTTP/2 cancel (§65.5): idle is 0 after any failure; over HTTP/1.1 a
 * pooled connection has had its whole response read and was never closed;
 * over HTTP/2 an end or an abort pools it. Then a second, buffered request
 * on the same pool must succeed with the whole payload, reusing the
 * connection whenever the pool kept it (and over HTTP/2 after a clean run).
 *
 * Input: byte 0 picks the options. Over HTTP/1.1, bits 0-1 the framing
 * (Content-Length, chunked in 5-byte pieces, close-delimited, Content-Length
 * in a 1-byte-per-read connection) and bit 2 7-byte reads; over HTTP/2 bits
 * 0-1 the DATA frame size (1, 7, 64 or 1000 bytes) and bit 2 a transport
 * that hands out 16 bytes per read, so a stream can be cut or cancelled
 * while its frames are still on the wire. Bit 3 pools the
 * connection, bit 4 is HTTP/2, bits 5-6 a failure part-way: the connection
 * ends, it is reset (RST_STREAM over HTTP/2, a read error over HTTP/1.1),
 * or the peer goes silent and the read times out. Byte 1 is the payload
 * length, up to 255; with a failure, the next byte is where it cuts (modulo
 * the length). The payload follows, then one byte per operation: the low
 * two bits pick it (read, peek then consume, abort, check done) and the
 * rest is its size, 1 to 64.
 */
#include "zuh_engine.h"
#include "zuh_mock_stream.h"
#include "zuh_alloc.h"
#include <nghttp2/nghttp2.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

enum { FAIL_NONE, FAIL_EOF, FAIL_RESET, FAIL_SILENT };

/* --- HTTP/1.1: the mock stream -------------------------------------------- */

typedef struct {
    zuh_mock_step step[2][2];
    size_t        nsteps[2];
    size_t        max_read;
    int           used, pin_idle;
    zuh_stream   *made[2];
} dialer;

static zuh_code dial(void *ctx, const char *host, uint16_t port,
                     zuh_stream **out, zuh_error *err) {
    dialer *d = (dialer *)ctx;
    int i = d->used;
    (void)host; (void)port;
    if (i >= 2 || d->nsteps[i] == 0) {
        zuh_error_set(err, ZUH_ERR_CONNECT, ZUH_PHASE_CONNECT, "no connection left");
        return ZUH_ERR_CONNECT;
    }
    d->used++;
    *out = zuh_mock_stream_new(d->step[i], d->nsteps[i], d->max_read, 0);
    d->made[i] = *out;
    if (*out && i == 0 && d->pin_idle) zuh_mock_stream_set_readable(*out, 1, 0);
    return *out ? ZUH_OK : ZUH_ERR_NOMEM;
}

/* The wire form of `payload` under framing `f`; *cut_at is where payload
 * byte `cut` starts in it. */
static int build(zuh_buffer *w, int f, const uint8_t *payload, size_t n,
                 size_t cut, size_t *cut_at) {
    char line[64];
    size_t off;
    *cut_at = 0;
    if (f == 1) {
        if (!zuh_buf_append_str(w, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"))
            return 0;
        for (off = 0; off < n; off += 5) {
            size_t k = n - off < 5 ? n - off : 5;
            snprintf(line, sizeof line, "%lx\r\n", (unsigned long)k);
            if (!zuh_buf_append_str(w, line)) return 0;
            if (cut >= off && cut < off + k) *cut_at = w->len + (cut - off);
            if (!zuh_buf_append(w, payload + off, k) || !zuh_buf_append_str(w, "\r\n"))
                return 0;
        }
        return zuh_buf_append_str(w, "0\r\n\r\n");
    }
    if (f == 2)
        snprintf(line, sizeof line, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n");
    else
        snprintf(line, sizeof line, "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\n\r\n",
                 (unsigned long)n);
    if (!zuh_buf_append_str(w, line)) return 0;
    *cut_at = w->len + cut;
    return n == 0 || zuh_buf_append(w, payload, n);
}

/* --- HTTP/2: an nghttp2 server session behind a zuh_stream ----------------
 *
 * The same shape as ctest/test_h2.c's: what the client writes is fed to the
 * server session, what the session emits is what the client reads. Its
 * memory is libc's, so the allocation balance is the client's alone. */

typedef struct {
    nghttp2_session *srv;
    unsigned char   *out;
    size_t           out_len, out_off, out_cap;
    int              eof, fail, closes;
    size_t           off;               /* response DATA produced so far */
} h2conn;

static struct {
    h2conn         c[2];
    int            dials;
    const uint8_t *payload;
    size_t         n, cut, frame, max_read;
    int            fail;                /* for the next response */
} S;

static void out_append(h2conn *v, const uint8_t *p, size_t n) {
    if (v->out_len + n > v->out_cap) {
        size_t cap = (v->out_len + n) * 2 + 1024;
        unsigned char *q = (unsigned char *)realloc(v->out, cap);
        if (!q) abort();
        v->out = q;
        v->out_cap = cap;
    }
    memcpy(v->out + v->out_len, p, n);
    v->out_len += n;
}

static void srv_drain(h2conn *v) {
    const uint8_t *p;
    nghttp2_ssize n;
    while ((n = nghttp2_session_mem_send2(v->srv, &p)) > 0) out_append(v, p, (size_t)n);
}

static nghttp2_ssize s_body(nghttp2_session *s, int32_t sid, uint8_t *buf, size_t len,
                            uint32_t *flags, nghttp2_data_source *src, void *ud) {
    h2conn *v = (h2conn *)ud;
    size_t lim = v->fail ? S.cut : S.n, k;
    (void)s; (void)sid; (void)src;
    if (v->off >= lim && v->fail) {
        if (v->fail == FAIL_RESET) return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
        if (v->fail == FAIL_EOF) v->eof = 1;
        return NGHTTP2_ERR_DEFERRED;     /* silent, or about to end */
    }
    k = lim - v->off;
    if (k > len) k = len;
    if (k > S.frame) k = S.frame;
    memcpy(buf, S.payload + v->off, k);
    v->off += k;
    if (!v->fail && v->off == S.n) *flags |= NGHTTP2_DATA_FLAG_EOF;
    return (nghttp2_ssize)k;
}

static int s_on_frame_recv(nghttp2_session *s, const nghttp2_frame *f, void *ud) {
    h2conn *v = (h2conn *)ud;
    if ((f->hd.type == NGHTTP2_HEADERS || f->hd.type == NGHTTP2_DATA) &&
        (f->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
        nghttp2_nv nv = { (uint8_t *)":status", (uint8_t *)"200", 7, 3, NGHTTP2_NV_FLAG_NONE };
        nghttp2_data_provider2 prd;
        v->off = 0;
        v->fail = S.fail;
        prd.source.ptr = NULL;
        prd.read_callback = s_body;
        nghttp2_submit_response2(s, f->hd.stream_id, &nv, 1, S.n ? &prd : NULL);
    }
    return 0;
}

static zuh_ssize lb_read(zuh_stream *st, void *b, size_t n, zuh_deadline d, zuh_error *e) {
    h2conn *v = (h2conn *)st->impl;
    size_t have = v->out_len - v->out_off;
    if (have == 0) {
        if (v->eof) return 0;
        if (v->fail == FAIL_SILENT) {
            /* A peer that is silently gone: the read lasts until its
             * deadline, as a socket's would. */
            while (!zuh_deadline_expired(d)) { }
            zuh_error_set(e, ZUH_ERR_TIMEOUT, ZUH_PHASE_READ, "loopback: deadline");
            return -1;
        }
        /* In a single-threaded loopback, waiting on a server with nothing
         * more to say is a bug in the client: say so at once. */
        zuh_error_set(e, ZUH_ERR_TIMEOUT, ZUH_PHASE_READ, "loopback: nothing to read");
        return -1;
    }
    if (n > have) n = have;
    if (S.max_read && n > S.max_read) n = S.max_read;
    memcpy(b, v->out + v->out_off, n);
    v->out_off += n;
    return (zuh_ssize)n;
}

static zuh_ssize lb_write(zuh_stream *st, const void *b, size_t n, zuh_deadline d, zuh_error *e) {
    h2conn *v = (h2conn *)st->impl;
    (void)d; (void)e;
    nghttp2_session_mem_recv2(v->srv, (const uint8_t *)b, n);
    srv_drain(v);
    return (zuh_ssize)n;
}

static void lb_close(zuh_stream *st) { ((h2conn *)st->impl)->closes++; }
static void lb_destroy(zuh_stream *st) { zuh_free(st); }
static int lb_readable(zuh_stream *st, int ms) {
    h2conn *v = (h2conn *)st->impl;
    (void)ms;
    return v->out_len > v->out_off || v->eof;
}
static const zuh_stream_vtable k_lb_vt = {
    "pull-h2", lb_read, lb_write, lb_close, lb_destroy, lb_readable
};

static zuh_code h2_dial(void *ctx, const char *host, uint16_t port,
                        zuh_stream **out, zuh_error *err) {
    nghttp2_session_callbacks *cb;
    zuh_stream *st;
    h2conn *v;
    (void)ctx; (void)host; (void)port;
    if (S.dials >= 2) {
        zuh_error_set(err, ZUH_ERR_CONNECT, ZUH_PHASE_CONNECT, "no connection left");
        return ZUH_ERR_CONNECT;
    }
    st = (zuh_stream *)zuh_calloc(1, sizeof *st);
    if (!st) {
        zuh_error_set(err, ZUH_ERR_NOMEM, ZUH_PHASE_CONNECT, "out of memory");
        return ZUH_ERR_NOMEM;
    }
    v = &S.c[S.dials++];
    if (nghttp2_session_callbacks_new(&cb) != 0) abort();
    nghttp2_session_callbacks_set_on_frame_recv_callback(cb, s_on_frame_recv);
    if (nghttp2_session_server_new(&v->srv, cb, v) != 0) abort();
    nghttp2_session_callbacks_del(cb);
    nghttp2_submit_settings(v->srv, NGHTTP2_FLAG_NONE, NULL, 0);
    srv_drain(v);
    st->vt = &k_lb_vt;
    st->impl = v;
    *out = st;
    return ZUH_OK;
}

static void h2_reset(void) {
    int i;
    for (i = 0; i < 2; i++) {
        if (S.c[i].srv) nghttp2_session_del(S.c[i].srv);
        free(S.c[i].out);
    }
    memset(&S, 0, sizeof S);
}

/* --- the model ------------------------------------------------------------ */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const size_t frames[4] = { 1, 7, 64, 1000 };
    zuh_alloc_stats before, after;
    const uint8_t *payload, *ops;
    size_t n, full, nops, i, had = 0, cut = 0, cut_at = 0, hdr;
    zuh_buffer wire, wire2, got;
    zuh_pool *pool = NULL;
    zuh_get_opts o;
    zuh_result r;
    zuh_error e;
    zuh_code prc;
    dialer d;
    int f, h2, pooled, fail, aborted = 0, ended = 0, failed = 0, idle_before;

    if (size < 2) return 0;
    f = data[0] & 3;
    pooled = (data[0] & 0x08) != 0;
    h2 = (data[0] & 0x10) != 0;
    fail = (data[0] >> 5) & 3;
    hdr = fail ? 3 : 2;
    if (size < hdr) return 0;
    n = data[1];
    if (size < hdr + n) n = size - hdr;
    if (fail && n == 0) fail = FAIL_NONE;              /* nothing to cut */
    if (fail) cut = data[2] % n;
    payload = data + hdr;
    ops = payload + n;
    nops = size - hdr - n;
    if (nops > 256) nops = 256;
    full = n;
    /* A close-delimited body that the connection ends early is a shorter
     * body, not a failure (§18.1 rule 5): the model's payload is the cut. */
    if (!h2 && f == 2 && fail == FAIL_EOF) { n = cut; fail = FAIL_NONE; }

    zuh_alloc_stats_get(&before);
    if (!zuh_buf_init(&wire, 0, (size_t)-1) || !zuh_buf_init(&wire2, 0, (size_t)-1)) abort();
    memset(&d, 0, sizeof d);
    h2_reset();
    zuh_get_opts_init(&o);
    o.proxy_set = 1;
    o.stream_body = 1;
    o.max_redirects = 0;
    /* A silent peer must cost milliseconds, not the default 30 s. */
    if (fail == FAIL_SILENT) o.body_timeout_ms = 5;
    if (h2) {
        S.payload = payload; S.n = full; S.cut = cut; S.frame = frames[f]; S.fail = fail;
        S.max_read = (data[0] & 4) ? 16 : 0;
        o.dial = h2_dial;
        o.http2 = ZUH_H2_REQUIRED;
    } else {
        size_t c2;
        int bf = f == 3 ? 0 : f;
        if (!build(&wire, bf, payload, full, cut, &cut_at) ||
            !build(&wire2, bf, payload, full, 0, &c2)) abort();
        d.max_read = f == 3 ? 1 : (data[0] & 4) ? 7 : 0;
        d.step[0][0].kind = ZUH_MOCK_DATA;
        d.step[0][0].data = wire.data;
        d.step[0][0].len = fail || (f == 2 && n < full) ? cut_at : wire.len;
        d.nsteps[0] = 2;
        if (fail == FAIL_RESET) { d.step[0][1].kind = ZUH_MOCK_ERROR; d.step[0][1].code = ZUH_ERR_IO; }
        else if (fail == FAIL_SILENT) d.step[0][1].kind = ZUH_MOCK_BLOCK;
        else if (fail == FAIL_EOF || f == 2) d.step[0][1].kind = ZUH_MOCK_EOF;
        else {
            /* The answer to the second request on this connection, if it is
             * pooled. dial() pins the liveness probe to "idle", so the pool
             * cannot see whether the first body was read to its end: the
             * second response can. Bytes of the first left on the wire would
             * be parsed as the second's. */
            d.step[0][1].kind = ZUH_MOCK_DATA;
            d.step[0][1].data = wire2.data;
            d.step[0][1].len = wire2.len;
            d.pin_idle = 1;
        }
        d.step[1][0].kind = ZUH_MOCK_DATA;
        d.step[1][0].data = wire2.data;
        d.step[1][0].len = wire2.len;
        d.nsteps[1] = 1;
        o.dial = dial;
        o.dial_ctx = &d;
    }
    if (pooled) {
        pool = zuh_pool_new(NULL);
        if (!pool) abort();
        o.pool = pool;
    }
    zuh_result_init(&r);
    zuh_error_clear(&e);
    prc = zuh_engine_perform(&r, "http://origin.test/", NULL, &o, &e);
    if (prc != ZUH_OK || !r.open) {
        /* A well-formed 200 comes back with its body open; a wire that
         * fails can fail before the headers are handed back. */
        if (prc == ZUH_OK || (e.code != ZUH_ERR_NOMEM && !fail)) abort();
        failed = 1;
    }
    if (!zuh_buf_init(&got, 0, (size_t)-1)) abort();

    for (i = 0; i < nops && r.open; i++) {
        size_t k = (size_t)(ops[i] >> 2) + 1, before_len = got.len;
        zuh_code rc;
        switch (ops[i] & 3) {
        case 0:                                         /* read */
            rc = zuh_open_body_read(r.open, &got, k, &e);
            if (failed) {
                if (rc == ZUH_OK || got.len != before_len) abort();
                break;
            }
            if (aborted && had < n) {
                if (rc != ZUH_ERR_CANCELLED || got.len != before_len) abort();
                break;
            }
            if (aborted && rc == ZUH_ERR_CANCELLED) break;  /* nothing was left */
            if (rc != ZUH_OK) {
                /* Only an injected failure explains an error, it delivers
                 * nothing, and a silent peer is a timeout. */
                if (!fail || got.len != before_len) abort();
                if (fail == FAIL_SILENT && rc != ZUH_ERR_TIMEOUT) abort();
                failed = 1;
                break;
            }
            if (got.len - before_len > k) abort();
            had = got.len;
            if (got.len == before_len) ended = 1;
            break;
        case 1: {                                       /* peek, then consume half */
            const void *p = NULL;
            size_t len = 0;
            rc = zuh_open_body_peek(r.open, k, &p, &len, 0, &e);
            if (failed) {
                if (rc == ZUH_OK || len != 0) abort();
                break;
            }
            if (aborted && had < n) {
                if (rc != ZUH_ERR_CANCELLED || len != 0) abort();
                break;
            }
            if (aborted && rc == ZUH_ERR_CANCELLED) break;
            if (rc != ZUH_OK) {
                if (!fail || len != 0) abort();
                if (fail == FAIL_SILENT && rc != ZUH_ERR_TIMEOUT) abort();
                failed = 1;
                break;
            }
            if (len > k) abort();
            if (had + len > n || (len && memcmp(p, payload + had, len) != 0)) abort();
            if (len == 0) { ended = 1; break; }
            if (!zuh_buf_append(&got, p, (len + 1) / 2)) abort();
            zuh_open_body_consume(r.open, (len + 1) / 2);
            had = got.len;
            break;
        }
        case 2:                                         /* abort */
            zuh_open_body_abort(r.open);
            if (!failed) aborted = 1;                   /* a failed body stays failed */
            break;
        default:                                        /* done? */
            if (zuh_open_body_done(r.open) && !aborted && !failed && had != n) abort();
            if (failed && !zuh_open_body_done(r.open)) abort();
            break;
        }
        /* What the caller has had is the payload's prefix, always, and with
         * a failure never past the cut. */
        if (got.len > n || (got.len && memcmp(got.data, payload, got.len) != 0)) abort();
        if (fail && got.len > cut) abort();
        if (ended && (fail || (!aborted && had != n))) abort();  /* an end, early or impossible */
        if (pool) {
            size_t idle = zuh_pool_idle_count(pool);
            /* §26.3, §25.3: a failed or timed-out body never pools. */
            if (failed && idle != 0) abort();
            if (!h2 && fail && idle != 0) abort();     /* the HTTP/1.1 wire never ended */
            /* Over HTTP/1.1 a pooled connection is never close-delimited and
             * was never closed; that it was read to the end of its response
             * is the second request's to show. */
            if (!h2 && idle == 1 && (f == 2 || zuh_mock_stream_closed(d.made[0]))) abort();
            /* An end pools it; over HTTP/2 a clean cancel does too (§65.5). */
            if (ended && !failed && (h2 || f != 2) && idle != 1) abort();
            if (h2 && !fail && aborted && idle != 1) abort();
        }
    }
    if (r.open && !aborted && !failed && had == n && ended && !zuh_open_body_done(r.open))
        abort();

    zuh_buf_free(&got);
    zuh_result_free(&r);                                /* aborts what is still open */
    if (pool) {
        size_t idle = zuh_pool_idle_count(pool);
        if (failed && idle != 0) abort();
        if (!h2 && fail && idle != 0) abort();
        if (h2 && !fail && !failed && idle != 1) abort();
        idle_before = (int)idle;
        /* The connection the pool kept serves the next request whole. */
        S.fail = FAIL_NONE;
        o.stream_body = 0;
        o.body_timeout_ms = 0;
        zuh_result_init(&r);
        zuh_error_clear(&e);
        prc = zuh_engine_perform(&r, "http://origin.test/again", NULL, &o, &e);
        if (prc != ZUH_OK) {
            if (e.code != ZUH_ERR_NOMEM) abort();
        } else {
            if (r.status != 200 || r.body.len != full ||
                (full && memcmp(r.body.data, payload, full) != 0)) abort();
            if (h2 && !fail && idle_before && (!r.reused_connection || S.dials != 1)) abort();
            if (!h2 && idle_before && !r.reused_connection) abort();
        }
        zuh_result_free(&r);
        zuh_pool_free(pool);
    }
    if (h2 && S.c[0].closes > 1) abort();               /* closed once at most */
    h2_reset();
    zuh_buf_free(&wire);
    zuh_buf_free(&wire2);
    zuh_alloc_stats_get(&after);
    if (after.live_blocks != before.live_blocks) abort();
    return 0;
}

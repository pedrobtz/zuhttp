/* Target 2 — chunked decoder (§18.2, §43).
 *
 * Decoding is in place, so an overrun shows up as a heap-buffer-overflow.
 * A decoder that drops a byte at a chunk boundary, or hands the caller the
 * framing bytes of a call that failed (#210), shows up as nothing at all,
 * so the target compares (#239):
 *
 *   - GRAMMAR. Every run against g_decode_chunked() in http_grammar.h, an
 *     independent decoder of RFC 9112 §7.1: the same verdict (done, more,
 *     refused); once done, the same payload, trailer fields and surplus;
 *     while more is needed, every payload byte that has arrived; after a
 *     refusal, a prefix of the payload and nothing from the failed call
 *     (*len is 0, as zuh_response.h promises). zuhttp is held to the
 *     grammar with picohttpparser's reading of chunk extensions, and that
 *     reading to accepting everything the strict ABNF accepts.
 *   - PIECES. The same wire bytes decoded whole, split at the byte the
 *     first input byte picks, one byte per call, and, for short inputs,
 *     split at every offset: all of them are checked against the grammar,
 *     so all of them agree.
 *   - ROUND TRIP. An accepted body re-encoded in other chunk sizes, its
 *     trailers written back with zuh_headers_write, decodes to the same
 *     payload, trailers and surplus.
 *
 * Input: byte 0 picks the split point (modulo the length) and the chunk size
 * of the re-encoding (bits 6-7: 1, 7, 300, 16384); the rest is the wire.
 */
#include "zuh_response.h"
#include "zuh_alloc.h"
#include "http_grammar.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* One call per byte re-parses the trailer section on each call. */
#define BYTEWISE_MAX  4096u
#define EVERY_SPLIT_MAX 256u

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

typedef struct {
    int        klass;
    zuh_buffer out;
    size_t     surplus;
    zuh_chunked c;
} run_t;

static void free_run(run_t *r) {
    zuh_buf_free(&r->out);
    zuh_chunked_free(&r->c);
}

/* Decode `w` in pieces: whole when `split` is 0 or past the end, else at
 * `split` and then the rest, or a byte per call when `bytewise`. 0 when
 * the harness ran out of memory, which says nothing about the decoder. */
static int run(const uint8_t *w, size_t n, size_t split, int bytewise, run_t *r) {
    size_t off = 0;
    memset(r, 0, sizeof *r);
    if (!zuh_buf_init(&r->out, 0, (size_t)-1)) return 0;
    if (zuh_chunked_init(&r->c) != ZUH_OK) { zuh_buf_free(&r->out); return 0; }
    r->klass = G_MORE;
    while (off < n) {
        size_t end = bytewise ? off + 1 : (split > off && split < n) ? split : n;
        size_t len = end - off, offered = len;
        zuh_error e;
        zuh_code rc;
        char *buf = (char *)malloc(len);
        if (!buf) return 0;
        memcpy(buf, w + off, len);
        rc = zuh_chunked_decode(&r->c, buf, &len, &e);
        off = end;
        if (rc == ZUH_ERR_NOMEM) { free(buf); return 0; }
        if (rc != ZUH_OK && rc != ZUH_ERR_WOULDBLOCK) {
            /* After a refusal no byte of the call is output (#210). */
            G_CHECK(len == 0);
            free(buf);
            r->klass = G_BAD;
            return 1;
        }
        G_CHECK(len <= offered);
        if (len && !zuh_buf_append(&r->out, buf, len)) { free(buf); return 0; }
        free(buf);
        if (rc == ZUH_OK) {
            /* What was never offered is surplus too. */
            r->klass = G_OK;
            r->surplus = r->c.surplus + (n - off);
            return 1;
        }
    }
    return 1;
}

static void same_trailers(const zuh_headers *h, const g_fields *t) {
    size_t i;
    G_CHECK(zuh_headers_total(h) == t->n);
    for (i = 0; i < t->n; i++) {
        const char *nm, *v;
        G_CHECK(zuh_headers_at(h, i, &nm, &v));
        G_CHECK(strlen(nm) == t->f[i].nlen && memcmp(nm, t->f[i].name, t->f[i].nlen) == 0);
        G_CHECK(strlen(v) == t->f[i].vlen &&
                (t->f[i].vlen == 0 || memcmp(v, t->f[i].value, t->f[i].vlen) == 0));
    }
}

/* D-101 parses a trailer section once it is complete, or past §40's 64 KiB,
 * as picohttpparser does a response head. So a trailer line that can already
 * never be valid ("0\r\nhSll@o": no field name holds '@') is refused at the
 * end of the line, not at its first bad byte, and zuhttp still wants more
 * where the grammar has refused. That deferral is allowed, and only that one:
 * the decoder is in the trailer section, it has delivered exactly the
 * grammar's payload, and the same bytes with the line and the section closed
 * are refused, delivering nothing more. A deferral that ended in acceptance
 * would be a real bug, and still aborts. */
static int deferred_trailer_refusal(const run_t *r, const g_chunked *m,
                                    const unsigned char *mout,
                                    const uint8_t *w, size_t n) {
    run_t closed;
    uint8_t *wc;
    int ok;
    if (!(r->klass == G_MORE && m->rc == G_BAD && r->c.in_trailer)) return 0;
    G_CHECK(r->out.len == m->outlen);
    G_CHECK(r->out.len == 0 || memcmp(r->out.data, mout, r->out.len) == 0);
    wc = (uint8_t *)malloc(n + 4);
    if (!wc) return 1;
    memcpy(wc, w, n);
    memcpy(wc + n, "\r\n\r\n", 4);
    ok = run(wc, n + 4, 0, 0, &closed);
    free(wc);
    if (ok) {
        G_CHECK(closed.klass == G_BAD);
        G_CHECK(closed.out.len <= m->outlen);
    }
    free_run(&closed);
    return 1;
}

/* One run against the grammar's verdict and payload. */
static void check_run(const run_t *r, const g_chunked *m, const unsigned char *mout,
                      const uint8_t *w, size_t n) {
    if (deferred_trailer_refusal(r, m, mout, w, n)) return;
    G_CHECK(r->klass == m->rc);
    if (r->klass == G_BAD) {
        G_CHECK(r->out.len <= m->outlen);
        G_CHECK(r->out.len == 0 || memcmp(r->out.data, mout, r->out.len) == 0);
        return;
    }
    G_CHECK(r->out.len == m->outlen);
    G_CHECK(r->out.len == 0 || memcmp(r->out.data, mout, r->out.len) == 0);
    if (r->klass == G_OK) {
        same_trailers(&r->c.trailers, &m->t);
        G_CHECK(r->surplus == m->surplus);
    }
}

/* The accepted body as a sender would write it, in `piece`-byte chunks. */
static void round_trip(const run_t *whole, const uint8_t *wire, size_t n, size_t piece) {
    zuh_buffer enc;
    run_t again;
    size_t off = 0;
    char hex[24];
    if (!zuh_buf_init(&enc, 0, (size_t)-1)) return;
    while (off < whole->out.len) {
        size_t k = whole->out.len - off < piece ? whole->out.len - off : piece;
        snprintf(hex, sizeof hex, "%lx\r\n", (unsigned long)k);
        if (!zuh_buf_append_str(&enc, hex) || !zuh_buf_append(&enc, whole->out.data + off, k) ||
            !zuh_buf_append(&enc, "\r\n", 2))
            goto out;
        off += k;
    }
    if (!zuh_buf_append_str(&enc, "0\r\n") || !zuh_headers_write(&whole->c.trailers, &enc) ||
        !zuh_buf_append(&enc, "\r\n", 2) ||
        (whole->surplus && !zuh_buf_append(&enc, wire + n - whole->surplus, whole->surplus)))
        goto out;
    if (run((const uint8_t *)enc.data, enc.len, 0, 0, &again)) {
        size_t i;
        G_CHECK(again.klass == G_OK);
        G_CHECK(again.out.len == whole->out.len &&
                (again.out.len == 0 ||
                 memcmp(again.out.data, whole->out.data, again.out.len) == 0));
        G_CHECK(again.surplus == whole->surplus);
        G_CHECK(zuh_headers_total(&again.c.trailers) == zuh_headers_total(&whole->c.trailers));
        for (i = 0; i < zuh_headers_total(&whole->c.trailers); i++) {
            const char *an, *av, *bn, *bv;
            G_CHECK(zuh_headers_at(&again.c.trailers, i, &an, &av) &&
                    zuh_headers_at(&whole->c.trailers, i, &bn, &bv));
            G_CHECK(strcmp(an, bn) == 0 && strcmp(av, bv) == 0);
        }
    }
    free_run(&again);
out:
    zuh_buf_free(&enc);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const size_t pieces[4] = { 1, 7, 300, 16384 };
    g_chunked *lax, *strict;
    unsigned char *lout, *sout;
    run_t r;
    size_t split, piece, s;
    uint8_t sel;

    if (size < 2 || size > 64 * 1024) return 0;
    sel = data[0];
    split = sel % size;
    data++; size--;

    lax = (g_chunked *)malloc(sizeof *lax);
    strict = (g_chunked *)malloc(sizeof *strict);
    lout = (unsigned char *)malloc(size);
    sout = (unsigned char *)malloc(size);
    if (!lax || !strict || !lout || !sout) goto done;
    g_decode_chunked(data, size, 0, lout, lax);
    g_decode_chunked(data, size, 1, sout, strict);
    /* What the ABNF accepts, the reading zuhttp is held to accepts alike. */
    if (strict->rc == G_OK) {
        G_CHECK(lax->rc == G_OK && lax->outlen == strict->outlen &&
                lax->surplus == strict->surplus && lax->t.n == strict->t.n);
        G_CHECK(lax->outlen == 0 || memcmp(lout, sout, lax->outlen) == 0);
    }

    /* Whole, then the re-encoding of what it accepted. */
    if (run(data, size, 0, 0, &r)) {
        check_run(&r, lax, lout, data, size);
        if (r.klass == G_OK) {
            piece = pieces[(sel >> 6) & 3];
            /* Five bytes of framing per 1-byte chunk is 83%, which
             * picohttpparser refuses once it passes 100 KB (§18.1). */
            if (piece == 1 && r.out.len > 16384) piece = 7;
            round_trip(&r, data, size, piece);
        }
    }
    free_run(&r);

    if (run(data, size, split, 0, &r)) check_run(&r, lax, lout, data, size);
    free_run(&r);

    if (size <= BYTEWISE_MAX && run(data, size, 0, 1, &r)) check_run(&r, lax, lout, data, size);
    free_run(&r);

    if (size <= EVERY_SPLIT_MAX) {
        for (s = 1; s < size; s++) {
            if (run(data, size, s, 0, &r)) check_run(&r, lax, lout, data, size);
            free_run(&r);
        }
    }
done:
    free(lax);
    free(strict);
    free(lout);
    free(sout);
    return 0;
}

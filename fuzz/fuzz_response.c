/* Target 1 — response parser wrapper (design §43, §50.3).
 *
 * Drives the whole header-block path the way the engine does, then decides
 * framing. A crash here is reachable from any server on the internet, but
 * a crash is the least of what can go wrong: a parser that takes a bare CR
 * as a line end, or a hint that makes the incremental parse end somewhere
 * the whole parse does not, crashes nothing. So the target compares (#239):
 *
 *   - GRAMMAR. The input parsed whole against http_grammar.h, an
 *     independent reading of RFC 9112 §4 and §5 with the §40 limits: both
 *     accept with the same status, version, reason, field list and
 *     `consumed`, or both refuse, or both ask for more. The one licensed
 *     difference is picohttpparser waiting for 9 bytes, and for 4 from the
 *     status code, before it judges (g_head.early).
 *   - READ SIZE. The same bytes offered one more byte at a time with the
 *     last_len hint, as the engine reads them: accepted exactly when the
 *     whole parse accepts, with the same result. The hint only checks for
 *     a blank line, so a malformed head may be refused late, or not at all
 *     before its blank line arrives; it is never accepted.
 *   - ROUND TRIP. An accepted head written back out (status line, then
 *     zuh_headers_write) and parsed again gives the same response, and is
 *     consumed to its last byte.
 *   - FRAMING. zuh_response_decide_framing, for GET and for HEAD, against
 *     the §18.1 table and RFC 9112 §6 written out again here over the
 *     grammar's field list.
 */
#include "zuh_response.h"
#include "zuh_alloc.h"
#include "http_grammar.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int klass(zuh_code rc) {
    if (rc == ZUH_OK) return G_OK;
    if (rc == ZUH_ERR_WOULDBLOCK) return G_MORE;
    return G_BAD;
}

/* An accepted response is the grammar's head, field for field. */
static void same_as_model(const zuh_response *r, size_t consumed, const g_head *m) {
    size_t i, rl = m->rlen < ZUH_REASON_MAX - 1 ? m->rlen : ZUH_REASON_MAX - 1;
    G_CHECK(consumed == m->h.end);
    G_CHECK(r->status == m->status && r->minor_version == m->minor);
    G_CHECK(strlen(r->reason) == rl && (rl == 0 || memcmp(r->reason, m->reason, rl) == 0));
    G_CHECK(zuh_headers_total(&r->headers) == m->h.n);
    for (i = 0; i < m->h.n; i++) {
        const char *n, *v;
        const g_field *f = &m->h.f[i];
        G_CHECK(zuh_headers_at(&r->headers, i, &n, &v));
        G_CHECK(strlen(n) == f->nlen && memcmp(n, f->name, f->nlen) == 0);
        G_CHECK(strlen(v) == f->vlen && (f->vlen == 0 || memcmp(v, f->value, f->vlen) == 0));
    }
}

static void same_response(const zuh_response *a, const zuh_response *b) {
    size_t i;
    G_CHECK(a->status == b->status && a->minor_version == b->minor_version);
    G_CHECK(strcmp(a->reason, b->reason) == 0);
    G_CHECK(zuh_headers_total(&a->headers) == zuh_headers_total(&b->headers));
    for (i = 0; i < zuh_headers_total(&a->headers); i++) {
        const char *an, *av, *bn, *bv;
        G_CHECK(zuh_headers_at(&a->headers, i, &an, &av) &&
                zuh_headers_at(&b->headers, i, &bn, &bv));
        G_CHECK(strcmp(an, bn) == 0 && strcmp(av, bv) == 0);
    }
}

/* §18.1 and RFC 9112 §6, over the grammar's fields. 0 when refused. */
static int model_framing(const g_head *m, int head, zuh_framing *f) {
    size_t i, n_cl = 0, n_te = 0;
    const g_field *cl = NULL, *te = NULL;
    memset(f, 0, sizeof *f);
    for (i = 0; i < m->h.n; i++) {
        const g_field *x = &m->h.f[i];
        if (g_name_is(x->name, x->nlen, "content-length")) { n_cl++; cl = x; }
        if (g_name_is(x->name, x->nlen, "transfer-encoding")) { n_te++; te = x; }
    }
    /* Both, or either twice: refused, never reconciled (D-15). */
    if ((n_cl && n_te) || n_cl > 1 || n_te > 1) return 0;
    /* `chunked` alone is the only coding taken (§18.1, §21.4). */
    if (te && !g_name_is(te->value, te->vlen, "chunked")) return 0;
    if (cl) {
        /* Content-Length = 1*DIGIT, in a uint64; checked even when the
         * response can have no content. */
        uint64_t v = 0;
        if (cl->vlen == 0) return 0;
        for (i = 0; i < cl->vlen; i++) {
            unsigned d;
            if (!g_digit(cl->value[i])) return 0;
            d = (unsigned)(cl->value[i] - '0');
            if (v > (UINT64_MAX - d) / 10u) return 0;
            v = v * 10u + d;
        }
        f->length = v;
    }
    f->poolable = 1;
    /* RFC 9112 §6.1: an HTTP/1.0 message with Transfer-Encoding is treated
     * as faulty framing, "and close the connection after processing the
     * message": the sender may have kept part of it back. */
    if (te && m->minor == 0) f->poolable = 0;
    /* RFC 9112 §6.3 rule 1: HEAD, 1xx, 204 and 304 have no content. */
    if (head || (m->status >= 100 && m->status <= 199) || m->status == 204 ||
        m->status == 304) {
        f->kind = ZUH_FRAME_NONE;
        f->length = 0;
        return 1;
    }
    if (te) { f->kind = ZUH_FRAME_CHUNKED; f->length = 0; return 1; }
    if (cl) { f->kind = ZUH_FRAME_LENGTH; return 1; }
    f->kind = ZUH_FRAME_UNTIL_CLOSE;        /* rule 7: to the close, unpooled */
    f->poolable = 0;
    return 1;
}

static void check_framing(zuh_response *r, const g_head *m) {
    int head;
    for (head = 0; head <= 1; head++) {
        zuh_framing want;
        zuh_error e;
        int ok = model_framing(m, head, &want);
        zuh_code rc = zuh_response_decide_framing(r, head, &e);
        G_CHECK((rc == ZUH_OK) == ok);
        if (!ok) continue;
        G_CHECK(r->framing.kind == want.kind && r->framing.poolable == want.poolable);
        G_CHECK(want.kind != ZUH_FRAME_LENGTH || r->framing.length == want.length);
    }
}

/* The response as a sender would write it, parsed back. */
static void round_trip(const zuh_response *r) {
    zuh_buffer w;
    zuh_response again;
    zuh_error e;
    size_t consumed = 0;
    char line[32];
    zuh_code rc;
    if (!zuh_buf_init(&w, 0, (size_t)-1)) return;
    snprintf(line, sizeof line, "HTTP/1.%d %03d ", r->minor_version, r->status);
    if (!zuh_buf_append_str(&w, line) || !zuh_buf_append_str(&w, r->reason) ||
        !zuh_buf_append(&w, "\r\n", 2) || !zuh_headers_write(&r->headers, &w) ||
        !zuh_buf_append(&w, "\r\n", 2)) {
        zuh_buf_free(&w);
        return;
    }
    zuh_response_init(&again);
    rc = zuh_response_parse(&again, (const char *)w.data, w.len, 0, &consumed, &e);
    if (rc != ZUH_ERR_NOMEM) {
        G_CHECK(rc == ZUH_OK && consumed == w.len);
        same_response(r, &again);
    }
    zuh_response_free(&again);
    zuh_buf_free(&w);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    zuh_response whole, inc;
    zuh_error e;
    size_t consumed = 0, inc_consumed = 0, last = 0, i;
    zuh_code rc, irc = ZUH_ERR_WOULDBLOCK;
    g_head *m;
    if (size > 64 * 1024) return 0;
    m = (g_head *)malloc(sizeof *m);
    if (!m) return 0;
    g_parse_head(data, size, m);

    /* Grammar: the whole input at once. */
    zuh_response_init(&whole);
    rc = zuh_response_parse(&whole, (const char *)data, size, 0, &consumed, &e);
    if (rc != ZUH_ERR_NOMEM) {
        int k = klass(rc);
        G_CHECK(m->rc == G_BAD ? (k == G_BAD || (k == G_MORE && m->early)) : k == m->rc);
        if (rc == ZUH_OK) {
            same_as_model(&whole, consumed, m);
            round_trip(&whole);
            check_framing(&whole, m);
        }
    }

    /* Read size: one more byte per call, with the hint, until it decides. */
    zuh_response_init(&inc);
    for (i = 1; i <= size; i++) {
        irc = zuh_response_parse(&inc, (const char *)data, i, last, &inc_consumed, &e);
        last = i;
        if (irc != ZUH_ERR_WOULDBLOCK) break;
    }
    if (irc != ZUH_ERR_NOMEM && rc != ZUH_ERR_NOMEM) {
        G_CHECK((irc == ZUH_OK) == (rc == ZUH_OK));
        if (irc == ZUH_OK) {
            G_CHECK(inc_consumed == consumed);
            same_response(&whole, &inc);
        } else if (irc != ZUH_ERR_WOULDBLOCK) {
            G_CHECK(m->rc == G_BAD);
        }
    }
    (void)zuh_response_is_informational(&inc);
    zuh_response_free(&inc);
    zuh_response_free(&whole);
    free(m);
    return 0;
}

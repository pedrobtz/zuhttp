/* zuhttp — the HTTP/2 driver (design §65.2). See zuh_h2.h for the model. */
#include "zuh_h2.h"
#include "zuh_alloc.h"
#include "zuh_buffer.h"
#include "zuh_time.h"

#include <stdio.h>
#include <string.h>
#include <nghttp2/nghttp2.h>

#define H2_READ_CHUNK 16384
/* DATA held between a mem_recv2() call and the pipe. One read is at most
 * H2_READ_CHUNK bytes of frames, so the buffer never holds more than that;
 * the cap is a backstop, not a tuning knob. */
#define H2_DATA_MAX   (1024u * 1024u)

const char *zuh_h2_alpn_for(zuh_h2_mode m) {
    /* REQUIRED offers http/1.1 too. Offering h2 alone would let a server
     * that has ALPN but not h2 end the handshake with a
     * no_application_protocol alert (RFC 7301 §3.2), a TLS error, where
     * §65.1 promises zu_connect_error naming the protocol it did choose. */
    return m == ZUH_H2_OFF ? "http/1.1" : "h2,http/1.1";
}

int zuh_h2_alpn_is_h2(const char *selected) {
    return selected && strcmp(selected, "h2") == 0;
}

typedef struct {
    zuh_stream      *inner;
    nghttp2_session *sess;
    size_t           max_header_bytes;

    /* The one open stream (D-67) and what has happened on it. Reset by
     * zuh_h2_begin(); nothing here outlives a request but `failed`. */
    int32_t      sid;
    int          status;
    zuh_headers *hdrs;          /* the caller's: the final response block */
    zuh_headers  trailers;      /* §65.3 exposes them (W21); kept, bounded */
    int          in_trailers;   /* the block being received is the trailers */
    int          headers_done;  /* the final response block is complete */
    int          ended_on_headers;
    int          closed;
    uint32_t     close_code;
    /* RST_STREAM came from the server. When nghttp2 resets the stream
     * itself, because the response broke RFC 9113's message rules (a bad
     * header, a content-length that disagrees with the DATA), this stays 0
     * and the outcome is a malformed response, not the server's choice. */
    int          peer_reset;
    int          goaway;
    int          failed;        /* the session is unusable from here on */
    int          cancelled;     /* we reset the stream (§65.5): not a failure */
    int          ping_acked;    /* a PING ACK arrived (§65.6) */
    zuh_millis   last_frame;    /* last bytes in either direction (§65.6) */
    zuh_code     cb_code;       /* raised inside a callback */
    char         cb_msg[160];
    zuh_buffer   data;

    const unsigned char *body;
    size_t       body_len, body_off;
    /* §65.7: the unsent part of an in-memory body, copied once a pulled
     * response outlives the call that lent `body` (zuh_h2_own_body()). */
    unsigned char *body_owned;
    uint64_t     body_sent;     /* request DATA bytes handed to nghttp2 */

    /* §65.7: a streamed request body, borrowed for the open stream only. */
    zuh_body_source src;
    const unsigned char *src_data;
    size_t       src_len, src_off;
    int          src_end, src_failed;
    int          in_source;     /* inside src.next(): nghttp2 is mid-call */
    zuh_deadline send_dl;       /* the flush() that called it, for src.next() */
    zuh_error    src_err;
} h2_impl;

static const zuh_stream_vtable h2_vt;

int zuh_h2_is(const zuh_stream *s) { return s && s->vt == &h2_vt; }

zuh_stream *zuh_h2_transport(zuh_stream *s) {
    return zuh_h2_is(s) ? ((h2_impl *)s->impl)->inner : s;
}

/* --- allocation through zuh_alloc, so §43's allocation-balance oracle and
 * the alloc-failure tests see nghttp2's memory too --- */

static void *mem_malloc(size_t n, void *ud) { (void)ud; return zuh_alloc(n); }
static void  mem_free(void *p, void *ud) { (void)ud; zuh_free(p); }
static void *mem_calloc(size_t c, size_t n, void *ud) { (void)ud; return zuh_calloc(c, n); }
static void *mem_realloc(void *p, size_t n, void *ud) { (void)ud; return zuh_realloc(p, n); }

/* --- callbacks --- */

/* A block's headers object, holding the limit this session advertised in
 * SETTINGS_MAX_HEADER_LIST_SIZE: the one counter of D-101, so the value the
 * server is told and the value enforced are the same variable. */
static void h2_headers_init(h2_impl *h, zuh_headers *hd) {
    zuh_headers_init(hd);
    hd->max_bytes = h->max_header_bytes;
}

static int cb_fail(h2_impl *h, zuh_code code, const char *msg) {
    if (h->cb_code == ZUH_OK) {
        h->cb_code = code;
        strncpy(h->cb_msg, msg, sizeof h->cb_msg - 1);
        h->cb_msg[sizeof h->cb_msg - 1] = '\0';
    }
    return NGHTTP2_ERR_CALLBACK_FAILURE;
}

static int on_begin_headers(nghttp2_session *s, const nghttp2_frame *f, void *ud) {
    h2_impl *h = (h2_impl *)ud;
    (void)s;
    if (f->hd.type != NGHTTP2_HEADERS || f->hd.stream_id != h->sid) return 0;
    if (h->headers_done) {
        /* A second block after the final response is the trailers. */
        h->in_trailers = 1;
    } else {
        /* A response block: the first, or the one after a 1xx. `hdrs` is
         * the caller's, and only while zuh_h2_begin() runs (review #178). */
        if (!h->hdrs)
            return cb_fail(h, ZUH_ERR_PARSE, "HTTP/2 response headers arrived outside a request");
        zuh_headers_free(h->hdrs);
        h2_headers_init(h, h->hdrs);
        h->status = 0;
    }
    return 0;
}

static int on_header(nghttp2_session *s, const nghttp2_frame *f,
                     const uint8_t *name, size_t nlen,
                     const uint8_t *value, size_t vlen, uint8_t flags, void *ud) {
    h2_impl *h = (h2_impl *)ud;
    zuh_code rc;
    (void)s; (void)flags;
    if (f->hd.type != NGHTTP2_HEADERS || f->hd.stream_id != h->sid) return 0;

    if (nlen > 0 && name[0] == ':') {
        /* nghttp2 has validated the pseudo-headers (RFC 9113 §8.3.2): only
         * :status reaches a client, once, as three digits. */
        if (!h->in_trailers && nlen == 7 && memcmp(name, ":status", 7) == 0 && vlen == 3)
            h->status = (value[0] - '0') * 100 + (value[1] - '0') * 10 + (value[2] - '0');
        return 0;
    }
    if (!h->in_trailers && !h->hdrs)
        return cb_fail(h, ZUH_ERR_PARSE, "HTTP/2 response headers arrived outside a request");
    /* §40 for each block on its own (§65.3), by D-101's one rule: the
     * headers object charges name + value + 32 a field against the block's
     * limit, pseudo-header fields excluded, exactly as on HTTP/1.1. */
    rc = zuh_headers_add(h->in_trailers ? &h->trailers : h->hdrs,
                         (const char *)name, nlen, (const char *)value, vlen);
    if (rc == ZUH_ERR_NOMEM) return cb_fail(h, rc, "out of memory");
    if (rc == ZUH_ERR_BODY_LIMIT)
        return cb_fail(h, ZUH_ERR_PARSE, h->in_trailers
                       ? "HTTP/2 trailer block exceeds a header limit"
                       : "HTTP/2 response header block exceeds a header limit");
    if (rc != ZUH_OK)
        return cb_fail(h, ZUH_ERR_PARSE, "HTTP/2 response header is invalid");
    return 0;
}

static int on_frame_recv(nghttp2_session *s, const nghttp2_frame *f, void *ud) {
    h2_impl *h = (h2_impl *)ud;
    (void)s;
    if (f->hd.type == NGHTTP2_GOAWAY) { h->goaway = 1; return 0; }
    if (f->hd.type == NGHTTP2_PING && (f->hd.flags & NGHTTP2_FLAG_ACK)) {
        h->ping_acked = 1;
        return 0;
    }
    if (f->hd.stream_id != h->sid || h->sid == 0) return 0;
    switch (f->hd.type) {
    case NGHTTP2_RST_STREAM:
        h->peer_reset = 1;
        break;
    case NGHTTP2_HEADERS:
        if (h->in_trailers) break;
        if (h->status >= 100 && h->status < 200) {
            /* §18: an informational response is skipped. 101 never reaches
             * here; nghttp2 refuses it on an HTTP/2 stream. */
            if (!h->hdrs)
                return cb_fail(h, ZUH_ERR_PARSE, "HTTP/2 response headers arrived outside a request");
            zuh_headers_free(h->hdrs);
            h2_headers_init(h, h->hdrs);
            h->status = 0;
            break;
        }
        h->headers_done = 1;
        if (f->hd.flags & NGHTTP2_FLAG_END_STREAM) h->ended_on_headers = 1;
        break;
    default:
        break;
    }
    return 0;
}

static int on_data(nghttp2_session *s, uint8_t flags, int32_t sid,
                   const uint8_t *data, size_t len, void *ud) {
    h2_impl *h = (h2_impl *)ud;
    (void)s; (void)flags;
    if (sid != h->sid) return 0;
    if (!zuh_buf_append(&h->data, data, len))
        return cb_fail(h, ZUH_ERR_NOMEM, "out of memory");
    return 0;
}

/* The request body, in memory or streamed, is borrowed for the stream's
 * life only: a pooled connection outlives the call that lent it, so once
 * nothing more can be sent it keeps no pointer to it (#251). A copy made by
 * zuh_h2_own_body() is the connection's and goes with it. */
static void drop_request_body(h2_impl *h) {
    memset(&h->src, 0, sizeof h->src);
    h->src_data = NULL;
    h->src_len = h->src_off = 0;
    zuh_free(h->body_owned);
    h->body_owned = NULL;
    h->body = NULL;
    h->body_len = h->body_off = 0;
}

static int on_close(nghttp2_session *s, int32_t sid, uint32_t code, void *ud) {
    h2_impl *h = (h2_impl *)ud;
    (void)s;
    if (sid != h->sid) return 0;
    h->closed = 1;
    h->close_code = code;
    drop_request_body(h);
    return 0;
}

static nghttp2_ssize body_source(nghttp2_session *s, int32_t sid, uint8_t *buf,
                                 size_t n, uint32_t *flags,
                                 nghttp2_data_source *src, void *ud) {
    h2_impl *h = (h2_impl *)ud;
    size_t left = h->body_len - h->body_off;
    (void)s; (void)sid; (void)src;
    if (h->src.next) {
        /* §65.7: pieces from the caller's function, each sent as one or
         * more DATA frames under the peer's window; END_STREAM after the
         * empty piece that ends it. nghttp2 calls this as the window opens,
         * so the body goes out interleaved with whatever is being read. */
        while (h->src_off == h->src_len && !h->src_end) {
            const void *d = NULL;
            size_t l = 0;
            zuh_code rc;
            /* The function runs inside nghttp2_session_mem_send2(), which
             * is not re-entrant: zuh_h2_in_source() lets the R layer refuse
             * a read or abort of this same response from inside it. */
            h->in_source = 1;
            rc = h->src.next(h->src.ctx, &d, &l, h->send_dl, &h->src_err);
            h->in_source = 0;
            if (rc != ZUH_OK) {
                h->src_failed = 1;
                return NGHTTP2_ERR_CALLBACK_FAILURE;
            }
            if (l == 0) h->src_end = 1;
            else { h->src_data = (const unsigned char *)d; h->src_len = l; h->src_off = 0; }
        }
        if (n > h->src_len - h->src_off) n = h->src_len - h->src_off;
        if (n) memcpy(buf, h->src_data + h->src_off, n);
        h->src_off += n;
        h->body_sent += n;
        if (h->src_end && h->src_off == h->src_len) *flags |= NGHTTP2_DATA_FLAG_EOF;
        return (nghttp2_ssize)n;
    }
    if (n > left) n = left;
    if (n) memcpy(buf, h->body + h->body_off, n);
    h->body_off += n;
    h->body_sent += n;
    if (h->body_off == h->body_len) *flags |= NGHTTP2_DATA_FLAG_EOF;
    return (nghttp2_ssize)n;
}

/* --- moving bytes --- */

static zuh_code fail(h2_impl *h, zuh_error *err, zuh_code code, zuh_phase ph,
                     const char *msg, int ng) {
    h->failed = 1;
    zuh_error_set(err, code, ph, "%s", msg);
    if (ng) zuh_error_set_backend(err, "nghttp2", ng);
    return code;
}

static zuh_code flush(h2_impl *h, zuh_deadline dl, zuh_error *err) {
    h->send_dl = dl;          /* body_source() runs inside the send below */
    for (;;) {
        const uint8_t *p = NULL;
        nghttp2_ssize n = nghttp2_session_mem_send2(h->sess, &p);
        if (n < 0 && h->src_failed) {
            /* The body function failed: its error, not nghttp2's word for
             * it. The session is over, so the connection is never pooled
             * (D-47, §65.7). */
            h->failed = 1;
            *err = h->src_err;
            if (!err->code) zuh_error_set(err, ZUH_ERR_IO, ZUH_PHASE_WRITE,
                                         "the request body function failed");
            return err->code;
        }
        if (n < 0)
            return fail(h, err, n == NGHTTP2_ERR_NOMEM ? ZUH_ERR_NOMEM : ZUH_ERR_IO,
                        ZUH_PHASE_WRITE, nghttp2_strerror((int)n), (int)n);
        if (n == 0) return ZUH_OK;
        if (!zuh_stream_write_all(h->inner, p, (size_t)n, dl, err)) {
            h->failed = 1;
            return err->code ? err->code : ZUH_ERR_IO;
        }
        h->last_frame = zuh_now_ms();
    }
}

/* Send what is pending, then read once and feed it to the session. */
static zuh_code pump(h2_impl *h, zuh_deadline dl, zuh_error *err) {
    unsigned char buf[H2_READ_CHUNK];
    zuh_ssize n;
    nghttp2_ssize used;
    zuh_code rc = flush(h, dl, err);
    if (rc != ZUH_OK) return rc;
    if (!nghttp2_session_want_read(h->sess)) {
        /* The session is over. The server ended it with GOAWAY, or nghttp2
         * ended it because what the server sent broke RFC 9113 — a
         * malformed response, as §65.2 classes it. */
        if (h->goaway)
            return fail(h, err, ZUH_ERR_IO, ZUH_PHASE_READ,
                        "the server closed the HTTP/2 connection (GOAWAY) "
                        "before the response ended", 0);
        return fail(h, err, ZUH_ERR_PARSE, ZUH_PHASE_READ,
                    "the server broke the HTTP/2 protocol, so the session was ended", 0);
    }
    n = zuh_stream_read(h->inner, buf, sizeof buf, dl, err);
    if (n < 0) {
        if (err->code == ZUH_ERR_WOULDBLOCK) { zuh_error_clear(err); return ZUH_OK; }
        h->failed = 1;
        return err->code ? err->code : ZUH_ERR_IO;
    }
    if (n == 0)
        return fail(h, err, ZUH_ERR_IO, ZUH_PHASE_READ,
                    "the server closed the HTTP/2 connection before the response ended", 0);
    h->last_frame = zuh_now_ms();
    used = nghttp2_session_mem_recv2(h->sess, buf, (size_t)n);
    if (used < 0) {
        if (h->cb_code != ZUH_OK)
            return fail(h, err, h->cb_code, ZUH_PHASE_READ, h->cb_msg, 0);
        /* Out of memory is ours, not the server's: reporting it as a
         * protocol error would blame the peer (§34.1). */
        if (used == NGHTTP2_ERR_NOMEM)
            return fail(h, err, ZUH_ERR_NOMEM, ZUH_PHASE_READ, "out of memory", (int)used);
        {
            char msg[128];
            snprintf(msg, sizeof msg, "HTTP/2 protocol error from the server: %s",
                     nghttp2_strerror((int)used));
            return fail(h, err, ZUH_ERR_PARSE, ZUH_PHASE_READ, msg, (int)used);
        }
    }
    /* What the input produced goes out now: nghttp2 closes a stream it
     * reset (a malformed response) only once the RST_STREAM is sent, and a
     * caller waiting on that close must not wait on the server instead. */
    return flush(h, dl, err);
}

/* pump() for the open stream. Sending can close it: the last DATA of a
 * request body to a server that has already ended its side (an early 413, a
 * gRPC status before the upload ends; RFC 9113 §8.1 makes the RST_STREAM
 * optional) completes the stream inside mem_send2(), and a read after that
 * would wait on a server with nothing more to say, until the deadline.
 *
 * Today pump() ends with a flush, so DATA a read made sendable goes out
 * before pump() returns and the callers see `closed` before pumping again:
 * a flush at the start of a pump carries only WINDOW_UPDATE and PING. This
 * keeps that true if either order changes (review #140, measured). */
static zuh_code pump_stream(h2_impl *h, zuh_deadline dl, zuh_error *err) {
    zuh_code rc = flush(h, dl, err);
    if (rc != ZUH_OK || h->closed) return rc;
    return pump(h, dl, err);
}

/* §65.2: how a stream that closed with an error code reaches R. */
static zuh_code stream_outcome(h2_impl *h, zuh_error *err) {
    char msg[160];
    int code = (int)h->close_code;
    if (h->close_code == NGHTTP2_NO_ERROR) return ZUH_OK;
    if (h->peer_reset) {
        snprintf(msg, sizeof msg, "the server reset the HTTP/2 stream (%s)",
                 nghttp2_http2_strerror(h->close_code));
        fail(h, err, ZUH_ERR_IO, ZUH_PHASE_READ, msg, code);
        return ZUH_ERR_IO;
    }
    if (h->goaway) {
        snprintf(msg, sizeof msg, "the server closed the HTTP/2 connection (GOAWAY, %s)",
                 nghttp2_http2_strerror(h->close_code));
        fail(h, err, ZUH_ERR_IO, ZUH_PHASE_READ, msg, code);
        return ZUH_ERR_IO;
    }
    snprintf(msg, sizeof msg, "malformed HTTP/2 response (%s)",
             nghttp2_http2_strerror(h->close_code));
    return fail(h, err, ZUH_ERR_PARSE, ZUH_PHASE_READ, msg, code);
}

/* --- the request --- */

static int is_conn_specific(const char *name) {
    static const char *const drop[] = {
        "Connection", "Keep-Alive", "Proxy-Connection", "Transfer-Encoding",
        "Upgrade", "Host"
    };
    size_t i;
    for (i = 0; i < sizeof drop / sizeof drop[0]; i++)
        if (zuh_ascii_casecmp(name, drop[i]) == 0) return 1;
    return 0;
}

static void nv_set(nghttp2_nv *nv, const char *name, const char *value) {
    nv->name     = (uint8_t *)(uintptr_t)name;
    nv->namelen  = strlen(name);
    nv->value    = (uint8_t *)(uintptr_t)value;
    nv->valuelen = strlen(value);
    nv->flags    = NGHTTP2_NV_FLAG_NONE;   /* nghttp2 copies both */
}

zuh_code zuh_h2_begin(zuh_stream *conn, const zuh_h2_request *rq,
                      int *status, zuh_headers *headers, int *bodiless,
                      zuh_deadline dl, zuh_error *err) {
    h2_impl *h;
    size_t n_hdr, i, nv_n = 0;
    nghttp2_nv *nv = NULL;
    static char p_method[] = ":method", p_scheme[] = ":scheme",
                p_authority[] = ":authority", p_path[] = ":path";
    nghttp2_data_provider2 prd;
    int32_t sid;
    zuh_code rc = ZUH_OK;

    if (!zuh_h2_is(conn)) {
        zuh_error_set(err, ZUH_ERR_IO, ZUH_PHASE_WRITE, "not an HTTP/2 connection");
        return ZUH_ERR_IO;
    }
    h = (h2_impl *)conn->impl;
    if (h->failed || !nghttp2_session_check_request_allowed(h->sess)) {
        zuh_error_set(err, ZUH_ERR_IO, ZUH_PHASE_WRITE,
                      "this HTTP/2 connection cannot carry another request");
        return ZUH_ERR_IO;
    }

    /* RFC 9113 §8.2.2: TE is the one connection header with a stream
     * meaning, and only as "trailers", which gRPC sends to detect proxies
     * that drop trailers (§65.3). */
    n_hdr = zuh_headers_total(rq->headers);
    for (i = 0; i < n_hdr; i++) {
        const char *nm, *v;
        if (!zuh_headers_at(rq->headers, i, &nm, &v)) continue;
        if (zuh_ascii_casecmp(nm, "TE") == 0 && zuh_ascii_casecmp(v, "trailers") != 0) {
            zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_NONE,
                          "a TE header other than 'trailers' cannot be sent over HTTP/2");
            return ZUH_ERR_PARSE;
        }
    }

    nv    = (nghttp2_nv *)zuh_calloc(n_hdr + 4, sizeof *nv);
    if (!nv) { rc = ZUH_ERR_NOMEM; goto out; }
    nv_set(&nv[nv_n++], p_method, rq->method);
    nv_set(&nv[nv_n++], p_scheme, rq->scheme);
    nv_set(&nv[nv_n++], p_authority, rq->authority);
    nv_set(&nv[nv_n++], p_path, rq->path && *rq->path ? rq->path : "/");
    for (i = 0; i < n_hdr; i++) {
        const char *nm, *v;
        if (!zuh_headers_at(rq->headers, i, &nm, &v) || is_conn_specific(nm)) continue;
        /* HTTP/2 field names are lowercase on the wire (RFC 9113 §8.2.1).
         * nghttp2 lowercases them as it copies the list (nghttp2_nva_copy),
         * so a copy here lowered them twice; ctest's "#270" case asserts
         * the names as the server received them. */
        nv_set(&nv[nv_n++], nm, v);
    }

    /* Per-stream state. */
    h->hdrs = headers;
    h->status = 0;
    h->in_trailers = 0;
    h->headers_done = h->ended_on_headers = 0;
    h->closed = 0; h->close_code = 0; h->peer_reset = 0; h->cancelled = 0;
    h->cb_code = ZUH_OK; h->cb_msg[0] = '\0';
    zuh_headers_free(&h->trailers);
    h2_headers_init(h, &h->trailers);
    zuh_buf_reset(&h->data);
    zuh_free(h->body_owned);
    h->body_owned = NULL;
    h->body = (const unsigned char *)rq->body;
    h->body_len = rq->body ? rq->body_len : 0;
    h->body_off = 0;
    h->body_sent = 0;
    memset(&h->src, 0, sizeof h->src);
    if (rq->source && rq->source->next) h->src = *rq->source;
    h->src_data = NULL; h->src_len = h->src_off = 0;
    h->src_end = h->src_failed = h->in_source = 0;
    zuh_error_clear(&h->src_err);

    prd.source.ptr = NULL;
    prd.read_callback = body_source;
    sid = nghttp2_submit_request2(h->sess, NULL, nv, nv_n,
                                  (h->body_len || h->src.next) ? &prd : NULL, NULL);
    if (sid < 0) {
        /* NOMEM is the one code a client can meet here (#139). The others
         * nghttp2 documents, STREAM_ID_NOT_AVAILABLE after 2^30 streams on
         * one connection and PROTO for a server session, no test can
         * reach from this driver, which is why no test does (#192). */
        rc = fail(h, err, sid == NGHTTP2_ERR_NOMEM ? ZUH_ERR_NOMEM : ZUH_ERR_IO,
                  ZUH_PHASE_WRITE, nghttp2_strerror(sid), sid);
        drop_request_body(h);    /* no stream, so on_close will not */
        goto out;
    }
    h->sid = sid;

    while (rc == ZUH_OK && !h->headers_done) {
        if (h->closed) {
            rc = stream_outcome(h, err);
            if (rc == ZUH_OK)
                rc = fail(h, err, ZUH_ERR_PARSE, ZUH_PHASE_READ,
                          "the HTTP/2 stream ended without a response", 0);
            break;
        }
        rc = pump_stream(h, dl, err);
    }
    if (rc == ZUH_OK) {
        *status = h->status;
        *bodiless = h->ended_on_headers;
    }

out:
    /* `headers` lives on the caller's stack. The callbacks that write
     * through it are gated on !headers_done and nghttp2 does not deliver
     * headers for a closed stream, but a pointer into a frame that has
     * returned is not something to keep for the connection's pooled life
     * (review #178): the callbacks refuse a block when it is NULL. */
    h->hdrs = NULL;
    if (rc == ZUH_ERR_NOMEM && !err->code)
        zuh_error_set(err, rc, ZUH_PHASE_WRITE, "out of memory");
    zuh_free(nv);
    return rc;
}

/* Hand DATA that arrived to the pipe, and grant that much window back: the
 * window moves at the pace bytes leave the driver, which is the caller's
 * pace when the body is pulled (§65.4). */
static zuh_code deliver(h2_impl *h, zuh_body_pipe *pipe, zuh_error *err) {
    zuh_code rc;
    size_t n = h->data.len;
    if (n == 0) return ZUH_OK;
    pipe->raw_seen += (uint64_t)n;
    /* Granted before the pipe sees the bytes, so a body the pipe refuses
     * still returns its share of the connection window. */
    if (h->closed || nghttp2_session_consume(h->sess, h->sid, n) != 0)
        (void)nghttp2_session_consume_connection(h->sess, n);
    rc = zuh_body_pipe_feed(pipe, h->data.data, n, err);
    zuh_buf_reset(&h->data);
    /* A body the pipe refuses (max_body, a decoding error, a sink that asked
     * to stop) leaves the stream open: zuh_h2_cancel() resets it and keeps
     * the connection, and without that zuh_h2_reusable() says no. */
    return rc;
}

zuh_code zuh_h2_body_step(zuh_stream *conn, zuh_body_pipe *pipe, int *done,
                          zuh_deadline dl, zuh_error *err) {
    h2_impl *h;
    zuh_code rc;
    *done = 0;
    if (!zuh_h2_is(conn)) return ZUH_ERR_IO;
    h = (h2_impl *)conn->impl;
    if (!h->data.len && !h->closed) {
        rc = pump_stream(h, dl, err);
        if (rc != ZUH_OK) return rc;
    }
    rc = deliver(h, pipe, err);
    if (rc != ZUH_OK) return rc;
    if (!h->closed || h->data.len) return ZUH_OK;
    rc = stream_outcome(h, err);
    if (rc == ZUH_OK) rc = zuh_body_pipe_finish(pipe, err);
    if (rc != ZUH_OK) return rc;
    zuh_headers_free(&pipe->trailers);
    pipe->trailers = h->trailers;               /* ownership moves */
    h2_headers_init(h, &h->trailers);
    *done = 1;
    /* WINDOW_UPDATE and SETTINGS ACK frames the last read produced go out
     * now rather than with the next request, which may be a while. */
    {
        zuh_error tmp;
        zuh_error_clear(&tmp);
        (void)flush(h, dl, &tmp);
    }
    return ZUH_OK;
}

zuh_code zuh_h2_body(zuh_stream *conn, zuh_body_pipe *pipe,
                     zuh_deadline dl, zuh_error *err) {
    int done = 0;
    zuh_code rc = ZUH_OK;
    while (rc == ZUH_OK && !done) rc = zuh_h2_body_step(conn, pipe, &done, dl, err);
    return rc;
}

zuh_code zuh_h2_own_body(zuh_stream *conn, zuh_error *err) {
    h2_impl *h;
    size_t left;
    unsigned char *copy;
    if (!zuh_h2_is(conn)) return ZUH_OK;
    h = (h2_impl *)conn->impl;
    left = h->body_len - h->body_off;
    if (h->closed || h->src.next || h->body_owned || left == 0) return ZUH_OK;
    copy = (unsigned char *)zuh_alloc(left);
    if (!copy) {
        zuh_error_set(err, ZUH_ERR_NOMEM, ZUH_PHASE_WRITE, "out of memory");
        return ZUH_ERR_NOMEM;
    }
    memcpy(copy, h->body + h->body_off, left);
    h->body_owned = copy;
    h->body = copy;
    h->body_len = left;
    h->body_off = 0;
    return ZUH_OK;
}

int zuh_h2_borrowed(const zuh_stream *conn) {
    const h2_impl *h;
    if (!zuh_h2_is(conn)) return 0;
    h = (const h2_impl *)conn->impl;
    return (h->hdrs != NULL) + (h->body != NULL && h->body != h->body_owned) +
           (h->src.next != NULL);
}

uint64_t zuh_h2_body_sent(const zuh_stream *conn) {
    return zuh_h2_is(conn) ? ((const h2_impl *)conn->impl)->body_sent : 0;
}

int zuh_h2_in_source(const zuh_stream *conn) {
    return zuh_h2_is(conn) && ((const h2_impl *)conn->impl)->in_source;
}

/* §65.5: end the open stream and keep the connection. DATA already in
 * flight for it is discarded by nghttp2 when it arrives, and its connection
 * window is returned, so the next stream starts with the whole window. */
void zuh_h2_cancel(zuh_stream *conn, zuh_deadline dl) {
    h2_impl *h;
    zuh_error tmp;
    if (!zuh_h2_is(conn)) return;
    h = (h2_impl *)conn->impl;
    if (h->closed || h->sid == 0 || h->failed) return;
    zuh_error_clear(&tmp);
    memset(&h->src, 0, sizeof h->src);
    if (h->data.len) {
        (void)nghttp2_session_consume_connection(h->sess, h->data.len);
        zuh_buf_reset(&h->data);
    }
    if (nghttp2_submit_rst_stream(h->sess, NGHTTP2_FLAG_NONE, h->sid, NGHTTP2_CANCEL) != 0 ||
        flush(h, dl, &tmp) != ZUH_OK) {
        h->failed = 1;
        return;
    }
    h->cancelled = 1;
}

/* §65.6: is the peer still there? Sends a PING and waits until `dl` for its
 * ACK, feeding whatever else arrives to the session. */
int zuh_h2_ping(zuh_stream *conn, zuh_deadline dl) {
    h2_impl *h;
    zuh_error e;
    if (!zuh_h2_is(conn)) return 0;
    h = (h2_impl *)conn->impl;
    if (h->failed || h->goaway) return 0;
    zuh_error_clear(&e);
    h->ping_acked = 0;
    if (nghttp2_submit_ping(h->sess, NGHTTP2_FLAG_NONE, NULL) != 0) return 0;
    while (!h->ping_acked) {
        if (pump(h, dl, &e) != ZUH_OK || h->goaway) return 0;
    }
    return 1;
}

long zuh_h2_idle_ms(zuh_stream *conn) {
    if (!zuh_h2_is(conn)) return -1;
    return (long)(zuh_now_ms() - ((h2_impl *)conn->impl)->last_frame);
}

int zuh_h2_reusable(zuh_stream *conn) {
    h2_impl *h;
    if (!zuh_h2_is(conn)) return 0;
    h = (h2_impl *)conn->impl;
    /* A stream we reset ourselves (§65.5) closes with CANCEL, and that is
     * the one error code after which the connection is still clean. */
    return !h->failed && !h->goaway &&
           (h->cancelled || (h->closed && h->close_code == NGHTTP2_NO_ERROR)) &&
           nghttp2_session_check_request_allowed(h->sess);
}

/* --- the wrapper as a zuh_stream --- */

static void h2_close(zuh_stream *s) {
    h2_impl *h = (h2_impl *)s->impl;
    if (h && h->inner) zuh_stream_close(h->inner);
}

static void h2_destroy(zuh_stream *s) {
    h2_impl *h = (h2_impl *)s->impl;
    if (h) {
        if (h->sess) nghttp2_session_del(h->sess);
        zuh_headers_free(&h->trailers);
        zuh_buf_free(&h->data);
        zuh_free(h->body_owned);
        zuh_stream_free(h->inner);
        zuh_free(h);
    }
    zuh_free(s);
}

/* §26.2 for an idle HTTP/2 connection. Readable bytes are not, as they are
 * for HTTP/1.1, a sign of a stale connection: a server sends SETTINGS ACK,
 * WINDOW_UPDATE and PING between requests. So the probe reads them into the
 * session, answers what needs answering, and reports the connection stale
 * only when what arrived ends it: EOF, GOAWAY, or a protocol error. */
static int h2_readable(zuh_stream *s, int timeout_ms) {
    h2_impl *h = (h2_impl *)s->impl;
    zuh_error e;
    int r = zuh_stream_readable(h->inner, timeout_ms);
    zuh_error_clear(&e);
    if (h->failed || h->goaway) return 1;
    while (r == 1) {
        /* Bytes are waiting, so this read does not block for long; the
         * deadline covers a TLS record that arrived in part. */
        if (pump(h, zuh_deadline_in(100), &e) != ZUH_OK || h->goaway) return 1;
        if (flush(h, zuh_deadline_in(100), &e) != ZUH_OK) return 1;
        /* A protocol error in what arrived is not an error return:
         * nghttp2 queues its own GOAWAY and stops reading, so the session
         * is over even though the peer sent no GOAWAY (found by the review
         * tests, #147). */
        if (!nghttp2_session_want_read(h->sess) ||
            !nghttp2_session_check_request_allowed(h->sess)) {
            h->failed = 1;
            return 1;
        }
        r = zuh_stream_readable(h->inner, 0);
    }
    return r < 0 ? r : 0;
}

/* No read or write: bytes on an HTTP/2 connection only make sense as frames,
 * so zuh_stream_read() and zuh_stream_write() refuse the wrapper outright. */
static const zuh_stream_vtable h2_vt = {
    "h2", NULL, NULL, h2_close, h2_destroy, h2_readable
};

zuh_code zuh_h2_wrap(zuh_stream **out, zuh_stream *inner,
                     size_t max_header_bytes, zuh_error *err) {
    nghttp2_session_callbacks *cbs = NULL;
    nghttp2_mem mem;
    nghttp2_settings_entry iv[4];
    nghttp2_option *opt = NULL;
    zuh_stream *s;
    h2_impl *h;
    int rv;

    s = (zuh_stream *)zuh_calloc(1, sizeof *s);
    h = (h2_impl *)zuh_calloc(1, sizeof *h);
    if (!s || !h || !zuh_buf_init(&h->data, 0, H2_DATA_MAX)) {
        zuh_free(s); zuh_free(h);
        zuh_error_set(err, ZUH_ERR_NOMEM, ZUH_PHASE_CONNECT, "out of memory");
        return ZUH_ERR_NOMEM;
    }
    h->max_header_bytes = max_header_bytes ? max_header_bytes : ZUH_DEFAULT_MAX_HEADER_BYTES;
    h2_headers_init(h, &h->trailers);

    mem.mem_user_data = NULL;
    mem.malloc = mem_malloc; mem.free = mem_free;
    mem.calloc = mem_calloc; mem.realloc = mem_realloc;

    rv = nghttp2_session_callbacks_new(&cbs);
    if (rv == 0) {
        nghttp2_session_callbacks_set_on_begin_headers_callback(cbs, on_begin_headers);
        nghttp2_session_callbacks_set_on_header_callback(cbs, on_header);
        nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, on_frame_recv);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, on_data);
        nghttp2_session_callbacks_set_on_stream_close_callback(cbs, on_close);
        if (nghttp2_option_new(&opt) == 0) {
            /* §65.4: window is granted as the caller takes bytes. */
            nghttp2_option_set_no_auto_window_update(opt, 1);
            rv = nghttp2_session_client_new3(&h->sess, cbs, h, opt, &mem);
            nghttp2_option_del(opt);
        } else {
            rv = NGHTTP2_ERR_NOMEM;
        }
        nghttp2_session_callbacks_del(cbs);
    }
    if (rv == 0) {
        /* §65.2: no server push, and the header limit §40 enforces. */
        iv[0].settings_id = NGHTTP2_SETTINGS_ENABLE_PUSH;            iv[0].value = 0;
        iv[1].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS; iv[1].value = 1;
        iv[2].settings_id = NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE;
        iv[2].value = (uint32_t)(h->max_header_bytes > UINT32_MAX ? UINT32_MAX : h->max_header_bytes);
        iv[3].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE; iv[3].value = ZUH_H2_WINDOW;
        rv = nghttp2_submit_settings(h->sess, NGHTTP2_FLAG_NONE, iv, 4);
    }
    if (rv == 0) {
        /* The connection window too, or the stream window above is capped
         * by the connection's default 65,535. */
        rv = nghttp2_session_set_local_window_size(h->sess, NGHTTP2_FLAG_NONE, 0, ZUH_H2_WINDOW);
    }
    if (rv != 0) {
        if (h->sess) nghttp2_session_del(h->sess);
        zuh_headers_free(&h->trailers);
        zuh_buf_free(&h->data);
        zuh_free(h); zuh_free(s);
        zuh_error_set(err, rv == NGHTTP2_ERR_NOMEM ? ZUH_ERR_NOMEM : ZUH_ERR_IO,
                      ZUH_PHASE_CONNECT, "could not start an HTTP/2 session: %s",
                      nghttp2_strerror(rv));
        return err->code;
    }
    h->inner = inner;
    h->last_frame = zuh_now_ms();
    s->vt = &h2_vt;
    s->impl = h;
    *out = s;
    return ZUH_OK;
}

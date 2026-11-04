/* zuhttp — the HTTP/2 driver (design §65.2). See zuh_h2.h for the model. */
#include "zuh_h2.h"
#include "zuh_alloc.h"
#include "zuh_buffer.h"

#include <stdio.h>
#include <string.h>
#include <nghttp2/nghttp2.h>

#define H2_READ_CHUNK 16384
/* DATA held between a mem_recv2() call and the pipe. One read is at most
 * H2_READ_CHUNK bytes of frames, so the buffer never holds more than that;
 * the cap is a backstop, not a tuning knob. */
#define H2_DATA_MAX   (1024u * 1024u)
/* HPACK's accounting (RFC 9113 §6.5.2): each field costs its name, its value
 * and 32 bytes, which is what SETTINGS_MAX_HEADER_LIST_SIZE advertises. */
#define H2_FIELD_OVERHEAD 32u

const char *zuh_h2_alpn_for(zuh_h2_mode m) {
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
    size_t       block_bytes;   /* of the block being received */
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
    zuh_code     cb_code;       /* raised inside a callback */
    char         cb_msg[160];
    zuh_buffer   data;

    const unsigned char *body;
    size_t       body_len, body_off;
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
    h->block_bytes = 0;
    if (h->headers_done) {
        /* A second block after the final response is the trailers. */
        h->in_trailers = 1;
    } else {
        /* A response block: the first, or the one after a 1xx. */
        zuh_headers_free(h->hdrs);
        zuh_headers_init(h->hdrs);
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

    /* §40 for each block on its own (§65.3), counted as HPACK counts. */
    h->block_bytes += nlen + vlen + H2_FIELD_OVERHEAD;
    if (h->block_bytes > h->max_header_bytes)
        return cb_fail(h, ZUH_ERR_PARSE, h->in_trailers
                       ? "HTTP/2 trailer block exceeds the header size limit"
                       : "HTTP/2 response header block exceeds the header size limit");

    if (nlen > 0 && name[0] == ':') {
        /* nghttp2 has validated the pseudo-headers (RFC 9113 §8.3.2): only
         * :status reaches a client, once, as three digits. */
        if (!h->in_trailers && nlen == 7 && memcmp(name, ":status", 7) == 0 && vlen == 3)
            h->status = (value[0] - '0') * 100 + (value[1] - '0') * 10 + (value[2] - '0');
        return 0;
    }
    rc = zuh_headers_add(h->in_trailers ? &h->trailers : h->hdrs,
                         (const char *)name, nlen, (const char *)value, vlen);
    if (rc == ZUH_ERR_NOMEM) return cb_fail(h, rc, "out of memory");
    if (rc != ZUH_OK)
        return cb_fail(h, ZUH_ERR_PARSE, "HTTP/2 response header is invalid or over a limit");
    return 0;
}

static int on_frame_recv(nghttp2_session *s, const nghttp2_frame *f, void *ud) {
    h2_impl *h = (h2_impl *)ud;
    (void)s;
    if (f->hd.type == NGHTTP2_GOAWAY) { h->goaway = 1; return 0; }
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
            zuh_headers_free(h->hdrs);
            zuh_headers_init(h->hdrs);
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

static int on_close(nghttp2_session *s, int32_t sid, uint32_t code, void *ud) {
    h2_impl *h = (h2_impl *)ud;
    (void)s;
    if (sid != h->sid) return 0;
    h->closed = 1;
    h->close_code = code;
    return 0;
}

static nghttp2_ssize body_source(nghttp2_session *s, int32_t sid, uint8_t *buf,
                                 size_t n, uint32_t *flags,
                                 nghttp2_data_source *src, void *ud) {
    h2_impl *h = (h2_impl *)ud;
    size_t left = h->body_len - h->body_off;
    (void)s; (void)sid; (void)src;
    if (n > left) n = left;
    if (n) memcpy(buf, h->body + h->body_off, n);
    h->body_off += n;
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
    for (;;) {
        const uint8_t *p = NULL;
        nghttp2_ssize n = nghttp2_session_mem_send2(h->sess, &p);
        if (n < 0)
            return fail(h, err, n == NGHTTP2_ERR_NOMEM ? ZUH_ERR_NOMEM : ZUH_ERR_IO,
                        ZUH_PHASE_WRITE, nghttp2_strerror((int)n), (int)n);
        if (n == 0) return ZUH_OK;
        if (!zuh_stream_write_all(h->inner, p, (size_t)n, dl, err)) {
            h->failed = 1;
            return err->code ? err->code : ZUH_ERR_IO;
        }
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
    used = nghttp2_session_mem_recv2(h->sess, buf, (size_t)n);
    if (used < 0) {
        if (h->cb_code != ZUH_OK)
            return fail(h, err, h->cb_code, ZUH_PHASE_READ, h->cb_msg, 0);
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

static void nv_set(nghttp2_nv *nv, char *name, const char *value) {
    nv->name     = (uint8_t *)name;
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
    char **names = NULL;
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
    names = (char **)zuh_calloc(n_hdr + 1, sizeof *names);
    if (!nv || !names) { rc = ZUH_ERR_NOMEM; goto out; }
    nv_set(&nv[nv_n++], p_method, rq->method);
    nv_set(&nv[nv_n++], p_scheme, rq->scheme);
    nv_set(&nv[nv_n++], p_authority, rq->authority);
    nv_set(&nv[nv_n++], p_path, rq->path && *rq->path ? rq->path : "/");
    for (i = 0; i < n_hdr; i++) {
        const char *nm, *v;
        size_t k, len;
        if (!zuh_headers_at(rq->headers, i, &nm, &v) || is_conn_specific(nm)) continue;
        /* HTTP/2 field names are lowercase on the wire (RFC 9113 §8.2.1). */
        len = strlen(nm);
        names[i] = (char *)zuh_alloc(len + 1);
        if (!names[i]) { rc = ZUH_ERR_NOMEM; goto out; }
        for (k = 0; k <= len; k++)
            names[i][k] = (char)(nm[k] >= 'A' && nm[k] <= 'Z' ? nm[k] + 32 : nm[k]);
        nv_set(&nv[nv_n++], names[i], v);
    }

    /* Per-stream state. */
    h->hdrs = headers;
    h->status = 0;
    h->in_trailers = 0;
    h->headers_done = h->ended_on_headers = 0;
    h->closed = 0; h->close_code = 0; h->peer_reset = 0;
    h->cb_code = ZUH_OK; h->cb_msg[0] = '\0';
    zuh_headers_free(&h->trailers);
    zuh_headers_init(&h->trailers);
    zuh_buf_reset(&h->data);
    h->body = (const unsigned char *)rq->body;
    h->body_len = rq->body ? rq->body_len : 0;
    h->body_off = 0;

    prd.source.ptr = NULL;
    prd.read_callback = body_source;
    sid = nghttp2_submit_request2(h->sess, NULL, nv, nv_n,
                                  h->body_len ? &prd : NULL, NULL);
    if (sid < 0) {
        rc = fail(h, err, sid == NGHTTP2_ERR_NOMEM ? ZUH_ERR_NOMEM : ZUH_ERR_IO,
                  ZUH_PHASE_WRITE, nghttp2_strerror(sid), sid);
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
        rc = pump(h, dl, err);
    }
    if (rc == ZUH_OK) {
        *status = h->status;
        *bodiless = h->ended_on_headers;
    }

out:
    if (rc == ZUH_ERR_NOMEM && !err->code)
        zuh_error_set(err, rc, ZUH_PHASE_WRITE, "out of memory");
    if (names) {
        for (i = 0; i < n_hdr; i++) zuh_free(names[i]);
        zuh_free(names);
    }
    zuh_free(nv);
    return rc;
}

zuh_code zuh_h2_body(zuh_stream *conn, zuh_body_pipe *pipe,
                     zuh_deadline dl, zuh_error *err) {
    h2_impl *h;
    zuh_code rc = ZUH_OK;
    if (!zuh_h2_is(conn)) return ZUH_ERR_IO;
    h = (h2_impl *)conn->impl;
    for (;;) {
        if (h->data.len) {
            pipe->raw_seen += (uint64_t)h->data.len;
            rc = zuh_body_pipe_feed(pipe, h->data.data, h->data.len, err);
            zuh_buf_reset(&h->data);
            /* A body refused by the pipe (max_body, a decoding error) is a
             * stream left open mid-flight: the connection is not reused.
             * W21's zu_resp_abort() resets the stream and keeps it. */
            if (rc != ZUH_OK) { h->failed = 1; return rc; }
        }
        if (h->closed) break;
        rc = pump(h, dl, err);
        if (rc != ZUH_OK) return rc;
    }
    rc = stream_outcome(h, err);
    if (rc == ZUH_OK) rc = zuh_body_pipe_finish(pipe, err);
    /* WINDOW_UPDATE and SETTINGS ACK frames the last read produced go out
     * now rather than with the next request, which may be a while. */
    if (rc == ZUH_OK) {
        zuh_error tmp;
        zuh_error_clear(&tmp);
        (void)flush(h, dl, &tmp);
    }
    return rc;
}

int zuh_h2_reusable(zuh_stream *conn) {
    h2_impl *h;
    if (!zuh_h2_is(conn)) return 0;
    h = (h2_impl *)conn->impl;
    return !h->failed && !h->goaway && h->closed && h->close_code == NGHTTP2_NO_ERROR &&
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
    nghttp2_settings_entry iv[3];
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
    zuh_headers_init(&h->trailers);
    h->max_header_bytes = max_header_bytes ? max_header_bytes : ZUH_DEFAULT_MAX_HEADER_BYTES;

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
        rv = nghttp2_session_client_new3(&h->sess, cbs, h, NULL, &mem);
        nghttp2_session_callbacks_del(cbs);
    }
    if (rv == 0) {
        /* §65.2: no server push, and the header limit §40 enforces. */
        iv[0].settings_id = NGHTTP2_SETTINGS_ENABLE_PUSH;            iv[0].value = 0;
        iv[1].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS; iv[1].value = 1;
        iv[2].settings_id = NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE;
        iv[2].value = (uint32_t)(h->max_header_bytes > UINT32_MAX ? UINT32_MAX : h->max_header_bytes);
        rv = nghttp2_submit_settings(h->sess, NGHTTP2_FLAG_NONE, iv, 3);
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
    s->vt = &h2_vt;
    s->impl = h;
    *out = s;
    return ZUH_OK;
}

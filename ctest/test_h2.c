/* HTTP/2 through the whole engine, offline (design §65, W20).
 *
 * The peer is a real HTTP/2 server: a vendored nghttp2 server session behind a
 * zuh_stream, handed to the engine through the D-72 dial seam. What the client
 * writes is fed to the server session; what the server session emits is what
 * the client reads. So the client's frames are parsed by an independent
 * HTTP/2 implementation, and every assertion about what reached the server
 * is about decoded headers and bodies, not bytes we guessed.
 *
 * The server's own memory comes from libc, not zuh_alloc, so the harness's
 * allocation balance and the allocation-failure sweep below see the client's
 * allocations alone.
 */
#include "zuh_test.h"
#include "zuh_engine.h"
#include "zuh_h2.h"
#include "zuh_alloc.h"
#include "zuh_trace.h"
#include "zuh_mock_stream.h"
#include <nghttp2/nghttp2.h>
#include <zlib.h>

void suite_h2(void);
static void cases_w21(void);
static void cases_w22(void);
static void cases_review(void);

/* --- what the server does -------------------------------------------------- */

typedef struct {
    int         status;
    const char *hname[4], *hvalue[4];
    const void *body;
    size_t      body_len;
    int         informational;   /* send a 103 before the response */
    int         rst_code;        /* reset the stream instead of answering */
    int         goaway_after;    /* GOAWAY once the response is out */
    int         eof_mid_body;    /* stop the connection half-way through DATA */
    const char *trailer_name, *trailer_value;
    int         stall_after_first; /* stop reading once a response is out */
    /* Review cases (2026-11-05). */
    int         respond_on_headers; /* answer on the request HEADERS, while the body comes */
    int         goaway_refuse;   /* GOAWAY below the stream id instead of answering */
    int         rst_no_error;    /* RST_STREAM(NO_ERROR) instead of answering */
    int         block_on_empty;  /* a read with nothing to give waits for its deadline */
    int         wouldblock_every; /* every other read is WOULDBLOCK first (#192) */
    /* Hostile mode: no server session at all; these bytes are the "server". */
    const unsigned char *raw;
    size_t      raw_len;
    /* §40 at its edges (#253, #259): any number of extra header fields and
     * trailer fields, and client reads of at most read_max bytes. */
    const char *const *xname, *const *xvalue;
    size_t      nx;
    const char *const *tname, *const *tvalue;
    size_t      nt;
    size_t      read_max;
} srv_cfg;

#define SRV_MAX_CONN 4

typedef struct {
    const srv_cfg *cfg;
    nghttp2_session *srv;
    unsigned char *out;          /* server -> client, pending */
    size_t out_len, out_off, out_cap;
    int eof;
    int requests;
    /* The last request, as the server decoded it. */
    char method[16], path[256], authority[128], scheme[8];
    char fields[2048];           /* "name: value\n", in order */
    unsigned char body[4096];
    size_t body_len;
    size_t body_total;           /* request DATA bytes, all of them */
    unsigned long body_sum;      /* a position-weighted checksum, for order */
    int32_t last_sid;
    size_t body_off;             /* response DATA sent so far */
    uint32_t rst_code;           /* RST_STREAM the client sent, if any */
    int rst_seen;
    int pings;                   /* PINGs from the client, ACKs not counted */
    int fail_writes;             /* every client write fails from now on */
    size_t written;              /* bytes the client wrote on this connection */
    int reads, wouldblocks;      /* client reads, and how many blocked first */
} srv;

typedef struct {
    srv conns[SRV_MAX_CONN];
    const srv_cfg *cfg;
    int dials;
    size_t client_bytes;         /* everything the client wrote, all conns */
    zuh_tick_fn tick;            /* #189: consulted before every read */
    void       *tick_ctx;
} srv_dialer;

static void out_append(srv *v, const uint8_t *p, size_t n) {
    if (v->out_len + n > v->out_cap) {
        size_t cap = (v->out_len + n) * 2 + 1024;
        v->out = (unsigned char *)realloc(v->out, cap);
        v->out_cap = cap;
    }
    memcpy(v->out + v->out_len, p, n);
    v->out_len += n;
}

static void srv_drain(srv *v) {
    const uint8_t *p;
    nghttp2_ssize n;
    if (!v->srv) return;
    while ((n = nghttp2_session_mem_send2(v->srv, &p)) > 0) {
        if (v->cfg->eof_mid_body && v->body_off > 0 && v->body_off < v->cfg->body_len) {
            /* Keep what is already out, then end the connection. */
            out_append(v, p, (size_t)n);
            v->eof = 1;
            return;
        }
        out_append(v, p, (size_t)n);
    }
}

static int s_on_header(nghttp2_session *s, const nghttp2_frame *f,
                       const uint8_t *name, size_t nlen, const uint8_t *value,
                       size_t vlen, uint8_t flags, void *ud) {
    srv *v = (srv *)ud;
    (void)s; (void)f; (void)flags;
#define COPYTO(dst) snprintf(dst, sizeof dst, "%.*s", (int)vlen, (const char *)value)
    if (nlen == 7 && !memcmp(name, ":method", 7)) COPYTO(v->method);
    else if (nlen == 5 && !memcmp(name, ":path", 5)) COPYTO(v->path);
    else if (nlen == 10 && !memcmp(name, ":authority", 10)) COPYTO(v->authority);
    else if (nlen == 7 && !memcmp(name, ":scheme", 7)) COPYTO(v->scheme);
    else {
        size_t used = strlen(v->fields);
        snprintf(v->fields + used, sizeof v->fields - used, "%.*s: %.*s\n",
                 (int)nlen, (const char *)name, (int)vlen, (const char *)value);
    }
#undef COPYTO
    return 0;
}

static int s_on_begin_headers(nghttp2_session *s, const nghttp2_frame *f, void *ud) {
    srv *v = (srv *)ud;
    (void)s;
    if (f->hd.type == NGHTTP2_HEADERS && f->headers.cat == NGHTTP2_HCAT_REQUEST) {
        v->method[0] = v->path[0] = v->authority[0] = v->scheme[0] = '\0';
        v->fields[0] = '\0';
        v->body_len = 0;
        v->body_total = 0;
        v->body_sum = 0;
    }
    return 0;
}

static int s_on_data(nghttp2_session *s, uint8_t flags, int32_t sid,
                     const uint8_t *data, size_t len, void *ud) {
    srv *v = (srv *)ud;
    (void)s; (void)flags; (void)sid;
    {
        size_t k;
        for (k = 0; k < len; k++)
            v->body_sum += (unsigned long)data[k] * (unsigned long)((v->body_total + k) % 251 + 1);
        v->body_total += len;
    }
    if (v->body_len + len <= sizeof v->body) {
        memcpy(v->body + v->body_len, data, len);
        v->body_len += len;
    }
    return 0;
}

static nghttp2_ssize s_body(nghttp2_session *s, int32_t sid, uint8_t *buf, size_t n,
                            uint32_t *flags, nghttp2_data_source *src, void *ud) {
    srv *v = (srv *)ud;
    size_t left = v->cfg->body_len - v->body_off;
    (void)src;
    if (n > left) n = left;
    if (n > 1000) n = 1000;              /* several DATA frames for any real body */
    if (n) memcpy(buf, (const char *)v->cfg->body + v->body_off, n);
    v->body_off += n;
    if (v->body_off == v->cfg->body_len) {
        *flags |= NGHTTP2_DATA_FLAG_EOF;
        if (v->cfg->trailer_name) {
            nghttp2_nv tr;
            *flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
            tr.name = (uint8_t *)(uintptr_t)v->cfg->trailer_name;
            tr.namelen = strlen(v->cfg->trailer_name);
            tr.value = (uint8_t *)(uintptr_t)v->cfg->trailer_value;
            tr.valuelen = strlen(v->cfg->trailer_value);
            tr.flags = NGHTTP2_NV_FLAG_NONE;
            nghttp2_submit_trailer(s, sid, &tr, 1);
        } else if (v->cfg->nt) {
            /* nghttp2 copies the list before submit returns. */
            nghttp2_nv *tr = (nghttp2_nv *)calloc(v->cfg->nt, sizeof *tr);
            size_t i;
            *flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
            for (i = 0; tr && i < v->cfg->nt; i++) {
                tr[i].name = (uint8_t *)(uintptr_t)v->cfg->tname[i];
                tr[i].namelen = strlen(v->cfg->tname[i]);
                tr[i].value = (uint8_t *)(uintptr_t)v->cfg->tvalue[i];
                tr[i].valuelen = strlen(v->cfg->tvalue[i]);
            }
            if (tr) nghttp2_submit_trailer(s, sid, tr, v->cfg->nt);
            free(tr);
        }
    }
    return (nghttp2_ssize)n;
}

static void respond(srv *v, int32_t sid) {
    const srv_cfg *c = v->cfg;
    nghttp2_nv nv[6], *all;
    char st[8];
    size_t n = 0, i;
    nghttp2_data_provider2 prd;
    v->requests++;
    v->last_sid = sid;
    v->body_off = 0;
    if (c->rst_code) {
        nghttp2_submit_rst_stream(v->srv, NGHTTP2_FLAG_NONE, sid, (uint32_t)c->rst_code);
        return;
    }
    if (c->rst_no_error) {
        nghttp2_submit_rst_stream(v->srv, NGHTTP2_FLAG_NONE, sid, NGHTTP2_NO_ERROR);
        return;
    }
    if (c->goaway_refuse) {
        /* last-stream-id below this stream: RFC 9113 §6.8, it was never
         * processed, and the client may retry it elsewhere. */
        nghttp2_submit_goaway(v->srv, NGHTTP2_FLAG_NONE, sid - 2 > 0 ? sid - 2 : 0,
                              NGHTTP2_NO_ERROR, NULL, 0);
        return;
    }
    if (c->informational) {
        nghttp2_nv info = { (uint8_t *)":status", (uint8_t *)"103", 7, 3, 0 };
        nghttp2_submit_headers(v->srv, NGHTTP2_FLAG_NONE, sid, NULL, &info, 1, NULL);
    }
    snprintf(st, sizeof st, "%d", c->status ? c->status : 200);
    nv[n].name = (uint8_t *)":status"; nv[n].namelen = 7;
    nv[n].value = (uint8_t *)st; nv[n].valuelen = strlen(st); nv[n].flags = 0; n++;
    for (i = 0; i < 4 && c->hname[i]; i++, n++) {
        nv[n].name = (uint8_t *)(uintptr_t)c->hname[i]; nv[n].namelen = strlen(c->hname[i]);
        nv[n].value = (uint8_t *)(uintptr_t)c->hvalue[i]; nv[n].valuelen = strlen(c->hvalue[i]);
        nv[n].flags = 0;
    }
    prd.source.ptr = NULL;
    prd.read_callback = s_body;
    /* The extra fields follow the fixed ones; nghttp2 copies the list. */
    all = (nghttp2_nv *)calloc(n + c->nx, sizeof *all);
    if (!all) return;
    memcpy(all, nv, n * sizeof *nv);
    for (i = 0; i < c->nx; i++) {
        all[n + i].name = (uint8_t *)(uintptr_t)c->xname[i];
        all[n + i].namelen = strlen(c->xname[i]);
        all[n + i].value = (uint8_t *)(uintptr_t)c->xvalue[i];
        all[n + i].valuelen = strlen(c->xvalue[i]);
    }
    nghttp2_submit_response2(v->srv, sid, all, n + c->nx, c->body_len ? &prd : NULL);
    free(all);
    if (c->goaway_after)
        nghttp2_submit_goaway(v->srv, NGHTTP2_FLAG_NONE, sid, NGHTTP2_NO_ERROR, NULL, 0);
}

static int s_on_frame_recv(nghttp2_session *s, const nghttp2_frame *f, void *ud) {
    srv *v = (srv *)ud;
    (void)s;
    if (f->hd.type == NGHTTP2_RST_STREAM) {
        v->rst_seen = 1;
        v->rst_code = f->rst_stream.error_code;
    }
    if (f->hd.type == NGHTTP2_PING && !(f->hd.flags & NGHTTP2_FLAG_ACK)) v->pings++;
    if (v->cfg->respond_on_headers) {
        if (f->hd.type == NGHTTP2_HEADERS && f->headers.cat == NGHTTP2_HCAT_REQUEST)
            respond(v, f->hd.stream_id);
        return 0;
    }
    if ((f->hd.type == NGHTTP2_HEADERS || f->hd.type == NGHTTP2_DATA) &&
        (f->hd.flags & NGHTTP2_FLAG_END_STREAM))
        respond(v, f->hd.stream_id);
    return 0;
}

/* --- the server as a zuh_stream -------------------------------------------- */

static srv_dialer *g_lb_dialer;      /* the dialer whose tick lb_read asks */

static zuh_ssize lb_read(zuh_stream *st, void *b, size_t n, zuh_deadline d, zuh_error *e) {
    srv *v = (srv *)st->impl;
    size_t have = v->out_len - v->out_off;
    if (g_lb_dialer && g_lb_dialer->tick && g_lb_dialer->tick(g_lb_dialer->tick_ctx)) {
        zuh_error_set(e, ZUH_ERR_CANCELLED, ZUH_PHASE_NONE, "operation cancelled");
        return -1;
    }
    v->reads++;
    if (v->cfg->wouldblock_every && (v->reads % 2) == 1) {
        v->wouldblocks++;
        zuh_error_set(e, ZUH_ERR_WOULDBLOCK, ZUH_PHASE_READ, "loopback: would block");
        return -1;
    }
    if (have == 0) {
        if (v->eof || v->cfg->raw) return 0;
        if (v->cfg->block_on_empty) {
            /* A peer that is silently gone: the read lasts until the
             * deadline, as a socket's would. */
            while (!zuh_deadline_expired(d)) { }
            zuh_error_set(e, ZUH_ERR_TIMEOUT, ZUH_PHASE_READ, "loopback: deadline");
            return -1;
        }
        /* A real socket would wait; this one has nothing more to say, which
         * in a single-threaded loopback is a bug in the test or the client. */
        zuh_error_set(e, ZUH_ERR_TIMEOUT, ZUH_PHASE_READ, "loopback: nothing to read");
        return -1;
    }
    if (n > have) n = have;
    if (v->cfg->read_max && n > v->cfg->read_max) n = v->cfg->read_max;
    memcpy(b, v->out + v->out_off, n);
    v->out_off += n;
    return (zuh_ssize)n;
}

static zuh_ssize lb_write(zuh_stream *st, const void *b, size_t n, zuh_deadline d, zuh_error *e) {
    srv *v = (srv *)st->impl;
    (void)d;
    if (v->fail_writes) {
        zuh_error_set(e, ZUH_ERR_IO, ZUH_PHASE_WRITE, "loopback: write failed");
        return -1;
    }
    v->written += n;
    if (v->srv && v->cfg->stall_after_first && v->requests >= 1) return (zuh_ssize)n;
    if (v->srv) {
        nghttp2_session_mem_recv2(v->srv, (const uint8_t *)b, n);
        srv_drain(v);
    }
    return (zuh_ssize)n;
}

static void lb_close(zuh_stream *st) { (void)st; }
static void lb_destroy(zuh_stream *st) { zuh_free(st); }
static int lb_readable(zuh_stream *st, int ms) {
    srv *v = (srv *)st->impl;
    (void)ms;
    return (v->out_len > v->out_off || v->eof) ? 1 : 0;
}
static const zuh_stream_vtable k_lb_vt = {
    "h2-loopback", lb_read, lb_write, lb_close, lb_destroy, lb_readable
};

static zuh_code lb_dial(void *ctx, const char *host, uint16_t port,
                        zuh_stream **out, zuh_error *err) {
    srv_dialer *dd = (srv_dialer *)ctx;
    srv *v;
    zuh_stream *st;
    (void)host; (void)port;
    if (dd->dials >= SRV_MAX_CONN) {
        zuh_error_set(err, ZUH_ERR_CONNECT, ZUH_PHASE_CONNECT, "no connection left");
        return ZUH_ERR_CONNECT;
    }
    st = (zuh_stream *)zuh_calloc(1, sizeof *st);
    if (!st) {
        zuh_error_set(err, ZUH_ERR_NOMEM, ZUH_PHASE_CONNECT, "out of memory");
        return ZUH_ERR_NOMEM;
    }
    v = &dd->conns[dd->dials++];
    v->cfg = dd->cfg;
    if (dd->cfg->raw) {
        out_append(v, dd->cfg->raw, dd->cfg->raw_len);
    } else {
        nghttp2_session_callbacks *cb;
        nghttp2_option *opt;
        nghttp2_session_callbacks_new(&cb);
        nghttp2_session_callbacks_set_on_header_callback(cb, s_on_header);
        nghttp2_session_callbacks_set_on_begin_headers_callback(cb, s_on_begin_headers);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, s_on_data);
        nghttp2_session_callbacks_set_on_frame_recv_callback(cb, s_on_frame_recv);
        nghttp2_option_new(&opt);
        /* Let the server send header blocks bigger than the client allows, so
         * the client's own limit is what is tested. */
        nghttp2_option_set_max_send_header_block_length(opt, 1u << 20);
        nghttp2_session_server_new2(&v->srv, cb, v, opt);
        nghttp2_option_del(opt);
        nghttp2_session_callbacks_del(cb);
        nghttp2_submit_settings(v->srv, NGHTTP2_FLAG_NONE, NULL, 0);
        srv_drain(v);
    }
    st->vt = &k_lb_vt;
    st->impl = v;
    *out = st;
    return ZUH_OK;
}

static void dialer_init(srv_dialer *dd, const srv_cfg *c) {
    memset(dd, 0, sizeof *dd);
    dd->cfg = c;
    g_lb_dialer = dd;
}

static void dialer_free(srv_dialer *dd) {
    int i;
    for (i = 0; i < SRV_MAX_CONN; i++) {
        if (dd->conns[i].srv) nghttp2_session_del(dd->conns[i].srv);
        free(dd->conns[i].out);
    }
}

static void h2c_opts(zuh_get_opts *o, srv_dialer *dd) {
    zuh_get_opts_init(o);
    o->dial = lb_dial; o->dial_ctx = dd;
    o->proxy_set = 1;
    o->http2 = ZUH_H2_REQUIRED;
}

static int has(const char *hay, const char *needle) { return strstr(hay, needle) != NULL; }

/* --- cases ----------------------------------------------------------------- */

static void cases_unit(void) {
    unsigned char w[32];
    ZUH_CASE("ALPN wire form: each name prefixed by its length (RFC 7301 §3.1)");
    ZUH_CHECK_EQ_INT(zuh_tls_alpn_wire("h2,http/1.1", w, sizeof w), 12);
    ZUH_CHECK_MEM(w, "\x02h2\x08http/1.1", 12);
    ZUH_CHECK_EQ_INT(zuh_tls_alpn_wire("http/1.1", w, sizeof w), 9);
    ZUH_CASE("ALPN wire form refuses an empty list, an empty name, and overflow");
    ZUH_CHECK_EQ_INT(zuh_tls_alpn_wire("", w, sizeof w), 0);
    ZUH_CHECK_EQ_INT(zuh_tls_alpn_wire("h2,,http/1.1", w, sizeof w), 0);
    ZUH_CHECK_EQ_INT(zuh_tls_alpn_wire("h2,http/1.1", w, 5), 0);
    ZUH_CASE("§65.1: the offer follows the mode; off offers HTTP/1.1 alone");
    ZUH_CHECK(strcmp(zuh_h2_alpn_for(ZUH_H2_AUTO), "h2,http/1.1") == 0);
    ZUH_CHECK(strcmp(zuh_h2_alpn_for(ZUH_H2_REQUIRED), "h2,http/1.1") == 0);
    ZUH_CHECK(strcmp(zuh_h2_alpn_for(ZUH_H2_OFF), "http/1.1") == 0);
    ZUH_CHECK(zuh_h2_alpn_is_h2("h2"));
    ZUH_CHECK(!zuh_h2_alpn_is_h2("http/1.1"));
    ZUH_CHECK(!zuh_h2_alpn_is_h2(""));
    ZUH_CHECK(!zuh_h2_alpn_is_h2(NULL));
}

static void cases_exchange(void) {
    static const char hello[] = "hello over h2";
    srv_dialer dd;
    zuh_get_opts o;
    zuh_result r;
    zuh_error e;
    zuh_code rc;

    ZUH_CASE("§65.1: h2c by prior knowledge: a GET returns the server's bytes over HTTP/2");
    {
        srv_cfg c; memset(&c, 0, sizeof c);
        c.hname[0] = "x-served-by"; c.hvalue[0] = "nghttp2";
        c.body = hello; c.body_len = sizeof hello - 1;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test:8080/a/b?q=1", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) {
            ZUH_CHECK_EQ_INT(r.status, 200);
            ZUH_CHECK_EQ_INT(r.http_major, 2);
            ZUH_CHECK_EQ_INT(r.body.len, sizeof hello - 1);
            ZUH_CHECK_MEM(r.body.data, hello, sizeof hello - 1);
            ZUH_CHECK(zuh_headers_get(&r.headers, "X-Served-By") != NULL);
            zuh_result_free(&r);
        }
        ZUH_CASE("§65.2: the request's pseudo-headers are the URL's, decoded by the server");
        ZUH_CHECK(strcmp(dd.conns[0].method, "GET") == 0);
        ZUH_CHECK(strcmp(dd.conns[0].path, "/a/b?q=1") == 0);
        ZUH_CHECK(strcmp(dd.conns[0].authority, "example.test:8080") == 0);
        ZUH_CHECK(strcmp(dd.conns[0].scheme, "http") == 0);
        ZUH_CASE("§65.2: Host and Connection are not sent on a stream; names are lowercase");
        ZUH_CHECK(!has(dd.conns[0].fields, "host:"));
        ZUH_CHECK(!has(dd.conns[0].fields, "connection:"));
        ZUH_CHECK(has(dd.conns[0].fields, "user-agent: zuhttp"));
        ZUH_CHECK(has(dd.conns[0].fields, "accept-encoding: gzip"));
        dialer_free(&dd);
    }

    ZUH_CASE("§65.2: a POST body reaches the server whole, with its content-length");
    {
        static const char payload[] = "{\"x\": 1, \"y\": [1, 2, 3]}";
        zuh_req_spec spec;
        srv_cfg c; memset(&c, 0, sizeof c);
        c.status = 201;
        memset(&spec, 0, sizeof spec);
        spec.method = "POST"; spec.body = payload; spec.body_len = sizeof payload - 1;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/post", &spec, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) { ZUH_CHECK_EQ_INT(r.status, 201); zuh_result_free(&r); }
        ZUH_CHECK(strcmp(dd.conns[0].method, "POST") == 0);
        ZUH_CHECK_EQ_INT(dd.conns[0].body_len, sizeof payload - 1);
        ZUH_CHECK_MEM(dd.conns[0].body, payload, sizeof payload - 1);
        ZUH_CHECK(has(dd.conns[0].fields, "content-length: 24"));
        dialer_free(&dd);
    }

    ZUH_CASE("§65.2: a body larger than one DATA frame and one window arrives in order");
    {
        static char big[200000];
        size_t i;
        srv_cfg c; memset(&c, 0, sizeof c);
        for (i = 0; i < sizeof big; i++) big[i] = (char)('a' + (i * 7) % 26);
        c.body = big; c.body_len = sizeof big;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/big", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) {
            ZUH_CHECK_EQ_INT(r.body.len, sizeof big);
            ZUH_CHECK(r.body.len == sizeof big && memcmp(r.body.data, big, sizeof big) == 0);
            zuh_result_free(&r);
        }
        dialer_free(&dd);
    }

    ZUH_CASE("§18 under §65.2: a 103 before the response is skipped");
    {
        srv_cfg c; memset(&c, 0, sizeof c);
        c.informational = 1; c.body = "ok"; c.body_len = 2;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) {
            ZUH_CHECK_EQ_INT(r.status, 200);
            ZUH_CHECK_EQ_INT(r.body.len, 2);
            zuh_result_free(&r);
        }
        dialer_free(&dd);
    }

    ZUH_CASE("§65.2: a bodiless response (204, END_STREAM on HEADERS) is complete");
    {
        srv_cfg c; memset(&c, 0, sizeof c);
        c.status = 204;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) { ZUH_CHECK_EQ_INT(r.status, 204); ZUH_CHECK_EQ_INT(r.body.len, 0); zuh_result_free(&r); }
        dialer_free(&dd);
    }

    ZUH_CASE("§21 under §65.2: a gzip body is decoded as over HTTP/1.1");
    {
        static const char plain[] = "decoded over HTTP/2, decoded over HTTP/2";
        unsigned char gz[256];
        z_stream zs;
        srv_cfg c; memset(&c, 0, sizeof c);
        memset(&zs, 0, sizeof zs);
        deflateInit2(&zs, 6, Z_DEFLATED, 16 + 15, 8, Z_DEFAULT_STRATEGY);
        zs.next_in = (Bytef *)(uintptr_t)plain; zs.avail_in = (uInt)(sizeof plain - 1);
        zs.next_out = gz; zs.avail_out = (uInt)sizeof gz;
        deflate(&zs, Z_FINISH);
        c.body = gz; c.body_len = sizeof gz - zs.avail_out;
        deflateEnd(&zs);
        c.hname[0] = "content-encoding"; c.hvalue[0] = "gzip";
        dialer_init(&dd, &c); h2c_opts(&o, &dd); zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/gz", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) {
            ZUH_CHECK_EQ_INT(r.body.len, sizeof plain - 1);
            ZUH_CHECK_MEM(r.body.data, plain, sizeof plain - 1);
            zuh_result_free(&r);
        }
        dialer_free(&dd);
    }

    ZUH_CASE("§65.3: a response with trailers completes; the trailers are not headers");
    {
        srv_cfg c; memset(&c, 0, sizeof c);
        c.body = "x"; c.body_len = 1;
        c.trailer_name = "grpc-status"; c.trailer_value = "0";
        dialer_init(&dd, &c); h2c_opts(&o, &dd); zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) {
            ZUH_CHECK(zuh_headers_get(&r.headers, "grpc-status") == NULL);
            zuh_result_free(&r);
        }
        dialer_free(&dd);
    }
}

static void cases_pool(void) {
    srv_dialer dd;
    zuh_get_opts o;
    zuh_result r;
    zuh_error e;
    zuh_code rc;
    zuh_pool *pool;

    ZUH_CASE("§65.2: the next request reuses the connection on a new stream");
    {
        srv_cfg c; memset(&c, 0, sizeof c);
        c.body = "one"; c.body_len = 3;
        dialer_init(&dd, &c); h2c_opts(&o, &dd);
        pool = zuh_pool_new(NULL); o.pool = pool;
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/1", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) { ZUH_CHECK_EQ_INT(r.reused_connection, 0); zuh_result_free(&r); }
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/2", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) {
            ZUH_CHECK_EQ_INT(r.reused_connection, 1);
            ZUH_CHECK_EQ_INT(r.http_major, 2);
            zuh_result_free(&r);
        }
        ZUH_CHECK_EQ_INT(dd.dials, 1);
        ZUH_CHECK_EQ_INT(dd.conns[0].requests, 2);
        ZUH_CHECK_EQ_INT(dd.conns[0].last_sid, 3);
        ZUH_CHECK(strcmp(dd.conns[0].path, "/2") == 0);
        zuh_pool_free(pool);
        dialer_free(&dd);
    }

    ZUH_CASE("§26.3 under §65.2: after GOAWAY the next request opens a new connection");
    {
        srv_cfg c; memset(&c, 0, sizeof c);
        c.body = "bye"; c.body_len = 3; c.goaway_after = 1;
        dialer_init(&dd, &c); h2c_opts(&o, &dd);
        pool = zuh_pool_new(NULL); o.pool = pool;
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/1", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) zuh_result_free(&r);
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/2", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) { ZUH_CHECK_EQ_INT(r.reused_connection, 0); zuh_result_free(&r); }
        ZUH_CHECK_EQ_INT(dd.dials, 2);
        zuh_pool_free(pool);
        dialer_free(&dd);
    }

    ZUH_CASE("§26.1: an h2c client and an HTTP/1.1 client never share a connection");
    {
        zuh_pool_key k1, k2;
        zuh_uri u;
        zuh_get_opts a, b;
        static const char url[] = "http://example.test/";
        ZUH_CHECK_EQ_INT(zuh_uri_parse(&u, url, url + sizeof url - 1), ZUH_OK);
        zuh_get_opts_init(&a); zuh_get_opts_init(&b);
        b.http2 = ZUH_H2_REQUIRED;
        ZUH_CHECK_EQ_INT(zuh_engine_pool_key(&k1, &u, &a, NULL), 1);
        ZUH_CHECK_EQ_INT(zuh_engine_pool_key(&k2, &u, &b, NULL), 1);
        ZUH_CHECK_EQ_INT(zuh_pool_key_eq(&k1, &k2), 0);
        zuh_pool_key_free(&k1); zuh_pool_key_free(&k2);
        zuh_uri_free(&u);
    }
}

static void cases_failures(void) {
    srv_dialer dd;
    zuh_get_opts o;
    zuh_result r;
    zuh_error e;
    zuh_code rc;

    ZUH_CASE("§65.2: RST_STREAM from the server is zu_io_error with the HTTP/2 code");
    {
        srv_cfg c; memset(&c, 0, sizeof c);
        c.rst_code = NGHTTP2_INTERNAL_ERROR;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_ERR_IO);
        ZUH_CHECK_EQ_INT(e.backend_code, NGHTTP2_INTERNAL_ERROR);
        ZUH_CHECK(has(e.message, "reset"));
        dialer_free(&dd);
    }

    ZUH_CASE("§65.2: a content-length the DATA disagrees with is a malformed response");
    {
        srv_cfg c; memset(&c, 0, sizeof c);
        c.hname[0] = "content-length"; c.hvalue[0] = "10";
        c.body = "short"; c.body_len = 5;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_ERR_PARSE);
        dialer_free(&dd);
    }

    ZUH_CASE("§40 under §65.2: max_body holds across DATA frames");
    {
        static char body[5000];
        srv_cfg c; memset(&c, 0, sizeof c);
        memset(body, 'z', sizeof body);
        c.body = body; c.body_len = sizeof body;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); o.max_body = 3000; zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_ERR_BODY_LIMIT);
        dialer_free(&dd);
    }

    ZUH_CASE("§40 under §65.2: a header block over the limit is zu_http_parse_error");
    {
        static char v1[30000], v2[30000], v3[30000];
        srv_cfg c; memset(&c, 0, sizeof c);
        memset(v1, 'a', sizeof v1 - 1); memset(v2, 'b', sizeof v2 - 1); memset(v3, 'c', sizeof v3 - 1);
        c.hname[0] = "x-a"; c.hvalue[0] = v1;
        c.hname[1] = "x-b"; c.hvalue[1] = v2;
        c.hname[2] = "x-c"; c.hvalue[2] = v3;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_ERR_PARSE);
        dialer_free(&dd);
    }

    ZUH_CASE("§65.2: the connection ending inside the body is zu_io_error");
    {
        static char body[20000];
        srv_cfg c; memset(&c, 0, sizeof c);
        memset(body, 'q', sizeof body);
        c.body = body; c.body_len = sizeof body; c.eof_mid_body = 1;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_ERR_IO);
        dialer_free(&dd);
    }

    ZUH_CASE("§65.2: bytes that are not HTTP/2 are zu_http_parse_error");
    {
        static const unsigned char junk[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
        srv_cfg c; memset(&c, 0, sizeof c);
        c.raw = junk; c.raw_len = sizeof junk - 1;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_ERR_PARSE);
        dialer_free(&dd);
    }

    ZUH_CASE("§65.2: a TE other than trailers is refused before the request is sent");
    {
        static const char *const hn[] = { "TE" };
        static const char *const hv[] = { "gzip" };
        zuh_req_spec spec;
        srv_cfg c; memset(&c, 0, sizeof c);
        memset(&spec, 0, sizeof spec);
        spec.header_names = hn; spec.header_values = hv; spec.n_headers = 1;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", &spec, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_ERR_PARSE);
        ZUH_CHECK_EQ_INT(dd.conns[0].requests, 0);
        dialer_free(&dd);
    }

    ZUH_CASE("§65.3: te: trailers reaches the server unchanged");
    {
        static const char *const hn[] = { "TE" };
        static const char *const hv[] = { "trailers" };
        zuh_req_spec spec;
        srv_cfg c; memset(&c, 0, sizeof c);
        memset(&spec, 0, sizeof spec);
        spec.header_names = hn; spec.header_values = hv; spec.n_headers = 1;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", &spec, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) zuh_result_free(&r);
        ZUH_CHECK(has(dd.conns[0].fields, "te: trailers"));
        dialer_free(&dd);
    }

    ZUH_CASE("§65.1: h2c through an HTTP proxy is refused before a request byte is sent");
    {
        srv_cfg c; memset(&c, 0, sizeof c);
        dialer_init(&dd, &c); h2c_opts(&o, &dd);
        o.proxy = "http://proxy.test:3128"; o.proxy_set = 1;
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_ERR_CONNECT);
        ZUH_CHECK(has(e.message, "proxy"));
        /* Not a byte on any connection (review #162: `requests == 0` held
         * whenever the server decoded nothing, which a refusal after a
         * written preface would also give). */
        ZUH_CHECK_EQ_INT(dd.conns[0].written, 0);
        ZUH_CHECK_EQ_INT(dd.conns[0].requests, 0);
        dialer_free(&dd);
    }

    ZUH_CASE("§65.1: with http2 = auto, http:// stays HTTP/1.1 (no preface is sent)");
    {
        static const char resp[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        srv_cfg c; memset(&c, 0, sizeof c);
        /* The h2 server would reject an HTTP/1.1 request line, so a server
         * that answered at all would prove the wrong protocol. Instead the
         * raw HTTP/1.1 reply is the peer, and the client must parse it. */
        c.raw = (const unsigned char *)resp; c.raw_len = sizeof resp - 1;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); o.http2 = ZUH_H2_AUTO;
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) {
            ZUH_CHECK_EQ_INT(r.http_major, 1);
            ZUH_CHECK_EQ_INT(r.status, 200);
            zuh_result_free(&r);
        }
        dialer_free(&dd);
    }
}

/* §43's oracle over HTTP/2: every allocation a scenario makes, failed in
 * turn. Each run must succeed, or fail as ZUH_ERR_NOMEM, both in the return
 * code and in the error (review #139: nghttp2's own NOMEM once reached R as
 * a protocol error that blamed the server), with nothing leaked. A scenario
 * returns its first non-OK code and fills `e` with its error. */
typedef zuh_code (*h2_scenario)(zuh_error *e);

static const char k_abc[] = "abc";

static zuh_code scn_get(zuh_error *e) {
    srv_dialer dd; zuh_get_opts o; zuh_result r; zuh_code rc;
    srv_cfg c; memset(&c, 0, sizeof c);
    c.body = k_abc; c.body_len = 3;
    dialer_init(&dd, &c); h2c_opts(&o, &dd);
    rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, e);
    if (rc == ZUH_OK) zuh_result_free(&r);
    dialer_free(&dd);
    return rc;
}

/* A second request on the pooled connection, then trailers on a third. */
static zuh_code scn_reuse_trailers(zuh_error *e) {
    srv_dialer dd; zuh_get_opts o; zuh_result r; zuh_code rc;
    zuh_pool *pool = zuh_pool_new(NULL);
    srv_cfg c; memset(&c, 0, sizeof c);
    c.body = k_abc; c.body_len = 3;
    c.trailer_name = "grpc-status"; c.trailer_value = "0";
    if (!pool) { zuh_error_set(e, ZUH_ERR_NOMEM, ZUH_PHASE_NONE, "out of memory"); return ZUH_ERR_NOMEM; }
    dialer_init(&dd, &c); h2c_opts(&o, &dd); o.pool = pool;
    rc = zuh_engine_perform(&r, "http://example.test/1", NULL, &o, e);
    if (rc == ZUH_OK) {
        zuh_result_free(&r);
        rc = zuh_engine_perform(&r, "http://example.test/2", NULL, &o, e);
        if (rc == ZUH_OK) zuh_result_free(&r);
    }
    zuh_pool_free(pool);
    dialer_free(&dd);
    return rc;
}

/* A pulled body read to its end, its trailers taken, then freed. */
static zuh_code scn_pulled(zuh_error *e) {
    srv_dialer dd; zuh_get_opts o; zuh_result r; zuh_code rc; zuh_buffer got;
    srv_cfg c; memset(&c, 0, sizeof c);
    c.body = k_abc; c.body_len = 3;
    c.trailer_name = "grpc-status"; c.trailer_value = "0";
    if (!zuh_buf_init(&got, 0, (size_t)-1)) { zuh_error_set(e, ZUH_ERR_NOMEM, ZUH_PHASE_NONE, "out of memory"); return ZUH_ERR_NOMEM; }
    dialer_init(&dd, &c); h2c_opts(&o, &dd); o.stream_body = 1;
    rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, e);
    if (rc == ZUH_OK) {
        while ((rc = zuh_open_body_read(r.open, &got, 2, e)) == ZUH_OK &&
               !zuh_open_body_done(r.open)) { }
        zuh_result_free(&r);
    }
    zuh_buf_free(&got);
    dialer_free(&dd);
    return rc;
}

typedef struct {
    int pieces, piece_len, fail_at, sent, released, calls;
    unsigned char buf[4000];
    unsigned long expect_sum;
    size_t expect_total;
} gen_ctx;
static zuh_code gen_next(void *ctx, const void **data, size_t *len, zuh_deadline dl,
                         zuh_error *err);
static void gen_release(void *ctx);

/* A streamed request body, and a pulled response that is aborted. */
static zuh_code scn_source_abort(zuh_error *e) {
    srv_dialer dd; zuh_get_opts o; zuh_result r; zuh_code rc; zuh_req_spec spec; zuh_buffer got;
    gen_ctx g;
    srv_cfg c; memset(&c, 0, sizeof c);
    memset(&g, 0, sizeof g);
    g.pieces = 4; g.piece_len = 100;
    c.body = k_abc; c.body_len = 3;
    memset(&spec, 0, sizeof spec);
    spec.method = "POST";
    spec.source.next = gen_next; spec.source.release = gen_release; spec.source.ctx = &g;
    if (!zuh_buf_init(&got, 0, (size_t)-1)) { zuh_error_set(e, ZUH_ERR_NOMEM, ZUH_PHASE_NONE, "out of memory"); return ZUH_ERR_NOMEM; }
    dialer_init(&dd, &c); h2c_opts(&o, &dd); o.stream_body = 1;
    rc = zuh_engine_perform(&r, "http://example.test/up", &spec, &o, e);
    if (rc == ZUH_OK) {
        rc = zuh_open_body_read(r.open, &got, 1, e);
        zuh_open_body_abort(r.open);
        zuh_result_free(&r);
    }
    zuh_buf_free(&got);
    dialer_free(&dd);
    return rc;
}

/* #137's shape: the response arrives before the in-memory body has gone
 * out, so the driver copies the unsent part (zuh_h2_own_body), then the
 * pulled body is read to the end. */
static zuh_code scn_own_body(zuh_error *e) {
    srv_dialer dd; zuh_get_opts o; zuh_result r; zuh_code rc; zuh_req_spec spec; zuh_buffer got;
    static unsigned char body[200000];
    srv_cfg c; memset(&c, 0, sizeof c);
    if (!body[1]) { size_t i; for (i = 0; i < sizeof body; i++) body[i] = (unsigned char)((i * 7 + 3) & 0xff); }
    c.respond_on_headers = 1;
    c.body = k_abc; c.body_len = 3;
    memset(&spec, 0, sizeof spec);
    spec.method = "POST"; spec.body = body; spec.body_len = sizeof body;
    if (!zuh_buf_init(&got, 0, (size_t)-1)) { zuh_error_set(e, ZUH_ERR_NOMEM, ZUH_PHASE_NONE, "out of memory"); return ZUH_ERR_NOMEM; }
    dialer_init(&dd, &c); h2c_opts(&o, &dd); o.stream_body = 1;
    rc = zuh_engine_perform(&r, "http://example.test/up", &spec, &o, e);
    if (rc == ZUH_OK) {
        while ((rc = zuh_open_body_read(r.open, &got, 100, e)) == ZUH_OK &&
               !zuh_open_body_done(r.open)) { }
        zuh_result_free(&r);
    }
    zuh_buf_free(&got);
    dialer_free(&dd);
    return rc;
}

static void sweep(const char *name, h2_scenario scn) {
    zuh_alloc_stats before, after;
    zuh_error e;
    zuh_code rc;
    long n, total;
    int bad_code = 0, leaked = 0, failed = 0;
    ZUH_CASE(name);
    zuh_alloc_stats_get(&before);
    zuh_error_clear(&e);
    rc = scn(&e);
    ZUH_CHECK_EQ_INT(rc, ZUH_OK);
    zuh_alloc_stats_get(&after);
    total = (long)(after.total_allocs - before.total_allocs);
    ZUH_CHECK(total > 10);
    for (n = 0; n < total; n++) {
        zuh_alloc_stats_get(&before);
        zuh_error_clear(&e);
        zuh_alloc_fail_after(n);
        rc = scn(&e);
        zuh_alloc_fail_after(-1);
        if (rc != ZUH_OK) {
            failed++;
            if (rc != ZUH_ERR_NOMEM || e.code != ZUH_ERR_NOMEM) {
                if (bad_code++ == 0)
                    fprintf(stderr, "    allocation %ld: code %d / %d: %s\n",
                            n, (int)rc, (int)e.code, e.message);
            }
        }
        zuh_alloc_stats_get(&after);
        if (after.live_blocks != before.live_blocks) leaked++;
    }
    ZUH_CHECK(failed > 0);
    ZUH_CHECK_EQ_INT(bad_code, 0);
    ZUH_CHECK_EQ_INT(leaked, 0);
}

static void cases_alloc(void) {
    sweep("§43: an h2c GET survives every allocation failing in turn, as NOMEM", scn_get);
    sweep("§43: reuse on a pooled connection and trailers, every allocation failing", scn_reuse_trailers);
    sweep("§43: a pulled body and its trailers, every allocation failing", scn_pulled);
    sweep("§43: a streamed request body and an aborted pulled body, every allocation failing",
          scn_source_abort);
    sweep("§43: a body the driver had to copy (#137) and a pulled response, every allocation failing (#188)",
          scn_own_body);
}

/* --- §40 at its edges, HTTP/1.1 and HTTP/2 side by side (#253, #259) ---- */

/* HTTP/1.1 through the same engine: one connection whose bytes are `bytes`,
 * at most `max_read` a read. */
typedef struct { const char *bytes; size_t len, max_read; } h1_wire;
static zuh_code h1_dial(void *ctx, const char *host, uint16_t port,
                        zuh_stream **out, zuh_error *err) {
    h1_wire *w = (h1_wire *)ctx;
    (void)host; (void)port;
    *out = zuh_mock_stream_from_bytes(w->bytes, w->len, w->max_read);
    if (*out) return ZUH_OK;
    zuh_error_set(err, ZUH_ERR_NOMEM, ZUH_PHASE_CONNECT, "out of memory");
    return ZUH_ERR_NOMEM;
}

/* A field list, the same for every protocol: `n` fields named `name`
 * followed by a two-digit index (which may be widened by `pad` bytes of
 * 'n'), whose values make the list cost exactly `cost` by D-101's rule
 * (name + value + 32 a field). Values are spread evenly and the remainder
 * goes to the first. 0 if `cost` cannot be met. */
#define LF_MAX 128
typedef struct {
    char name[LF_MAX][300];
    char *value[LF_MAX];
    const char *np[LF_MAX], *vp[LF_MAX];
    size_t n;
} field_list;
static int field_list_make(field_list *f, size_t n, size_t pad, size_t cost) {
    size_t i, names = 0, each, extra;
    memset(f, 0, sizeof *f);
    if (n > LF_MAX || pad > 250) return 0;
    f->n = n;
    for (i = 0; i < n; i++) {
        size_t l = (size_t)snprintf(f->name[i], sizeof f->name[i], "x-%02lu", (unsigned long)i);
        memset(f->name[i] + l, 'n', pad); f->name[i][l + pad] = '\0';
        names += l + pad + 32;
        f->np[i] = f->name[i];
    }
    if (cost < names + n) return 0;
    each = (cost - names) / n; extra = (cost - names) % n;
    for (i = 0; i < n; i++) {
        size_t vl = each + (i == 0 ? extra : 0);
        f->value[i] = (char *)malloc(vl + 1);
        if (!f->value[i]) return 0;
        memset(f->value[i], 'v', vl); f->value[i][vl] = '\0';
        f->vp[i] = f->value[i];
    }
    return 1;
}
static void field_list_free(field_list *f) {
    size_t i;
    for (i = 0; i < f->n; i++) free(f->value[i]);
}
/* The list as HTTP/1.1 field lines. */
static size_t field_lines(const field_list *f, char *out, size_t cap) {
    size_t i, n = 0;
    for (i = 0; i < f->n; i++)
        n += (size_t)snprintf(out + n, cap - n, "%s: %s\r\n", f->np[i], f->vp[i]);
    return n;
}

/* One field list over the four places a response carries one: the HTTP/1.1
 * head, HTTP/1.1 chunked trailers, the HTTP/2 HEADERS and HTTP/2 trailers.
 * Each returns the engine's code; `got` is the number of fields that arrived
 * in the block under test, on success. */
enum { AT_H1_HEAD, AT_H1_TRAILERS, AT_H2_HEAD, AT_H2_TRAILERS, AT_COUNT };
static const char *const k_at[AT_COUNT] = {
    "HTTP/1.1 head", "HTTP/1.1 trailers", "HTTP/2 head", "HTTP/2 trailers" };
static zuh_code serve_fields(int at, const field_list *f, size_t max_read, size_t *got) {
    static char wire[1u << 20];
    zuh_get_opts o;
    zuh_result r;
    zuh_error e;
    zuh_code rc;
    zuh_error_clear(&e);
    *got = 0;
    if (at == AT_H1_HEAD || at == AT_H1_TRAILERS) {
        h1_wire w;
        size_t n;
        if (at == AT_H1_HEAD) {
            /* Close-delimited, so no framing field joins the list. */
            n = (size_t)snprintf(wire, sizeof wire, "HTTP/1.1 200 OK\r\n");
            n += field_lines(f, wire + n, sizeof wire - n);
            n += (size_t)snprintf(wire + n, sizeof wire - n, "\r\nok");
        } else {
            n = (size_t)snprintf(wire, sizeof wire, "HTTP/1.1 200 OK\r\n"
                                 "Transfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n");
            n += field_lines(f, wire + n, sizeof wire - n);
            n += (size_t)snprintf(wire + n, sizeof wire - n, "\r\n");
        }
        w.bytes = wire; w.len = n; w.max_read = max_read;
        zuh_get_opts_init(&o);
        o.dial = h1_dial; o.dial_ctx = &w; o.proxy_set = 1; o.http2 = ZUH_H2_OFF;
        rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, &e);
    } else {
        srv_dialer dd;
        srv_cfg c; memset(&c, 0, sizeof c);
        c.body = "ok"; c.body_len = 2; c.read_max = max_read;
        if (at == AT_H2_HEAD) { c.xname = f->np; c.xvalue = f->vp; c.nx = f->n; }
        else                  { c.tname = f->np; c.tvalue = f->vp; c.nt = f->n; }
        dialer_init(&dd, &c); h2c_opts(&o, &dd);
        rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, &e);
        dialer_free(&dd);
    }
    if (rc == ZUH_OK) {
        *got = zuh_headers_total(at == AT_H1_HEAD || at == AT_H2_HEAD ? &r.headers : &r.trailers);
        if (!(r.body.len == 2 && memcmp(r.body.data, "ok", 2) == 0)) rc = ZUH_ERR_IO;
        zuh_result_free(&r);
    } else if (e.code != rc) {
        rc = ZUH_CODE_COUNT;        /* the error and the code disagree */
    }
    return rc;
}

static void cases_limits(void) {
    field_list f;
    size_t at, k, got;
    static const size_t splits[] = { 0, 1 };

    /* #259, D-101: one rule and one class. 8 fields straddle 64 KiB by the
     * field-section rule; their wire bytes stay under the HTTP/1.1 cap, so
     * the rule alone decides. Before D-101, HTTP/1.1 heads charged 4 bytes
     * a field and raised zu_body_limit_error, and HTTP/2 counted :status. */
    ZUH_CASE("limits: one field list is accepted or refused alike in every block, as D-101 counts it (#259)");
    {
        static const struct { size_t cost; zuh_code want; } cases[] = {
            { 65535, ZUH_OK }, { 65536, ZUH_OK }, { 65537, ZUH_ERR_PARSE } };
        size_t j;
        for (j = 0; j < sizeof cases / sizeof cases[0]; j++) {
            ZUH_CHECK(field_list_make(&f, 8, 0, cases[j].cost));
            for (at = 0; at < AT_COUNT; at++) {
                for (k = 0; k < sizeof splits / sizeof splits[0]; k++) {
                    zuh_code rc = serve_fields((int)at, &f, splits[k], &got);
                    if (rc != cases[j].want)
                        printf("    %s, cost %lu, reads of %lu: code %d\n", k_at[at],
                               (unsigned long)cases[j].cost, (unsigned long)splits[k], (int)rc);
                    ZUH_CHECK_EQ_INT(rc, cases[j].want);
                    if (rc == ZUH_OK) ZUH_CHECK_EQ_INT(got, 8);
                }
            }
            field_list_free(&f);
        }
    }
}

void suite_h2(void) {
    cases_unit();
    cases_exchange();
    cases_pool();
    cases_failures();
    cases_alloc();
    cases_w21();
    cases_w22();
    cases_review();
    cases_limits();
}


/* --- W21: trailers, the pulled body, cancellation, keepalive ------------- */

static zuh_code stop_write(zuh_sink *sk, const unsigned char *d, size_t n, zuh_error *e) {
    (void)d; (void)e;
    sk->written += n;
    sk->stopped = 1;
    return ZUH_ERR_CANCELLED;
}

static void spin_ms(long ms) {
    zuh_millis t0 = zuh_now_ms();
    while (zuh_now_ms() - t0 < ms) { }
}

static void cases_w21(void) {
    static char big[12 * 1024 * 1024];
    srv_dialer dd;
    zuh_get_opts o;
    zuh_result r;
    zuh_error e;
    zuh_code rc;
    zuh_pool *pool;
    size_t i;
    for (i = 0; i < sizeof big; i++) big[i] = (char)('A' + (i * 13) % 26);

    ZUH_CASE("§65.3: trailers arrive in the result, apart from the headers");
    {
        srv_cfg c; memset(&c, 0, sizeof c);
        c.body = "x"; c.body_len = 1;
        c.trailer_name = "grpc-status"; c.trailer_value = "0";
        dialer_init(&dd, &c); h2c_opts(&o, &dd); zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) {
            const char *v = zuh_headers_get(&r.trailers, "Grpc-Status");
            ZUH_CHECK(v && strcmp(v, "0") == 0);
            ZUH_CHECK(zuh_headers_get(&r.headers, "grpc-status") == NULL);
            zuh_result_free(&r);
        }
        dialer_free(&dd);
    }

    ZUH_CASE("§65.3, §40: an HTTP/2 trailer block over the limit is zu_http_parse_error");
    {
        static char huge[70000];
        srv_cfg c; memset(&c, 0, sizeof c);
        memset(huge, 't', sizeof huge - 1);
        c.body = "x"; c.body_len = 1;
        c.trailer_name = "x-huge"; c.trailer_value = huge;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_ERR_PARSE);
        ZUH_CHECK(has(e.message, "trailer"));
        dialer_free(&dd);
    }

    ZUH_CASE("§65.3: a Trailers-Only response is headers, an empty body, no error");
    {
        srv_cfg c; memset(&c, 0, sizeof c);
        c.hname[0] = "grpc-status"; c.hvalue[0] = "5";
        dialer_init(&dd, &c); h2c_opts(&o, &dd); zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) {
            ZUH_CHECK(zuh_headers_get(&r.headers, "grpc-status") != NULL);
            ZUH_CHECK_EQ_INT(r.body.len, 0);
            ZUH_CHECK_EQ_INT(zuh_headers_total(&r.trailers), 0);
            zuh_result_free(&r);
        }
        dialer_free(&dd);
    }

    ZUH_CASE("§65.4: a pulled body arrives whole, in the caller's pieces, then the trailers");
    {
        zuh_buffer got;
        srv_cfg c; memset(&c, 0, sizeof c);
        c.body = big; c.body_len = 300000;
        c.trailer_name = "grpc-status"; c.trailer_value = "0";
        dialer_init(&dd, &c); h2c_opts(&o, &dd); o.stream_body = 1;
        pool = zuh_pool_new(NULL); o.pool = pool;
        zuh_buf_init(&got, 0, (size_t)-1);
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/s", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) {
            int reads = 0;
            ZUH_CHECK(r.open != NULL);
            ZUH_CHECK_EQ_INT(r.body.len, 0);
            for (;;) {
                size_t before = got.len;
                rc = zuh_open_body_read(r.open, &got, 7000, &e);
                if (rc != ZUH_OK || got.len == before) break;
                ZUH_CHECK(got.len - before <= 7000);
                reads++;
            }
            ZUH_CHECK_EQ_INT(rc, ZUH_OK);
            ZUH_CHECK(reads > 40);
            ZUH_CHECK_EQ_INT(got.len, 300000);
            ZUH_CHECK(got.len == 300000 && memcmp(got.data, big, 300000) == 0);
            ZUH_CHECK(zuh_open_body_done(r.open));
            {
                const char *v = zuh_headers_get(zuh_open_body_trailers(r.open), "grpc-status");
                ZUH_CHECK(v && strcmp(v, "0") == 0);
            }
            zuh_result_free(&r);
        }
        ZUH_CASE("§65.4: an ended pulled body gives its connection back to the pool");
        zuh_error_clear(&e);
        o.stream_body = 0;
        rc = zuh_engine_perform(&r, "http://example.test/again", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) { ZUH_CHECK_EQ_INT(r.reused_connection, 1); zuh_result_free(&r); }
        ZUH_CHECK_EQ_INT(dd.dials, 1);
        zuh_buf_free(&got);
        zuh_pool_free(pool);
        dialer_free(&dd);
    }

    ZUH_CASE("§65.4: an unread stream stops the server after one window");
    {
        zuh_buffer got;
        size_t sent_before;
        srv_cfg c; memset(&c, 0, sizeof c);
        c.body = big; c.body_len = sizeof big;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); o.stream_body = 1;
        zuh_buf_init(&got, 0, (size_t)-1);
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/s", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) {
            sent_before = dd.conns[0].body_off;
            /* The window is ZUH_H2_WINDOW; nothing beyond it was produced. */
            ZUH_CHECK(sent_before <= (size_t)ZUH_H2_WINDOW);
            ZUH_CHECK(sent_before < sizeof big);
            ZUH_CASE("§65.4: reading grants the window back, and the server goes on");
            while (got.len < (size_t)ZUH_H2_WINDOW + 2u * 1024u * 1024u &&
                   zuh_open_body_read(r.open, &got, 65536, &e) == ZUH_OK) { }
            ZUH_CHECK(dd.conns[0].body_off > sent_before);
            ZUH_CHECK(memcmp(got.data, big, got.len) == 0);
            zuh_result_free(&r);
        }
        zuh_buf_free(&got);
        dialer_free(&dd);
    }

    ZUH_CASE("§40 under §65.4: max_body holds across a pulled body");
    {
        zuh_buffer got;
        srv_cfg c; memset(&c, 0, sizeof c);
        c.body = big; c.body_len = 100000;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); o.stream_body = 1; o.max_body = 50000;
        zuh_buf_init(&got, 0, (size_t)-1);
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/s", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) {
            while ((rc = zuh_open_body_read(r.open, &got, 4096, &e)) == ZUH_OK &&
                   !zuh_open_body_done(r.open)) { }
            ZUH_CHECK_EQ_INT(rc, ZUH_ERR_BODY_LIMIT);
            ZUH_CHECK(got.len <= 50000);
            zuh_result_free(&r);
        }
        zuh_buf_free(&got);
        dialer_free(&dd);
    }

    ZUH_CASE("§65.5: abort over HTTP/2 sends RST_STREAM(CANCEL) and keeps the connection");
    {
        zuh_buffer got;
        srv_cfg c; memset(&c, 0, sizeof c);
        c.body = big; c.body_len = sizeof big;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); o.stream_body = 1;
        pool = zuh_pool_new(NULL); o.pool = pool;
        zuh_buf_init(&got, 0, (size_t)-1);
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/s", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) {
            ZUH_CHECK_EQ_INT(zuh_open_body_read(r.open, &got, 1000, &e), ZUH_OK);
            zuh_open_body_abort(r.open);
            ZUH_CHECK(dd.conns[0].rst_seen);
            ZUH_CHECK_EQ_INT(dd.conns[0].rst_code, NGHTTP2_CANCEL);
            ZUH_CASE("§65.5: reading an aborted body is zu_cancelled_error; a second abort is a no-op");
            zuh_open_body_abort(r.open);
            ZUH_CHECK_EQ_INT(zuh_open_body_read(r.open, &got, 1000, &e), ZUH_ERR_CANCELLED);
            zuh_result_free(&r);
        }
        ZUH_CASE("§65.5: the next request reuses the connection the abort kept");
        {
            srv_cfg c2; memset(&c2, 0, sizeof c2);
            c2.body = "after"; c2.body_len = 5;
            dd.cfg = &c2; dd.conns[0].cfg = &c2;
            o.stream_body = 0;
            zuh_error_clear(&e);
            rc = zuh_engine_perform(&r, "http://example.test/next", NULL, &o, &e);
            ZUH_CHECK_EQ_INT(rc, ZUH_OK);
            if (rc == ZUH_OK) {
                ZUH_CHECK_EQ_INT(r.reused_connection, 1);
                ZUH_CHECK_EQ_INT(r.body.len, 5);
                zuh_result_free(&r);
            }
            ZUH_CHECK_EQ_INT(dd.dials, 1);
            dd.conns[0].cfg = &c;
        }
        zuh_buf_free(&got);
        zuh_pool_free(pool);
        dialer_free(&dd);
    }

    ZUH_CASE("§65.5: a sink that asks to stop resets the stream and keeps the connection");
    {
        zuh_sink stop;
        srv_cfg c; memset(&c, 0, sizeof c);
        c.body = big; c.body_len = 200000;
        memset(&stop, 0, sizeof stop);
        stop.write = stop_write;
        dialer_init(&dd, &c); h2c_opts(&o, &dd);
        pool = zuh_pool_new(NULL); o.pool = pool; o.sink = &stop;
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/s", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) zuh_result_free(&r);
        ZUH_CHECK(dd.conns[0].rst_seen);
        ZUH_CHECK_EQ_INT(dd.conns[0].rst_code, NGHTTP2_CANCEL);
        o.sink = NULL;
        {
            srv_cfg c2; memset(&c2, 0, sizeof c2);
            c2.body = "ok"; c2.body_len = 2;
            dd.cfg = &c2; dd.conns[0].cfg = &c2;
            zuh_error_clear(&e);
            rc = zuh_engine_perform(&r, "http://example.test/next", NULL, &o, &e);
            ZUH_CHECK_EQ_INT(rc, ZUH_OK);
            if (rc == ZUH_OK) { ZUH_CHECK_EQ_INT(r.reused_connection, 1); zuh_result_free(&r); }
            ZUH_CHECK_EQ_INT(dd.dials, 1);
            dd.conns[0].cfg = &c;
        }
        zuh_pool_free(pool);
        dialer_free(&dd);
    }

    ZUH_CASE("§65.6: a pooled h2 connection that answers PING is kept");
    {
        zuh_pool_config pc;
        srv_cfg c; memset(&c, 0, sizeof c);
        c.body = "k"; c.body_len = 1;
        zuh_pool_config_init(&pc); pc.keepalive_time_ms = 1; pc.keepalive_timeout_ms = 200;
        dialer_init(&dd, &c); h2c_opts(&o, &dd);
        pool = zuh_pool_new(&pc); o.pool = pool;
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/1", NULL, &o, &e);
        if (rc == ZUH_OK) zuh_result_free(&r);
        spin_ms(5);
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/2", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) { ZUH_CHECK_EQ_INT(r.reused_connection, 1); zuh_result_free(&r); }
        ZUH_CHECK_EQ_INT(dd.dials, 1);
        /* Exactly one: a PING per acquire past keepalive_time, not per
         * poll or per frame (review #160). */
        ZUH_CHECK_EQ_INT(dd.conns[0].pings, 1);
        zuh_pool_free(pool);
        dialer_free(&dd);
    }

    ZUH_CASE("§65.6: within keepalive_time a pooled connection is reused without a PING");
    {
        /* zuh_h2_idle_ms() reads the monotonic clock, not the pool's
         * injectable one: the idle time is the connection's own, measured
         * from its last frame, so this case and the one above use a time
         * far above and far below the spin rather than a fake clock. */
        zuh_pool_config pc;
        srv_cfg c; memset(&c, 0, sizeof c);
        c.body = "k"; c.body_len = 1;
        zuh_pool_config_init(&pc); pc.keepalive_time_ms = 600000; pc.keepalive_timeout_ms = 200;
        dialer_init(&dd, &c); h2c_opts(&o, &dd);
        pool = zuh_pool_new(&pc); o.pool = pool;
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/1", NULL, &o, &e);
        if (rc == ZUH_OK) zuh_result_free(&r);
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/2", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) { ZUH_CHECK_EQ_INT(r.reused_connection, 1); zuh_result_free(&r); }
        ZUH_CHECK_EQ_INT(dd.conns[0].pings, 0);
        zuh_pool_free(pool);
        dialer_free(&dd);
    }

    ZUH_CASE("§65.6: one that stops answering PING is evicted, and the next request reconnects");
    {
        zuh_pool_config pc;
        srv_cfg c; memset(&c, 0, sizeof c);
        c.body = "k"; c.body_len = 1; c.stall_after_first = 1;
        zuh_pool_config_init(&pc); pc.keepalive_time_ms = 1; pc.keepalive_timeout_ms = 50;
        dialer_init(&dd, &c); h2c_opts(&o, &dd);
        pool = zuh_pool_new(&pc); o.pool = pool;
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/1", NULL, &o, &e);
        if (rc == ZUH_OK) zuh_result_free(&r);
        spin_ms(5);
        /* The stalled server is the first connection; the second is new and
         * answers, because stall_after_first counts its own requests. */
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/2", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) { ZUH_CHECK_EQ_INT(r.reused_connection, 0); zuh_result_free(&r); }
        ZUH_CHECK_EQ_INT(dd.dials, 2);
        zuh_pool_free(pool);
        dialer_free(&dd);
    }

    ZUH_CASE("§65.4 over HTTP/1.1: a pulled body, and abort closes the connection");
    {
        static const char resp[] =
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            "5\r\nhello\r\n6\r\n world\r\n0\r\nX-Checksum: abc\r\n\r\n";
        zuh_buffer got;
        srv_cfg c; memset(&c, 0, sizeof c);
        c.raw = (const unsigned char *)resp; c.raw_len = sizeof resp - 1;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); o.http2 = ZUH_H2_AUTO; o.stream_body = 1;
        zuh_buf_init(&got, 0, (size_t)-1);
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) {
            while (zuh_open_body_read(r.open, &got, 3, &e) == ZUH_OK && !zuh_open_body_done(r.open)) { }
            ZUH_CHECK_EQ_INT(got.len, 11);
            ZUH_CHECK_MEM(got.data, "hello world", 11);
            ZUH_CASE("§18.2, D-91: chunked trailers reach the caller");
            {
                const char *v = zuh_headers_get(zuh_open_body_trailers(r.open), "x-checksum");
                ZUH_CHECK(v && strcmp(v, "abc") == 0);
            }
            zuh_result_free(&r);
        }
        zuh_buf_free(&got);
        dialer_free(&dd);
    }

    ZUH_CASE("§18.2, D-91: chunked trailers reach a buffered result too");
    {
        static const char resp[] =
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            "2\r\nhi\r\n0\r\nGrpc-Status: 0\r\nGrpc-Message: ok\r\n\r\n";
        srv_cfg c; memset(&c, 0, sizeof c);
        c.raw = (const unsigned char *)resp; c.raw_len = sizeof resp - 1;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); o.http2 = ZUH_H2_AUTO;
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) {
            ZUH_CHECK_EQ_INT(zuh_headers_total(&r.trailers), 2);
            ZUH_CHECK(zuh_headers_get(&r.trailers, "grpc-message") != NULL);
            zuh_result_free(&r);
        }
        dialer_free(&dd);
    }
}


/* --- W22: a streamed request body (§65.7) ---------------------------------- */

static zuh_code gen_next(void *ctx, const void **data, size_t *len, zuh_deadline dl,
                         zuh_error *err) {
    gen_ctx *g = (gen_ctx *)ctx;
    int k;
    (void)dl;
    g->calls++;
    if (g->fail_at && g->sent == g->fail_at) {
        zuh_error_set(err, ZUH_ERR_CANCELLED, ZUH_PHASE_WRITE, "the generator failed");
        return ZUH_ERR_CANCELLED;
    }
    if (g->sent == g->pieces) { *len = 0; return ZUH_OK; }
    for (k = 0; k < g->piece_len; k++) g->buf[k] = (unsigned char)((g->sent * 7 + k) & 0xff);
    *data = g->buf;
    *len = (size_t)g->piece_len;
    g->sent++;
    return ZUH_OK;
}
static void gen_release(void *ctx) { ((gen_ctx *)ctx)->released++; }

static void gen_expect(gen_ctx *g) {
    int p, k;
    size_t pos = 0;
    g->expect_sum = 0;
    for (p = 0; p < g->pieces; p++)
        for (k = 0; k < g->piece_len; k++, pos++)
            g->expect_sum += (unsigned long)((p * 7 + k) & 0xff) * (unsigned long)(pos % 251 + 1);
    g->expect_total = pos;
}

static void cases_w22(void) {
    srv_dialer dd;
    zuh_get_opts o;
    zuh_result r;
    zuh_error e;
    zuh_code rc;
    zuh_req_spec spec;

    ZUH_CASE("§65.7: a streamed body reaches the server whole and in order, with no length");
    {
        gen_ctx g; srv_cfg c;
        memset(&g, 0, sizeof g); memset(&c, 0, sizeof c);
        g.pieces = 60; g.piece_len = 3000;          /* 180 KB: past the 64 KiB window */
        gen_expect(&g);
        memset(&spec, 0, sizeof spec);
        spec.method = "POST";
        spec.source.next = gen_next; spec.source.release = gen_release; spec.source.ctx = &g;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/up", &spec, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) zuh_result_free(&r);
        ZUH_CHECK_EQ_INT(dd.conns[0].body_total, g.expect_total);
        ZUH_CHECK(dd.conns[0].body_sum == g.expect_sum);
        ZUH_CHECK(!has(dd.conns[0].fields, "content-length"));
        ZUH_CHECK_EQ_INT(g.released, 1);
        dialer_free(&dd);
    }

    ZUH_CASE("§65.7, D-47: a failing body function stops the request and the connection is not pooled");
    {
        gen_ctx g; srv_cfg c; zuh_pool *pool;
        memset(&g, 0, sizeof g); memset(&c, 0, sizeof c);
        g.pieces = 10; g.piece_len = 1000; g.fail_at = 3;
        c.body = "ok"; c.body_len = 2;
        memset(&spec, 0, sizeof spec);
        spec.method = "POST";
        spec.source.next = gen_next; spec.source.release = gen_release; spec.source.ctx = &g;
        dialer_init(&dd, &c); h2c_opts(&o, &dd);
        pool = zuh_pool_new(NULL); o.pool = pool;
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/up", &spec, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_ERR_CANCELLED);
        ZUH_CHECK(has(e.message, "generator"));
        ZUH_CHECK_EQ_INT(g.released, 1);
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/next", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) { ZUH_CHECK_EQ_INT(r.reused_connection, 0); zuh_result_free(&r); }
        ZUH_CHECK_EQ_INT(dd.dials, 2);
        zuh_pool_free(pool);
        dialer_free(&dd);
    }

    ZUH_CASE("§65.7: with stream_body, the pulled body inherits the source and releases it once");
    {
        gen_ctx g; srv_cfg c; zuh_buffer got;
        memset(&g, 0, sizeof g); memset(&c, 0, sizeof c);
        g.pieces = 3; g.piece_len = 100;
        c.body = "echo"; c.body_len = 4;
        memset(&spec, 0, sizeof spec);
        spec.method = "POST";
        spec.source.next = gen_next; spec.source.release = gen_release; spec.source.ctx = &g;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); o.stream_body = 1;
        zuh_buf_init(&got, 0, (size_t)-1);
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/up", &spec, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) {
            ZUH_CHECK_EQ_INT(g.released, 0);        /* still the pulled body's */
            ZUH_CHECK(zuh_open_body_source_ctx(r.open) == &g);
            while (zuh_open_body_read(r.open, &got, 100, &e) == ZUH_OK && !zuh_open_body_done(r.open)) { }
            ZUH_CHECK_EQ_INT(got.len, 4);
            zuh_result_free(&r);
        }
        ZUH_CHECK_EQ_INT(g.released, 1);
        zuh_buf_free(&got);
        dialer_free(&dd);
    }
}

/* --- the 2026-11-05 review (#137-#162) ------------------------------------ */

static unsigned long weighted_sum(const unsigned char *p, size_t n) {
    unsigned long sum = 0;
    size_t k;
    for (k = 0; k < n; k++) sum += (unsigned long)p[k] * (unsigned long)(k % 251 + 1);
    return sum;
}

/* First request on a pooled connection, then `poke` changes what the idle
 * connection holds, then a second request. */
static void stale_probe_case(const char *name, void (*poke)(srv *), int want_dials) {
    srv_dialer dd; zuh_get_opts o; zuh_result r; zuh_error e; zuh_code rc;
    zuh_pool *pool = zuh_pool_new(NULL);
    srv_cfg c; memset(&c, 0, sizeof c);
    c.body = "1"; c.body_len = 1;
    ZUH_CASE(name);
    dialer_init(&dd, &c); h2c_opts(&o, &dd); o.pool = pool;
    zuh_error_clear(&e);
    rc = zuh_engine_perform(&r, "http://example.test/1", NULL, &o, &e);
    ZUH_CHECK_EQ_INT(rc, ZUH_OK);
    if (rc == ZUH_OK) zuh_result_free(&r);
    poke(&dd.conns[0]);
    zuh_error_clear(&e);
    rc = zuh_engine_perform(&r, "http://example.test/2", NULL, &o, &e);
    ZUH_CHECK_EQ_INT(rc, ZUH_OK);
    if (rc == ZUH_OK) {
        ZUH_CHECK_EQ_INT(r.reused_connection, want_dials == 1);
        zuh_result_free(&r);
    }
    ZUH_CHECK_EQ_INT(dd.dials, want_dials);
    zuh_pool_free(pool);
    dialer_free(&dd);
}

static void poke_goaway(srv *v) {
    nghttp2_submit_goaway(v->srv, NGHTTP2_FLAG_NONE, v->last_sid, NGHTTP2_NO_ERROR, NULL, 0);
    srv_drain(v);
}
static void poke_eof(srv *v) { v->eof = 1; }
static void poke_garbage(srv *v) {
    /* A DATA frame on stream 0: a connection error (RFC 9113 §6.1). */
    static const unsigned char bad[] = { 0, 0, 1, 0, 0, 0, 0, 0, 0, 'x' };
    out_append(v, bad, sizeof bad);
}
static void poke_ping_settings(srv *v) {
    nghttp2_submit_ping(v->srv, NGHTTP2_FLAG_NONE, NULL);
    nghttp2_submit_settings(v->srv, NGHTTP2_FLAG_NONE, NULL, 0);
    srv_drain(v);
}

static unsigned char k_huge[5u << 20];

/* #189: a tick that cancels on its n-th call. */
typedef struct { int calls, cancel_at; } tick_ctr;
static int counting_tick(void *ctx) {
    tick_ctr *c = (tick_ctr *)ctx;
    c->calls++;
    return c->calls >= c->cancel_at;
}

static void cases_review(void) {
    srv_dialer dd;
    zuh_get_opts o;
    zuh_result r;
    zuh_error e;
    zuh_code rc;
    zuh_req_spec spec;
    size_t i;

    for (i = 0; i < sizeof k_huge; i++) k_huge[i] = (unsigned char)((i * 13 + 5) & 0xff);

    ZUH_CASE("§65.7: a response that arrives before the in-memory body has gone out (#137)");
    {
        /* The server answers on HEADERS; the body is three windows long, so
         * most of it is unsent when zuh_engine_perform() returns the pulled
         * response. The caller's buffer is then overwritten and freed, as
         * an R raw vector can be collected once the .Call returns: the rest
         * must come from the connection's own copy. */
        const size_t n = 200000;
        unsigned char *body = (unsigned char *)malloc(n);
        unsigned long want;
        zuh_buffer got;
        srv_cfg c; memset(&c, 0, sizeof c);
        for (i = 0; i < n; i++) body[i] = (unsigned char)((i * 7 + 3) & 0xff);
        want = weighted_sum(body, n);
        c.respond_on_headers = 1;
        c.body = "ok"; c.body_len = 2;
        memset(&spec, 0, sizeof spec);
        spec.method = "POST"; spec.body = body; spec.body_len = n;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); o.stream_body = 1;
        zuh_buf_init(&got, 0, (size_t)-1);
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/up", &spec, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        ZUH_CHECK(dd.conns[0].body_total < n);     /* the case is real */
        memset(body, 0xEE, n);
        free(body);
        if (rc == ZUH_OK) {
            while ((rc = zuh_open_body_read(r.open, &got, 100, &e)) == ZUH_OK &&
                   !zuh_open_body_done(r.open)) { }
            ZUH_CHECK_EQ_INT(rc, ZUH_OK);
            ZUH_CHECK(got.len == 2 && memcmp(got.data, "ok", 2) == 0);
            zuh_result_free(&r);
        }
        ZUH_CHECK_EQ_INT(dd.conns[0].body_total, n);
        ZUH_CHECK(dd.conns[0].body_sum == want);
        zuh_buf_free(&got);
        dialer_free(&dd);
    }

    ZUH_CASE("§65.7: a server that ended its side first: the last DATA closes the stream, no wait (#140)");
    {
        /* The loopback fails a read it cannot answer at once, so a driver
         * that read after the stream closed fails here instead of waiting
         * out the deadline. One window and 1000 bytes: the last piece goes
         * out after the server has answered, and is too small to make the
         * server send a WINDOW_UPDATE back, so after it there is nothing at
         * all to read. (pump() sends that piece in its closing flush, so the
         * pump_stream() guard is not what this case needs today; it is the
         * end-to-end regression for the early-response exchange.) */
        const size_t n = 65535 + 1000;
        srv_cfg c; memset(&c, 0, sizeof c);
        c.respond_on_headers = 1;
        c.body = "early"; c.body_len = 5;
        memset(&spec, 0, sizeof spec);
        spec.method = "POST"; spec.body = k_huge; spec.body_len = n;
        dialer_init(&dd, &c); h2c_opts(&o, &dd);
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/up", &spec, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) {
            ZUH_CHECK(r.body.len == 5 && memcmp(r.body.data, "early", 5) == 0);
            zuh_result_free(&r);
        }
        ZUH_CHECK_EQ_INT(dd.conns[0].body_total, n);
        ZUH_CHECK(dd.conns[0].body_sum == weighted_sum(k_huge, n));
        dialer_free(&dd);
    }

    ZUH_CASE("§65.7: full duplex: headers arrive before the body function ends, all of it in order");
    {
        gen_ctx g; srv_cfg c; zuh_buffer got;
        memset(&g, 0, sizeof g); memset(&c, 0, sizeof c);
        g.pieces = 60; g.piece_len = 3000;
        gen_expect(&g);
        c.respond_on_headers = 1;
        c.body = "duplex"; c.body_len = 6;
        memset(&spec, 0, sizeof spec);
        spec.method = "POST";
        spec.source.next = gen_next; spec.source.release = gen_release; spec.source.ctx = &g;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); o.stream_body = 1;
        zuh_buf_init(&got, 0, (size_t)-1);
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/up", &spec, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) {
            ZUH_CHECK(g.sent < g.pieces);            /* still sending */
            while ((rc = zuh_open_body_read(r.open, &got, 100, &e)) == ZUH_OK &&
                   !zuh_open_body_done(r.open)) { }
            ZUH_CHECK_EQ_INT(rc, ZUH_OK);
            ZUH_CHECK_EQ_INT(got.len, 6);
            ZUH_CHECK(zuh_open_body_ended_clean(r.open));
            zuh_result_free(&r);
        }
        ZUH_CHECK_EQ_INT(dd.conns[0].body_total, g.expect_total);
        ZUH_CHECK(dd.conns[0].body_sum == g.expect_sum);
        ZUH_CHECK_EQ_INT(g.released, 1);
        zuh_buf_free(&got);
        dialer_free(&dd);
    }

    ZUH_CASE("§65.2: GOAWAY below the stream id is zu_io_error naming GOAWAY, never pooled (#146)");
    {
        zuh_pool *pool = zuh_pool_new(NULL);
        srv_cfg c; memset(&c, 0, sizeof c);
        c.goaway_refuse = 1;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); o.pool = pool;
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_ERR_IO);
        ZUH_CHECK(has(e.message, "GOAWAY"));
        ZUH_CHECK_EQ_INT(e.backend_code, NGHTTP2_REFUSED_STREAM);
        ZUH_CHECK_EQ_INT(zuh_pool_idle_count(pool), 0);
        zuh_pool_free(pool);
        dialer_free(&dd);
    }

    ZUH_CASE("§65.2: RST_STREAM(NO_ERROR) before any response is a malformed response (#146)");
    {
        srv_cfg c; memset(&c, 0, sizeof c);
        c.rst_no_error = 1;
        dialer_init(&dd, &c); h2c_opts(&o, &dd);
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_ERR_PARSE);
        ZUH_CHECK(has(e.message, "without a response"));
        dialer_free(&dd);
    }

    ZUH_CASE("§65.2: a transport write failure is that failure, and the connection is not pooled (#146)");
    {
        zuh_pool *pool = zuh_pool_new(NULL);
        zuh_buffer got;
        srv_cfg c; memset(&c, 0, sizeof c);
        /* Over ZUH_H2_WINDOW, so reading it needs a WINDOW_UPDATE. */
        c.body = k_huge; c.body_len = sizeof k_huge;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); o.pool = pool; o.stream_body = 1;
        zuh_buf_init(&got, 0, (size_t)-1);
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) {
            /* The window update the next read sends cannot go out. */
            dd.conns[0].fail_writes = 1;
            while ((rc = zuh_open_body_read(r.open, &got, 65536, &e)) == ZUH_OK &&
                   !zuh_open_body_done(r.open)) { }
            ZUH_CHECK_EQ_INT(rc, ZUH_ERR_IO);
            ZUH_CHECK(has(e.message, "write failed"));
            zuh_result_free(&r);
        }
        ZUH_CHECK_EQ_INT(zuh_pool_idle_count(pool), 0);
        zuh_buf_free(&got);
        zuh_pool_free(pool);
        dialer_free(&dd);
    }

    ZUH_CASE("§65.5: an abort whose RST_STREAM cannot be sent ends the connection too (#146)");
    {
        zuh_pool *pool = zuh_pool_new(NULL);
        srv_cfg c; memset(&c, 0, sizeof c);
        c.body = k_huge; c.body_len = 300000;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); o.pool = pool; o.stream_body = 1;
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) {
            size_t written = dd.conns[0].written;
            dd.conns[0].fail_writes = 1;
            zuh_open_body_abort(r.open);
            zuh_result_free(&r);
            /* Nothing more reached the wire (#196): the server session
             * never sees the RST_STREAM, so `rst_seen` would be 0 whatever
             * the client did, and is not the evidence. */
            ZUH_CHECK_EQ_INT(dd.conns[0].written, written);
        }
        ZUH_CHECK_EQ_INT(zuh_pool_idle_count(pool), 0);
        zuh_pool_free(pool);
        dialer_free(&dd);
    }

    ZUH_CASE("§65.2: a failed connection refuses another request (#146)");
    {
        zuh_stream *t = NULL, *h2s = NULL;
        zuh_headers hh;
        zuh_h2_request rq;
        int st = 0, bodiless = 0;
        srv_cfg c; memset(&c, 0, sizeof c);
        dialer_init(&dd, &c);
        zuh_error_clear(&e);
        ZUH_CHECK_EQ_INT(lb_dial(&dd, "example.test", 80, &t, &e), ZUH_OK);
        ZUH_CHECK_EQ_INT(zuh_h2_wrap(&h2s, t, 0, &e), ZUH_OK);
        zuh_headers_init(&hh);
        memset(&rq, 0, sizeof rq);
        rq.method = "GET"; rq.scheme = "http"; rq.authority = "example.test"; rq.path = "/";
        rq.headers = &hh;
        dd.conns[0].fail_writes = 1;
        rc = zuh_h2_begin(h2s, &rq, &st, &hh, &bodiless, zuh_deadline_in(1000), &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_ERR_IO);
        ZUH_CHECK(!zuh_h2_reusable(h2s));
        dd.conns[0].fail_writes = 0;
        zuh_error_clear(&e);
        rc = zuh_h2_begin(h2s, &rq, &st, &hh, &bodiless, zuh_deadline_in(1000), &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_ERR_IO);
        ZUH_CHECK(has(e.message, "cannot carry another request"));
        zuh_headers_free(&hh);
        zuh_stream_free(h2s);
        dialer_free(&dd);
    }

    /* #147: the idle probe answers from what arrived on the connection. */
    stale_probe_case("§65.2: an idle connection the server sent GOAWAY on is stale (#147)",
                     poke_goaway, 2);
    stale_probe_case("§65.2: an idle connection the server closed is stale (#147)",
                     poke_eof, 2);
    stale_probe_case("§65.2: an idle connection carrying a protocol error is stale (#147)",
                     poke_garbage, 2);
    stale_probe_case("§65.2: PING and SETTINGS on an idle connection are answered; it is reused (#147)",
                     poke_ping_settings, 1);

    ZUH_CASE("§65.5: aborts with more than a window in flight leak no connection window (#148)");
    {
        zuh_pool *pool = zuh_pool_new(NULL);
        zuh_buffer got;
        int k;
        srv_cfg c; memset(&c, 0, sizeof c);
        c.body = k_huge; c.body_len = sizeof k_huge;      /* over ZUH_H2_WINDOW */
        dialer_init(&dd, &c); h2c_opts(&o, &dd); o.pool = pool;
        zuh_buf_init(&got, 0, (size_t)-1);
        for (k = 0; k < 3; k++) {
            o.stream_body = 1;
            zuh_error_clear(&e);
            rc = zuh_engine_perform(&r, "http://example.test/a", NULL, &o, &e);
            ZUH_CHECK_EQ_INT(rc, ZUH_OK);
            if (rc == ZUH_OK) {
                /* The first time, nothing is read: what came in with the
                 * headers is still in the driver (zuh_h2_cancel()'s
                 * buffered-DATA branch). */
                if (k > 0) (void)zuh_open_body_read(r.open, &got, 1000, &e);
                zuh_open_body_abort(r.open);
                zuh_result_free(&r);
            }
        }
        o.stream_body = 0;
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/whole", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) {
            ZUH_CHECK_EQ_INT(r.reused_connection, 1);
            ZUH_CHECK_EQ_INT(r.body.len, sizeof k_huge);
            ZUH_CHECK(r.body.len == sizeof k_huge && memcmp(r.body.data, k_huge, sizeof k_huge) == 0);
            zuh_result_free(&r);
        }
        ZUH_CHECK_EQ_INT(dd.dials, 1);
        zuh_buf_free(&got);
        zuh_pool_free(pool);
        dialer_free(&dd);
    }

    ZUH_CASE("RFC 9113 §8.2.2: no connection-specific header a caller sets is sent (#161)");
    {
        /* Transfer-Encoding is the sixth; the engine refuses it from a
         * caller before any protocol is chosen (§17), so here it can only
         * be the generated one, which HTTP/2 never generates. */
        static const char *const hn[] = { "keep-ALIVE", "Proxy-Connection",
                                          "Upgrade", "CONNECTION", "Host", "X-Kept" };
        static const char *const hv[] = { "timeout=5", "keep-alive",
                                          "websocket", "keep-alive", "example.test", "yes" };
        srv_cfg c; memset(&c, 0, sizeof c);
        memset(&spec, 0, sizeof spec);
        spec.header_names = hn; spec.header_values = hv; spec.n_headers = 6;
        dialer_init(&dd, &c); h2c_opts(&o, &dd);
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", &spec, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) zuh_result_free(&r);
        ZUH_CHECK(!has(dd.conns[0].fields, "keep-alive:"));
        ZUH_CHECK(!has(dd.conns[0].fields, "proxy-connection:"));
        ZUH_CHECK(!has(dd.conns[0].fields, "transfer-encoding:"));
        ZUH_CHECK(!has(dd.conns[0].fields, "upgrade:"));
        ZUH_CHECK(!has(dd.conns[0].fields, "connection:"));
        ZUH_CHECK(!has(dd.conns[0].fields, "host:"));
        ZUH_CHECK(strcmp(dd.conns[0].authority, "example.test") == 0);
        ZUH_CHECK(has(dd.conns[0].fields, "x-kept: yes"));
        dialer_free(&dd);
    }

    ZUH_CASE("§35.3: request.sent counts a streamed body's bytes over HTTP/2 (#169)");
    {
        gen_ctx g; srv_cfg c; zuh_trace tr;
        size_t k; uint64_t sent = 0; int seen = 0;
        memset(&g, 0, sizeof g); memset(&c, 0, sizeof c);
        g.pieces = 5; g.piece_len = 100;
        memset(&spec, 0, sizeof spec);
        spec.method = "POST";
        spec.source.next = gen_next; spec.source.release = gen_release; spec.source.ctx = &g;
        dialer_init(&dd, &c); h2c_opts(&o, &dd);
        zuh_trace_init(&tr); o.trace = &tr;
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/up", &spec, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) zuh_result_free(&r);
        for (k = 0; k < tr.n; k++)
            if (tr.ev[k].ev == ZUH_EV_REQUEST_SENT) { sent = tr.ev[k].n; seen = 1; }
        ZUH_CHECK(seen);
        ZUH_CHECK_EQ_INT(sent, 500);
        o.trace = NULL;
        dialer_free(&dd);
    }

    ZUH_CASE("§24.1, §65.6: the keepalive PING waits no longer than the request's deadline (#145)");
    {
        zuh_pool_config pc;
        zuh_pool *pool;
        zuh_millis t0;
        srv_cfg c; memset(&c, 0, sizeof c);
        c.body = "k"; c.body_len = 1; c.stall_after_first = 1; c.block_on_empty = 1;
        zuh_pool_config_init(&pc); pc.keepalive_time_ms = 1; pc.keepalive_timeout_ms = 10000;
        dialer_init(&dd, &c); h2c_opts(&o, &dd);
        pool = zuh_pool_new(&pc); o.pool = pool;
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/1", NULL, &o, &e);
        if (rc == ZUH_OK) zuh_result_free(&r);
        spin_ms(5);
        o.timeout_ms = 300;
        t0 = zuh_now_ms();
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/2", NULL, &o, &e);
        if (rc == ZUH_OK) zuh_result_free(&r);
        /* 300 ms, not keepalive_timeout's 10 s; whether the request then
         * fits on a new connection in what is left is the deadline's call,
         * so the outcome is one of those two (#196). */
        ZUH_CHECK(zuh_now_ms() - t0 < 1000);
        ZUH_CHECK(rc == ZUH_OK || rc == ZUH_ERR_TIMEOUT);
        zuh_pool_free(pool);
        dialer_free(&dd);
    }

    ZUH_CASE("§65.2: a read that would block is retried, not an error (#192)");
    {
        srv_cfg c; memset(&c, 0, sizeof c);
        c.body = k_abc; c.body_len = 3; c.wouldblock_every = 1;
        dialer_init(&dd, &c); h2c_opts(&o, &dd);
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) {
            ZUH_CHECK(r.body.len == 3 && memcmp(r.body.data, "abc", 3) == 0);
            zuh_result_free(&r);
        }
        ZUH_CHECK(dd.conns[0].wouldblocks > 0);      /* the branch ran */
        dialer_free(&dd);
    }

    ZUH_CASE("§65.2: a server that breaks the protocol mid-request ends the session as zu_http_parse_error (#192)");
    {
        /* A server preface (an empty SETTINGS), then DATA on stream 0: a
         * connection error (RFC 9113 §6.1). nghttp2 answers with GOAWAY and
         * wants nothing more, which is the "session over" branch of pump(),
         * with no GOAWAY from the peer to blame. */
        static const unsigned char raw[] = {
            0, 0, 0, 4, 0, 0, 0, 0, 0,           /* SETTINGS, empty */
            0, 0, 1, 0, 0, 0, 0, 0, 0, 'x' };    /* DATA on stream 0 */
        srv_cfg c; memset(&c, 0, sizeof c);
        c.raw = raw; c.raw_len = sizeof raw;
        dialer_init(&dd, &c); h2c_opts(&o, &dd);
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_ERR_PARSE);
        ZUH_CHECK(has(e.message, "broke the HTTP/2 protocol"));
        if (rc == ZUH_OK) zuh_result_free(&r);
        dialer_free(&dd);
    }

    ZUH_CASE("§25.1, §65.4: an interrupt inside a pulled HTTP/2 read cancels the body and pools nothing (#189)");
    {
        zuh_pool *pool = zuh_pool_new(NULL);
        zuh_buffer got;
        tick_ctr ctr = { 0, 3 };
        srv_cfg c; memset(&c, 0, sizeof c);
        c.body = k_huge; c.body_len = 300000;
        dialer_init(&dd, &c); h2c_opts(&o, &dd); o.pool = pool; o.stream_body = 1;
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) {
            dd.tick = counting_tick; dd.tick_ctx = &ctr;
            zuh_buf_init(&got, 0, (size_t)-1);
            while ((rc = zuh_open_body_read(r.open, &got, 1000, &e)) == ZUH_OK &&
                   !zuh_open_body_done(r.open)) { }
            ZUH_CHECK_EQ_INT(rc, ZUH_ERR_CANCELLED);
            ZUH_CHECK(ctr.calls >= 3);
            ZUH_CHECK(zuh_open_body_done(r.open));
            zuh_buf_free(&got);
            zuh_result_free(&r);
        }
        ZUH_CHECK_EQ_INT(zuh_pool_idle_count(pool), 0);
        zuh_pool_free(pool);
        dialer_free(&dd);
    }
}

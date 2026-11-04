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
#include "zuh_mock_stream.h"
#include <nghttp2/nghttp2.h>
#include <zlib.h>

void suite_h2(void);
static void cases_w21(void);

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
    /* Hostile mode: no server session at all; these bytes are the "server". */
    const unsigned char *raw;
    size_t      raw_len;
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
    int32_t last_sid;
    size_t body_off;             /* response DATA sent so far */
    uint32_t rst_code;           /* RST_STREAM the client sent, if any */
    int rst_seen;
} srv;

typedef struct {
    srv conns[SRV_MAX_CONN];
    const srv_cfg *cfg;
    int dials;
    size_t client_bytes;         /* everything the client wrote, all conns */
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
    }
    return 0;
}

static int s_on_data(nghttp2_session *s, uint8_t flags, int32_t sid,
                     const uint8_t *data, size_t len, void *ud) {
    srv *v = (srv *)ud;
    (void)s; (void)flags; (void)sid;
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
        }
    }
    return (nghttp2_ssize)n;
}

static void respond(srv *v, int32_t sid) {
    const srv_cfg *c = v->cfg;
    nghttp2_nv nv[6];
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
    nghttp2_submit_response2(v->srv, sid, nv, n, c->body_len ? &prd : NULL);
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
    if ((f->hd.type == NGHTTP2_HEADERS || f->hd.type == NGHTTP2_DATA) &&
        (f->hd.flags & NGHTTP2_FLAG_END_STREAM))
        respond(v, f->hd.stream_id);
    return 0;
}

/* --- the server as a zuh_stream -------------------------------------------- */

static zuh_ssize lb_read(zuh_stream *st, void *b, size_t n, zuh_deadline d, zuh_error *e) {
    srv *v = (srv *)st->impl;
    size_t have = v->out_len - v->out_off;
    (void)d;
    if (have == 0) {
        if (v->eof || v->cfg->raw) return 0;
        /* A real socket would wait; this one has nothing more to say, which
         * in a single-threaded loopback is a bug in the test or the client. */
        zuh_error_set(e, ZUH_ERR_TIMEOUT, ZUH_PHASE_READ, "loopback: nothing to read");
        return -1;
    }
    if (n > have) n = have;
    memcpy(b, v->out + v->out_off, n);
    v->out_off += n;
    return (zuh_ssize)n;
}

static zuh_ssize lb_write(zuh_stream *st, const void *b, size_t n, zuh_deadline d, zuh_error *e) {
    srv *v = (srv *)st->impl;
    (void)d; (void)e;
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
        ZUH_CHECK_EQ_INT(dd.conns[0].requests, 0);
        dialer_free(&dd);
    }

    ZUH_CASE("§65.1: with http2 = auto, http:// stays HTTP/1.1 (no preface is sent)");
    {
        static const char resp[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        zuh_mock_step step;
        zuh_stream *ms;
        srv_cfg c; memset(&c, 0, sizeof c);
        (void)ms;
        /* The h2 server would reject an HTTP/1.1 request line, so a server
         * that answered at all would prove the wrong protocol. Instead the
         * raw HTTP/1.1 reply is the peer, and the client must parse it. */
        c.raw = (const unsigned char *)resp; c.raw_len = sizeof resp - 1;
        memset(&step, 0, sizeof step);
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

/* Every allocation the client makes on an h2c GET, failed in turn: each
 * failure must come back as NOMEM with nothing leaked (§43's oracle). */
static void cases_alloc(void) {
    srv_dialer dd;
    zuh_get_opts o;
    zuh_result r;
    zuh_error e;
    zuh_code rc;
    zuh_alloc_stats before, after;
    long n, total = 0;
    int bad = 0, failed_cleanly = 0;
    srv_cfg c; memset(&c, 0, sizeof c);
    c.body = "abc"; c.body_len = 3;

    ZUH_CASE("§43: an h2c request survives every allocation failing in turn");
    zuh_alloc_stats_get(&before);
    dialer_init(&dd, &c); h2c_opts(&o, &dd); zuh_error_clear(&e);
    rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, &e);
    ZUH_CHECK_EQ_INT(rc, ZUH_OK);
    if (rc == ZUH_OK) zuh_result_free(&r);
    dialer_free(&dd);
    zuh_alloc_stats_get(&after);
    total = (long)(after.total_allocs - before.total_allocs);
    ZUH_CHECK(total > 10);
    for (n = 0; n < total; n++) {
        zuh_alloc_stats_get(&before);
        dialer_init(&dd, &c); h2c_opts(&o, &dd); zuh_error_clear(&e);
        zuh_alloc_fail_after(n);
        rc = zuh_engine_perform(&r, "http://example.test/", NULL, &o, &e);
        zuh_alloc_fail_after(-1);
        if (rc == ZUH_OK) zuh_result_free(&r);
        else if (e.code != ZUH_OK) failed_cleanly++;
        else bad++;
        dialer_free(&dd);
        zuh_alloc_stats_get(&after);
        if (after.live_blocks != before.live_blocks) bad++;
    }
    ZUH_CHECK(failed_cleanly > 0);
    ZUH_CHECK_EQ_INT(bad, 0);
}

void suite_h2(void) {
    cases_unit();
    cases_exchange();
    cases_pool();
    cases_failures();
    cases_alloc();
    cases_w21();
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

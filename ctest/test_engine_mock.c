/* The whole engine, offline, through the §50.1 dial seam.
 *
 * zu_engine_perform() runs for real — proxy routing, the pool, the CONNECT
 * tunnel, request building, framing, redirects, decoding and sinks — while
 * every connection it opens is a scripted mock. Until 2026-09-26 zu_engine.c
 * was not compiled into this suite at all, and the redirect credential leak
 * fixed then lived in exactly the code this file now drives.
 *
 * Each connection is wrapped in a "tap" that records what the engine wrote
 * and whether the script was consumed, into the dialer, so both survive the
 * engine freeing the stream. The harness's allocation check at the end of
 * main() then catches anything the engine leaked on any path below. */
#include "zu_test.h"
#include "zu_engine.h"
#include "zu_mock_stream.h"
#include "zu_pool.h"
#include "zu_alloc.h"
#include "zu_sink.h"
#include <zlib.h>

void suite_engine_mock(void);

#define MAXC 8

typedef struct {
    const char *bytes;
    size_t      len;          /* 0 => strlen(bytes) */
    size_t      max_read;     /* 1 => one byte per read */
    int         not_readable; /* force the §26.2 probe to "idle", for reuse */
    /* A second response, handed out only after the first is read — the way a
     * real server answers the next request, never ahead of it. */
    const char *next;
} conn_script;

typedef struct {
    const conn_script *scripts;
    size_t   n, next;
    char     host[MAXC][64];
    unsigned port[MAXC];
    zu_buffer sent[MAXC];
    int      exhausted[MAXC];
    zu_mock_step steps[MAXC][2];   /* the mock keeps a pointer to these */
} dialer;

typedef struct { zu_stream *inner; dialer *d; size_t idx; } tap_impl;

static zu_ssize tap_read(zu_stream *s, void *b, size_t n, zu_deadline dl, zu_error *e) {
    return zu_stream_read(((tap_impl *)s->impl)->inner, b, n, dl, e);
}
static zu_ssize tap_write(zu_stream *s, const void *b, size_t n, zu_deadline dl, zu_error *e) {
    tap_impl *t = (tap_impl *)s->impl;
    zu_ssize w = zu_stream_write(t->inner, b, n, dl, e);
    if (w > 0) zu_buf_append(&t->d->sent[t->idx], b, (size_t)w);
    return w;
}
static void tap_close(zu_stream *s) { zu_stream_close(((tap_impl *)s->impl)->inner); }
static int tap_readable(zu_stream *s, int ms) {
    return zu_stream_readable(((tap_impl *)s->impl)->inner, ms);
}
static void tap_destroy(zu_stream *s) {
    tap_impl *t = (tap_impl *)s->impl;
    t->d->exhausted[t->idx] = zu_mock_stream_exhausted(t->inner);
    zu_mock_stream_free(t->inner);
    zu_free(t);
    zu_free(s);
}
static const zu_stream_vtable k_tap_vt = {
    "tap", tap_read, tap_write, tap_close, tap_destroy, tap_readable
};

static zu_code dial(void *ctx, const char *host, uint16_t port,
                    zu_stream **out, zu_error *err) {
    dialer *d = (dialer *)ctx;
    const conn_script *c;
    tap_impl *t;
    zu_stream *s;
    size_t i = d->next;
    if (i >= d->n || i >= MAXC) {
        zu_error_set(err, ZU_ERR_CONNECT, ZU_PHASE_CONNECT, "no scripted connection left");
        return ZU_ERR_CONNECT;
    }
    c = &d->scripts[i];
    d->next++;
    snprintf(d->host[i], sizeof d->host[i], "%s", host);
    d->port[i] = port;
    t = (tap_impl *)zu_calloc(1, sizeof *t);
    s = (zu_stream *)zu_calloc(1, sizeof *s);
    d->steps[i][0].kind = ZU_MOCK_DATA;
    d->steps[i][0].data = c->bytes;
    d->steps[i][0].len  = c->len ? c->len : strlen(c->bytes);
    d->steps[i][1].kind = ZU_MOCK_DATA;
    d->steps[i][1].data = c->next;
    d->steps[i][1].len  = c->next ? strlen(c->next) : 0;
    t->inner = zu_mock_stream_new(d->steps[i], c->next ? 2 : 1, c->max_read, 0);
    if (c->not_readable) zu_mock_stream_set_readable(t->inner, 1, 0);
    t->d = d; t->idx = i;
    s->vt = &k_tap_vt; s->impl = t;
    *out = s;
    return ZU_OK;
}

static void dialer_init(dialer *d, const conn_script *s, size_t n) {
    size_t i;
    memset(d, 0, sizeof *d);
    d->scripts = s; d->n = n;
    for (i = 0; i < MAXC; i++) zu_buf_init(&d->sent[i], 256, 1 << 20);
}
static void dialer_free(dialer *d) {
    size_t i;
    for (i = 0; i < MAXC; i++) zu_buf_free(&d->sent[i]);
}
/* What connection i was sent, as a C string (the buffer is ours). */
static const char *sent(dialer *d, size_t i) {
    const char *s = "";
    zu_buf_cstr(&d->sent[i], &s);
    return s;
}
static int has(const char *hay, const char *needle) { return strstr(hay, needle) != NULL; }

static void opts_for(zu_get_opts *o, dialer *d) {
    zu_get_opts_init(o);
    o->dial = dial; o->dial_ctx = d;
    o->proxy_set = 1;            /* direct unless a test sets a proxy */
}

/* --- a table-backed environment, for the proxy cases (§20.1) --- */
typedef struct { const char *k[4]; const char *v[4]; } envtab;
static const char *env_get(void *ctx, const char *name) {
    envtab *e = (envtab *)ctx;
    int i;
    for (i = 0; i < 4 && e->k[i]; i++) if (strcmp(e->k[i], name) == 0) return e->v[i];
    return NULL;
}

#define OK200(body) "HTTP/1.1 200 OK\r\nContent-Length: " #body "\r\n\r\n"

void suite_engine_mock(void) {
    zu_get_opts o;
    zu_result r;
    zu_error e;
    dialer d;
    zu_code rc;

    ZU_CASE("engine: a GET is built, sent and parsed; Host carries a non-default port");
    {
        conn_script s[] = {{ "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello", 0, 0, 0, NULL }};
        dialer_init(&d, s, 1); opts_for(&o, &d);
        rc = zu_engine_get(&r, "http://example.test:8080/p?q=1", &o, &e);
        ZU_CHECK_EQ_INT(rc, ZU_OK);
        ZU_CHECK_EQ_INT(r.status, 200);
        ZU_CHECK(r.body.len == 5 && memcmp(r.body.data, "hello", 5) == 0);
        ZU_CHECK(strcmp(d.host[0], "example.test") == 0 && d.port[0] == 8080);
        ZU_CHECK(has(sent(&d, 0), "GET /p?q=1 HTTP/1.1\r\n"));
        ZU_CHECK(has(sent(&d, 0), "Host: example.test:8080\r\n"));
        ZU_CHECK(d.exhausted[0]);
        zu_result_free(&r); dialer_free(&d);
    }

    ZU_CASE("engine: the same exchange with a server that delivers one byte per read");
    {
        conn_script s[] = {{ "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                             "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n", 0, 1, 0, NULL }};
        dialer_init(&d, s, 1); opts_for(&o, &d);
        rc = zu_engine_get(&r, "http://example.test/", &o, &e);
        ZU_CHECK_EQ_INT(rc, ZU_OK);
        ZU_CHECK(r.body.len == 11 && memcmp(r.body.data, "hello world", 11) == 0);
        ZU_CHECK(has(sent(&d, 0), "Host: example.test\r\n"));   /* default port: no ":80" */
        zu_result_free(&r); dialer_free(&d);
    }

    ZU_CASE("engine: a cross-origin redirect drops credentials, keeps other headers (§19.2)");
    {
        static const char *hn[] = { "Authorization", "Cookie", "X-Keep" };
        static const char *hv[] = { "Bearer s3cret", "sid=1", "yes" };
        zu_req_spec spec;
        conn_script s[] = {
            { "HTTP/1.1 302 Found\r\nLocation: http://other.test/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0, 0, 0, NULL },
            { "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok", 0, 0, 0, NULL } };
        memset(&spec, 0, sizeof spec);
        spec.header_names = hn; spec.header_values = hv; spec.n_headers = 3;
        dialer_init(&d, s, 2); opts_for(&o, &d);
        rc = zu_engine_perform(&r, "http://example.test/start", &spec, &o, &e);
        ZU_CHECK_EQ_INT(rc, ZU_OK);
        ZU_CHECK_EQ_INT(r.redirects, 1);
        ZU_CHECK(has(sent(&d, 0), "Authorization: Bearer s3cret"));
        ZU_CHECK(!has(sent(&d, 1), "Authorization"));
        ZU_CHECK(!has(sent(&d, 1), "Cookie"));
        ZU_CHECK(has(sent(&d, 1), "X-Keep: yes"));
        ZU_CHECK(strcmp(d.host[1], "other.test") == 0);
        zu_result_free(&r); dialer_free(&d);
    }

    ZU_CASE("engine: a same-origin redirect on a pooled connection reuses it and keeps credentials");
    {
        static const char *hn[] = { "Authorization" };
        static const char *hv[] = { "Bearer s3cret" };
        zu_req_spec spec;
        zu_pool *pool = zu_pool_new(NULL);
        zu_pool_stats st;
        conn_script s[] = {{ "HTTP/1.1 301 Moved\r\nLocation: /new\r\nContent-Length: 3\r\n\r\nold",
                             0, 0, 1, OK200(3) "new" }};
        memset(&spec, 0, sizeof spec);
        spec.header_names = hn; spec.header_values = hv; spec.n_headers = 1;
        dialer_init(&d, s, 1); opts_for(&o, &d); o.pool = pool;
        rc = zu_engine_perform(&r, "http://example.test/old", &spec, &o, &e);
        ZU_CHECK_EQ_INT(rc, ZU_OK);
        ZU_CHECK(r.body.len == 3 && memcmp(r.body.data, "new", 3) == 0);
        ZU_CHECK_EQ_INT(d.next, 1);                          /* one connection, two hops */
        ZU_CHECK(has(sent(&d, 0), "GET /new HTTP/1.1\r\n"));
        {   /* the Authorization header was sent on BOTH hops of the one connection */
            const char *all = sent(&d, 0);
            const char *second = strstr(all, "GET /new");
            ZU_CHECK(second && strstr(second, "Authorization: Bearer s3cret"));
        }
        zu_pool_stats_get(pool, &st);
        ZU_CHECK_EQ_INT(st.hits, 1);
        zu_result_free(&r); dialer_free(&d); zu_pool_free(pool);
    }

    ZU_CASE("engine: an exhausted redirect chain raises; max 0 returns the 3xx (§19.4)");
    {
        conn_script s[] = {
            { "HTTP/1.1 302 Found\r\nLocation: /a\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0, 0, 0, NULL },
            { "HTTP/1.1 302 Found\r\nLocation: /b\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0, 0, 0, NULL },
            { "HTTP/1.1 302 Found\r\nLocation: /c\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0, 0, 0, NULL } };
        dialer_init(&d, s, 3); opts_for(&o, &d); o.max_redirects = 2;
        rc = zu_engine_get(&r, "http://example.test/", &o, &e);
        ZU_CHECK_EQ_INT(rc, ZU_ERR_TOO_MANY_REDIRECTS);
        dialer_free(&d);

        dialer_init(&d, s, 1); opts_for(&o, &d); o.max_redirects = 0;
        rc = zu_engine_get(&r, "http://example.test/", &o, &e);
        ZU_CHECK_EQ_INT(rc, ZU_OK);
        ZU_CHECK_EQ_INT(r.status, 302);
        zu_result_free(&r); dialer_free(&d);
    }

    ZU_CASE("engine: 303 turns POST into a bodiless GET; 307 resends method and body (§19.1)");
    {
        zu_req_spec spec;
        conn_script s303[] = {
            { "HTTP/1.1 303 See Other\r\nLocation: /done\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0, 0, 0, NULL },
            { "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0, 0, 0, NULL } };
        conn_script s307[] = {
            { "HTTP/1.1 307 Temporary Redirect\r\nLocation: /again\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0, 0, 0, NULL },
            { "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0, 0, 0, NULL } };
        memset(&spec, 0, sizeof spec);
        spec.method = "POST"; spec.body = "payload"; spec.body_len = 7;

        dialer_init(&d, s303, 2); opts_for(&o, &d);
        rc = zu_engine_perform(&r, "http://example.test/submit", &spec, &o, &e);
        ZU_CHECK_EQ_INT(rc, ZU_OK);
        ZU_CHECK(has(sent(&d, 0), "POST /submit") && has(sent(&d, 0), "payload"));
        ZU_CHECK(has(sent(&d, 1), "GET /done") && !has(sent(&d, 1), "payload"));
        ZU_CHECK(!has(sent(&d, 1), "Content-Length: 7"));
        zu_result_free(&r); dialer_free(&d);

        dialer_init(&d, s307, 2); opts_for(&o, &d);
        rc = zu_engine_perform(&r, "http://example.test/submit", &spec, &o, &e);
        ZU_CHECK_EQ_INT(rc, ZU_OK);
        ZU_CHECK(has(sent(&d, 1), "POST /again") && has(sent(&d, 1), "payload"));
        zu_result_free(&r); dialer_free(&d);
    }

    ZU_CASE("engine: 1xx responses are skipped; HEAD and 204 have no body and stay poolable");
    {
        zu_pool *pool = zu_pool_new(NULL);
        zu_req_spec head;
        zu_pool_stats st;
        conn_script s1[] = {{ "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n"
                              "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok", 0, 0, 0, NULL }};
        conn_script s2[] = {{ "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n",
                              0, 0, 1, "HTTP/1.1 204 No Content\r\n\r\n" }};
        dialer_init(&d, s1, 1); opts_for(&o, &d);
        rc = zu_engine_get(&r, "http://example.test/", &o, &e);
        ZU_CHECK_EQ_INT(rc, ZU_OK);
        ZU_CHECK_EQ_INT(r.status, 200);
        ZU_CHECK(zu_headers_get(&r.headers, "Link") == NULL);
        zu_result_free(&r); dialer_free(&d);

        memset(&head, 0, sizeof head); head.method = "HEAD";
        dialer_init(&d, s2, 1); opts_for(&o, &d); o.pool = pool;
        rc = zu_engine_perform(&r, "http://example.test/", &head, &o, &e);
        ZU_CHECK_EQ_INT(rc, ZU_OK);
        ZU_CHECK_EQ_INT(r.body.len, 0);          /* Content-Length: 100 read nothing */
        zu_result_free(&r);
        rc = zu_engine_get(&r, "http://example.test/", &o, &e);
        ZU_CHECK_EQ_INT(rc, ZU_OK);
        ZU_CHECK_EQ_INT(r.status, 204);
        ZU_CHECK_EQ_INT(d.next, 1);              /* the 204 came on the pooled connection */
        zu_pool_stats_get(pool, &st);
        ZU_CHECK_EQ_INT(st.hits, 1);
        zu_result_free(&r); dialer_free(&d); zu_pool_free(pool);
    }

    ZU_CASE("engine: gzip is decoded; no_decode returns the wire bytes (§21)");
    {
        unsigned char plain[2000], gz[2000];
        char resp[4096];
        z_stream zs;
        size_t i, gzlen, hl;
        for (i = 0; i < sizeof plain; i++) plain[i] = (unsigned char)('a' + i % 26);
        memset(&zs, 0, sizeof zs);
        deflateInit2(&zs, Z_BEST_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
        zs.next_in = plain; zs.avail_in = (uInt)sizeof plain;
        zs.next_out = gz; zs.avail_out = (uInt)sizeof gz;
        deflate(&zs, Z_FINISH);
        gzlen = sizeof gz - zs.avail_out;
        deflateEnd(&zs);
        hl = (size_t)snprintf(resp, sizeof resp,
                              "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %lu\r\n"
                              "Connection: close\r\n\r\n", (unsigned long)gzlen);
        memcpy(resp + hl, gz, gzlen);
        {
            conn_script s[] = {{ resp, hl + gzlen, 7, 0, NULL }};   /* odd read size, too */
            dialer_init(&d, s, 1); opts_for(&o, &d);
            rc = zu_engine_get(&r, "http://example.test/", &o, &e);
            ZU_CHECK_EQ_INT(rc, ZU_OK);
            ZU_CHECK(r.body.len == sizeof plain && memcmp(r.body.data, plain, sizeof plain) == 0);
            ZU_CHECK_EQ_INT(r.timings.body_bytes_wire, gzlen);
            zu_result_free(&r); dialer_free(&d);

            dialer_init(&d, s, 1); opts_for(&o, &d); o.no_decode = 1;
            rc = zu_engine_get(&r, "http://example.test/", &o, &e);
            ZU_CHECK_EQ_INT(rc, ZU_OK);
            ZU_CHECK(r.body.len == gzlen && memcmp(r.body.data, gz, gzlen) == 0);
            ZU_CHECK(has(sent(&d, 0), "Accept-Encoding: identity"));
            zu_result_free(&r); dialer_free(&d);
        }
    }

    ZU_CASE("engine: truncated bodies are errors, and over-limit bodies are refused");
    {
        conn_script cl[] = {{ "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n01234", 0, 0, 0, NULL }};
        conn_script ch[] = {{ "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel", 0, 0, 0, NULL }};
        conn_script big[] = {{ "HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n01234567890123456789", 0, 0, 0, NULL }};
        dialer_init(&d, cl, 1); opts_for(&o, &d);
        ZU_CHECK_EQ_INT(zu_engine_get(&r, "http://example.test/", &o, &e), ZU_ERR_PARSE);
        dialer_free(&d);
        dialer_init(&d, ch, 1); opts_for(&o, &d);
        ZU_CHECK_EQ_INT(zu_engine_get(&r, "http://example.test/", &o, &e), ZU_ERR_PARSE);
        dialer_free(&d);
        dialer_init(&d, big, 1); opts_for(&o, &d); o.max_body = 10;
        ZU_CHECK_EQ_INT(zu_engine_get(&r, "http://example.test/", &o, &e), ZU_ERR_BODY_LIMIT);
        dialer_free(&d);
    }

    ZU_CASE("engine: redirect bodies never reach the caller's sink (§19.5)");
    {
        zu_buffer out;
        zu_sink *sink;
        conn_script s[] = {
            { "HTTP/1.1 302 Found\r\nLocation: /f\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNOT-THIS!", 0, 0, 0, NULL },
            { "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nthis", 0, 0, 0, NULL } };
        zu_buf_init(&out, 64, 1 << 16);
        sink = zu_sink_memory(&out);
        dialer_init(&d, s, 2); opts_for(&o, &d); o.sink = sink;
        rc = zu_engine_get(&r, "http://example.test/", &o, &e);
        ZU_CHECK_EQ_INT(rc, ZU_OK);
        ZU_CHECK(out.len == 4 && memcmp(out.data, "this", 4) == 0);
        zu_result_free(&r); dialer_free(&d);
        zu_sink_free(sink); zu_buf_free(&out);
    }

    ZU_CASE("engine: a stale pooled connection is discarded and a new one dialled (§26.2)");
    {
        zu_pool *pool = zu_pool_new(NULL);
        zu_pool_stats st;
        /* The first connection answers once and then reads as readable: the
         * peer closed it while it sat in the pool. */
        conn_script s[] = {
            { OK200(1) "a", 0, 0, 0, NULL },
            { OK200(1) "b", 0, 0, 1, NULL } };
        dialer_init(&d, s, 2); opts_for(&o, &d); o.pool = pool;
        ZU_CHECK_EQ_INT(zu_engine_get(&r, "http://example.test/", &o, &e), ZU_OK);
        zu_result_free(&r);
        ZU_CHECK_EQ_INT(zu_engine_get(&r, "http://example.test/", &o, &e), ZU_OK);
        ZU_CHECK(r.body.len == 1 && r.body.data[0] == 'b');
        ZU_CHECK_EQ_INT(d.next, 2);
        zu_pool_stats_get(pool, &st);
        ZU_CHECK_EQ_INT(st.discarded_stale, 1);
        zu_result_free(&r); dialer_free(&d); zu_pool_free(pool);
    }

    ZU_CASE("engine: plain HTTP through a proxy uses absolute-form and Proxy-Authorization (§20)");
    {
        zu_env env;
        envtab tab = {{ "http_proxy", "no_proxy", NULL }, { "http://u:p@proxy.test:3128", "direct.test", NULL }};
        conn_script s[] = {
            { "HTTP/1.1 302 Found\r\nLocation: http://direct.test/x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0, 0, 0, NULL },
            { "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0, 0, 0, NULL } };
        env.get = env_get; env.ctx = &tab;
        dialer_init(&d, s, 2); opts_for(&o, &d);
        o.proxy_set = 0; o.env = &env;
        rc = zu_engine_get(&r, "http://example.test/start", &o, &e);
        ZU_CHECK_EQ_INT(rc, ZU_OK);
        ZU_CHECK(strcmp(d.host[0], "proxy.test") == 0 && d.port[0] == 3128);
        ZU_CHECK(has(sent(&d, 0), "GET http://example.test/start HTTP/1.1\r\n"));
        ZU_CHECK(has(sent(&d, 0), "Proxy-Authorization: Basic dTpw\r\n"));
        /* The redirect lands on a NO_PROXY host: direct, and no proxy credential. */
        ZU_CHECK(strcmp(d.host[1], "direct.test") == 0 && d.port[1] == 80);
        ZU_CHECK(has(sent(&d, 1), "GET /x HTTP/1.1\r\n"));
        ZU_CHECK(!has(sent(&d, 1), "Proxy-Authorization"));
        zu_result_free(&r); dialer_free(&d);
    }

    ZU_CASE("engine: CONNECT outcomes for HTTPS through a proxy (§20.3)");
    {
        conn_script s407[] = {{ "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n", 0, 0, 0, NULL }};
        conn_script s502[] = {{ "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n", 0, 0, 0, NULL }};
        conn_script junk[] = {{ "HTTP/1.1 200 Connection Established\r\n\r\n\x16\x03\x01", 0, 0, 0, NULL }};
        conn_script ok[]   = {{ "HTTP/1.1 200 Connection Established\r\n\r\n", 0, 0, 0, NULL }};
        dialer_init(&d, s407, 1); opts_for(&o, &d); o.proxy = "http://proxy.test:3128";
        ZU_CHECK_EQ_INT(zu_engine_get(&r, "https://example.test/", &o, &e), ZU_ERR_PROXY_AUTH);
        ZU_CHECK(has(sent(&d, 0), "CONNECT example.test:443 HTTP/1.1\r\n"));
        dialer_free(&d);
        dialer_init(&d, s502, 1); opts_for(&o, &d); o.proxy = "http://proxy.test:3128";
        ZU_CHECK_EQ_INT(zu_engine_get(&r, "https://example.test/", &o, &e), ZU_ERR_PROXY);
        dialer_free(&d);
        /* Bytes after the CONNECT response are origin TLS data the proxy had
         * no business sending: refused rather than spliced into a handshake. */
        dialer_init(&d, junk, 1); opts_for(&o, &d); o.proxy = "http://proxy.test:3128";
        ZU_CHECK_EQ_INT(zu_engine_get(&r, "https://example.test/", &o, &e), ZU_ERR_PROXY);
        dialer_free(&d);
        /* A clean tunnel reaches TLS, which this build does not have. */
        dialer_init(&d, ok, 1); opts_for(&o, &d); o.proxy = "http://proxy.test:3128";
        ZU_CHECK_EQ_INT(zu_engine_get(&r, "https://example.test/", &o, &e), ZU_ERR_TLS);
        dialer_free(&d);
    }

    ZU_CASE("engine: bytes past a response's framing keep its connection out of the pool (§26.3)");
    {
        /* Content-Length says 2 and the server sends 2 plus a whole second
         * response nobody asked for. The body is right; the connection is
         * not reusable, because whatever it says next is out of step. The
         * probe is forced to "idle" so it is the surplus rule, not §26.2's
         * liveness probe, that has to refuse the reuse. */
        const char *cases[3] = {
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nevil",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\nHTTP/1.1 200 OK\r\n\r\n",
            "HTTP/1.1 204 No Content\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nevil" };
        int k;
        for (k = 0; k < 3; k++) {
            zu_pool *pool = zu_pool_new(NULL);
            zu_pool_stats st;
            conn_script s[] = { { cases[k], 0, 0, 1, NULL }, { OK200(2) "ok", 0, 0, 1, NULL } };
            dialer_init(&d, s, 2); opts_for(&o, &d); o.pool = pool;
            ZU_CHECK_EQ_INT(zu_engine_get(&r, "http://example.test/", &o, &e), ZU_OK);
            ZU_CHECK(k == 2 || (r.body.len == 2 && memcmp(r.body.data, "ok", 2) == 0));
            zu_result_free(&r);
            ZU_CHECK_EQ_INT(zu_engine_get(&r, "http://example.test/", &o, &e), ZU_OK);
            ZU_CHECK(r.body.len == 2 && memcmp(r.body.data, "ok", 2) == 0);   /* never "evil" */
            ZU_CHECK_EQ_INT(d.next, 2);
            zu_pool_stats_get(pool, &st);
            ZU_CHECK_EQ_INT(st.hits, 0);
            zu_result_free(&r); dialer_free(&d); zu_pool_free(pool);
        }
    }

    ZU_CASE("engine: a connection failure is the dialer's error, and nothing is sent");
    {
        dialer_init(&d, NULL, 0); opts_for(&o, &d);
        ZU_CHECK_EQ_INT(zu_engine_get(&r, "http://example.test/", &o, &e), ZU_ERR_CONNECT);
        ZU_CHECK_EQ_INT(d.sent[0].len, 0);
        dialer_free(&d);
    }
}

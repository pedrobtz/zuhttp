/* The whole engine, offline, through the §50.1 dial seam.
 *
 * zuh_engine_perform() runs for real — proxy routing, the pool, the CONNECT
 * tunnel, request building, framing, redirects, decoding and sinks — while
 * every connection it opens is a scripted mock. Until 2026-09-26 zuh_engine.c
 * was not compiled into this suite at all, and the redirect credential leak
 * fixed then lived in exactly the code this file now drives.
 *
 * Each connection is wrapped in a "tap" that records what the engine wrote
 * and whether the script was consumed, into the dialer, so both survive the
 * engine freeing the stream. The harness's allocation check at the end of
 * main() then catches anything the engine leaked on any path below. */
#include "zuh_test.h"
#include "zuh_engine.h"
#include "zuh_mock_stream.h"
#include "zuh_pool.h"
#include "zuh_alloc.h"
#include "zuh_sink.h"
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
    zuh_buffer sent[MAXC];
    int      exhausted[MAXC];
    zuh_mock_step steps[MAXC][2];   /* the mock keeps a pointer to these */
} dialer;

typedef struct { zuh_stream *inner; dialer *d; size_t idx; } tap_impl;

static zuh_ssize tap_read(zuh_stream *s, void *b, size_t n, zuh_deadline dl, zuh_error *e) {
    return zuh_stream_read(((tap_impl *)s->impl)->inner, b, n, dl, e);
}
static zuh_ssize tap_write(zuh_stream *s, const void *b, size_t n, zuh_deadline dl, zuh_error *e) {
    tap_impl *t = (tap_impl *)s->impl;
    zuh_ssize w = zuh_stream_write(t->inner, b, n, dl, e);
    if (w > 0) zuh_buf_append(&t->d->sent[t->idx], b, (size_t)w);
    return w;
}
static void tap_close(zuh_stream *s) { zuh_stream_close(((tap_impl *)s->impl)->inner); }
static int tap_readable(zuh_stream *s, int ms) {
    return zuh_stream_readable(((tap_impl *)s->impl)->inner, ms);
}
static void tap_destroy(zuh_stream *s) {
    tap_impl *t = (tap_impl *)s->impl;
    t->d->exhausted[t->idx] = zuh_mock_stream_exhausted(t->inner);
    zuh_mock_stream_free(t->inner);
    zuh_free(t);
    zuh_free(s);
}
static const zuh_stream_vtable k_tap_vt = {
    "tap", tap_read, tap_write, tap_close, tap_destroy, tap_readable
};

static zuh_code dial(void *ctx, const char *host, uint16_t port,
                    zuh_stream **out, zuh_error *err) {
    dialer *d = (dialer *)ctx;
    const conn_script *c;
    tap_impl *t;
    zuh_stream *s;
    size_t i = d->next;
    if (i >= d->n || i >= MAXC) {
        zuh_error_set(err, ZUH_ERR_CONNECT, ZUH_PHASE_CONNECT, "no scripted connection left");
        return ZUH_ERR_CONNECT;
    }
    c = &d->scripts[i];
    d->next++;
    snprintf(d->host[i], sizeof d->host[i], "%s", host);
    d->port[i] = port;
    t = (tap_impl *)zuh_calloc(1, sizeof *t);
    s = (zuh_stream *)zuh_calloc(1, sizeof *s);
    /* The allocation-failure sweep below fails these too. */
    if (!t || !s) {
        zuh_free(t); zuh_free(s);
        zuh_error_set(err, ZUH_ERR_NOMEM, ZUH_PHASE_CONNECT, "out of memory");
        return ZUH_ERR_NOMEM;
    }
    d->steps[i][0].kind = ZUH_MOCK_DATA;
    d->steps[i][0].data = c->bytes;
    d->steps[i][0].len  = c->len ? c->len : strlen(c->bytes);
    d->steps[i][1].kind = ZUH_MOCK_DATA;
    d->steps[i][1].data = c->next;
    d->steps[i][1].len  = c->next ? strlen(c->next) : 0;
    t->inner = zuh_mock_stream_new(d->steps[i], c->next ? 2 : 1, c->max_read, 0);
    if (!t->inner) {
        zuh_free(t); zuh_free(s);
        zuh_error_set(err, ZUH_ERR_NOMEM, ZUH_PHASE_CONNECT, "out of memory");
        return ZUH_ERR_NOMEM;
    }
    if (c->not_readable) zuh_mock_stream_set_readable(t->inner, 1, 0);
    t->d = d; t->idx = i;
    s->vt = &k_tap_vt; s->impl = t;
    *out = s;
    return ZUH_OK;
}

static void dialer_init(dialer *d, const conn_script *s, size_t n) {
    size_t i;
    memset(d, 0, sizeof *d);
    d->scripts = s; d->n = n;
    for (i = 0; i < MAXC; i++) zuh_buf_init(&d->sent[i], 256, 1 << 20);
}
static void dialer_free(dialer *d) {
    size_t i;
    for (i = 0; i < MAXC; i++) zuh_buf_free(&d->sent[i]);
}
/* What connection i was sent, as a C string (the buffer is ours). */
static const char *sent(dialer *d, size_t i) {
    const char *s = "";
    zuh_buf_cstr(&d->sent[i], &s);
    return s;
}
static int has(const char *hay, const char *needle) { return strstr(hay, needle) != NULL; }

static void opts_for(zuh_get_opts *o, dialer *d) {
    zuh_get_opts_init(o);
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

/* zlib-compress `n` bytes: `window` 31 for gzip, 15 for the zlib wrapper. */
static size_t squeeze(const void *in, size_t n, int window, unsigned char *out, size_t cap) {
    z_stream zs;
    size_t len;
    memset(&zs, 0, sizeof zs);
    deflateInit2(&zs, Z_BEST_COMPRESSION, Z_DEFLATED, window, 8, Z_DEFAULT_STRATEGY);
    zs.next_in = (Bytef *)(uintptr_t)in; zs.avail_in = (uInt)n;
    zs.next_out = out; zs.avail_out = (uInt)cap;
    deflate(&zs, Z_FINISH);
    len = cap - zs.avail_out;
    deflateEnd(&zs);
    return len;
}

/* A 200 carrying `body` under `coding`, framed three ways (§18.1): 0 by
 * Content-Length, 1 chunked (in two chunks, so a boundary falls inside the
 * compressed stream), 2 until close. Returns the response's length. */
static size_t framed(char *out, size_t cap, int how, const char *coding,
                     const unsigned char *body, size_t n) {
    size_t h, half = n / 2;
    if (how == 0) {
        h = (size_t)snprintf(out, cap, "HTTP/1.1 200 OK\r\nContent-Encoding: %s\r\n"
                             "Content-Length: %lu\r\nConnection: close\r\n\r\n",
                             coding, (unsigned long)n);
        memcpy(out + h, body, n);
        return h + n;
    }
    if (how == 1) {
        h = (size_t)snprintf(out, cap, "HTTP/1.1 200 OK\r\nContent-Encoding: %s\r\n"
                             "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n", coding);
        h += (size_t)snprintf(out + h, cap - h, "%lx\r\n", (unsigned long)half);
        memcpy(out + h, body, half); h += half;
        h += (size_t)snprintf(out + h, cap - h, "\r\n%lx\r\n", (unsigned long)(n - half));
        memcpy(out + h, body + half, n - half); h += n - half;
        h += (size_t)snprintf(out + h, cap - h, "\r\n0\r\n\r\n");
        return h;
    }
    h = (size_t)snprintf(out, cap, "HTTP/1.1 200 OK\r\nContent-Encoding: %s\r\n"
                         "Connection: close\r\n\r\n", coding);
    memcpy(out + h, body, n);
    return h + n;
}

void suite_engine_mock(void) {
    zuh_get_opts o;
    zuh_result r;
    zuh_error e;
    dialer d;
    zuh_code rc;

    ZUH_CASE("engine: a GET is built, sent and parsed; Host carries a non-default port");
    {
        conn_script s[] = {{ "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello", 0, 0, 0, NULL }};
        dialer_init(&d, s, 1); opts_for(&o, &d);
        rc = zuh_engine_get(&r, "http://example.test:8080/p?q=1", &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        ZUH_CHECK_EQ_INT(r.status, 200);
        ZUH_CHECK(r.body.len == 5 && memcmp(r.body.data, "hello", 5) == 0);
        ZUH_CHECK(strcmp(d.host[0], "example.test") == 0 && d.port[0] == 8080);
        ZUH_CHECK(has(sent(&d, 0), "GET /p?q=1 HTTP/1.1\r\n"));
        ZUH_CHECK(has(sent(&d, 0), "Host: example.test:8080\r\n"));
        ZUH_CHECK(d.exhausted[0]);
        zuh_result_free(&r); dialer_free(&d);
    }

    ZUH_CASE("engine: the same exchange with a server that delivers one byte per read");
    {
        conn_script s[] = {{ "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                             "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n", 0, 1, 0, NULL }};
        dialer_init(&d, s, 1); opts_for(&o, &d);
        rc = zuh_engine_get(&r, "http://example.test/", &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        ZUH_CHECK(r.body.len == 11 && memcmp(r.body.data, "hello world", 11) == 0);
        ZUH_CHECK(has(sent(&d, 0), "Host: example.test\r\n"));   /* default port: no ":80" */
        zuh_result_free(&r); dialer_free(&d);
    }

    ZUH_CASE("engine: the body decides a request's framing, not the caller's headers (RFC 9112 §6.2)");
    {
        /* A caller Content-Length of 1 on a five-byte body went out as
         * written, followed by all five bytes; a caller Transfer-Encoding
         * went out beside the generated Content-Length over an unchunked
         * body. Either leaves the connection out of step with the server.
         * Both are refused before connecting; a matching Content-Length is
         * accepted and sent once. */
        static const char *te_n[] = { "Transfer-Encoding" }, *te_v[] = { "chunked" };
        static const char *bad_n[] = { "Content-Length" },   *bad_v[] = { "1" };
        static const char *ok_n[] = { "content-length", "Content-Length" };
        static const char *ok_v[] = { " 5 ", "5" };
        zuh_req_spec spec;
        memset(&spec, 0, sizeof spec);
        spec.method = "POST"; spec.body = "hello"; spec.body_len = 5;

        spec.header_names = bad_n; spec.header_values = bad_v; spec.n_headers = 1;
        dialer_init(&d, NULL, 0); opts_for(&o, &d); zuh_error_clear(&e);
        ZUH_CHECK_EQ_INT(zuh_engine_perform(&r, "http://example.test/", &spec, &o, &e), ZUH_ERR_PARSE);
        ZUH_CHECK_EQ_INT(e.code, ZUH_ERR_PARSE);
        ZUH_CHECK_EQ_INT(d.next, 0);
        dialer_free(&d);

        spec.header_names = te_n; spec.header_values = te_v;
        dialer_init(&d, NULL, 0); opts_for(&o, &d); zuh_error_clear(&e);
        ZUH_CHECK_EQ_INT(zuh_engine_perform(&r, "http://example.test/", &spec, &o, &e), ZUH_ERR_PARSE);
        ZUH_CHECK_EQ_INT(e.code, ZUH_ERR_PARSE);
        ZUH_CHECK_EQ_INT(d.next, 0);
        dialer_free(&d);

        /* Matching, twice and with whitespace: one Content-Length on the
         * wire. Then a 303 turns the POST into a GET and drops the body, and
         * the caller's length must not follow it. */
        {
            conn_script sc[] = {
                { "HTTP/1.1 303 See Other\r\nLocation: /done\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0, 0, 0, NULL },
                { OK200(2) "ok", 0, 0, 0, NULL } };
            const char *w0, *first;
            spec.header_names = ok_n; spec.header_values = ok_v; spec.n_headers = 2;
            dialer_init(&d, sc, 2); opts_for(&o, &d);
            rc = zuh_engine_perform(&r, "http://example.test/", &spec, &o, &e);
            ZUH_CHECK_EQ_INT(rc, ZUH_OK);
            w0 = sent(&d, 0);
            first = strstr(w0, "ontent-Length");
            ZUH_CHECK(first != NULL && strstr(first + 1, "ontent-Length") == NULL);
            ZUH_CHECK(has(w0, "Content-Length: 5\r\n") && has(w0, "\r\n\r\nhello"));
            ZUH_CHECK(has(sent(&d, 1), "GET /done HTTP/1.1\r\n"));
            ZUH_CHECK(!has(sent(&d, 1), "ontent-Length"));
            if (rc == ZUH_OK) zuh_result_free(&r);
            dialer_free(&d);
        }
    }

    ZUH_CASE("engine: a cross-origin redirect drops credentials, keeps other headers (§19.2)");
    {
        static const char *hn[] = { "Authorization", "Cookie", "X-Keep" };
        static const char *hv[] = { "Bearer s3cret", "sid=1", "yes" };
        zuh_req_spec spec;
        conn_script s[] = {
            { "HTTP/1.1 302 Found\r\nLocation: http://other.test/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0, 0, 0, NULL },
            { "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok", 0, 0, 0, NULL } };
        memset(&spec, 0, sizeof spec);
        spec.header_names = hn; spec.header_values = hv; spec.n_headers = 3;
        dialer_init(&d, s, 2); opts_for(&o, &d);
        rc = zuh_engine_perform(&r, "http://example.test/start", &spec, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        ZUH_CHECK_EQ_INT(r.redirects, 1);
        ZUH_CHECK(has(sent(&d, 0), "Authorization: Bearer s3cret"));
        ZUH_CHECK(!has(sent(&d, 1), "Authorization"));
        ZUH_CHECK(!has(sent(&d, 1), "Cookie"));
        ZUH_CHECK(has(sent(&d, 1), "X-Keep: yes"));
        ZUH_CHECK(strcmp(d.host[1], "other.test") == 0);
        zuh_result_free(&r); dialer_free(&d);
    }

    ZUH_CASE("engine: a cross-origin redirect drops every header §42 calls secret, configured ones too (§19.2)");
    {
        /* The filter knew three names; the redactor knows six and whatever
         * the caller configures. X-API-Key and X-Auth-Token followed a 302
         * to another port. One list now decides both. */
        static const char *hn[] = { "X-API-Key", "x-auth-token", "Set-Cookie", "X-Tenant-Secret", "X-Keep" };
        static const char *hv[] = { "k", "t", "c", "s", "yes" };
        static const char *const extra[] = { "X-Tenant-Secret", NULL };
        zuh_redact_policy pol;
        zuh_req_spec spec;
        int k;
        const char *targets[3] = { "http://example.test:8080/next",   /* port */
                                   "http://other.test/next",          /* host */
                                   "https://example.test/next" };     /* scheme */
        for (k = 0; k < 3; k++) {
            char loc[200];
            conn_script sc[2];
            snprintf(loc, sizeof loc, "HTTP/1.1 302 Found\r\nLocation: %s\r\n"
                     "Content-Length: 0\r\nConnection: close\r\n\r\n", targets[k]);
            sc[0].bytes = loc; sc[0].len = 0; sc[0].max_read = 0; sc[0].not_readable = 0; sc[0].next = NULL;
            sc[1].bytes = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            sc[1].len = 0; sc[1].max_read = 0; sc[1].not_readable = 0; sc[1].next = NULL;
            zuh_redact_policy_init(&pol); pol.extra_headers = extra;
            memset(&spec, 0, sizeof spec);
            spec.header_names = hn; spec.header_values = hv; spec.n_headers = 5;
            dialer_init(&d, sc, 2); opts_for(&o, &d); o.redact = &pol;
            rc = zuh_engine_perform(&r, "http://example.test/start", &spec, &o, &e);
            /* https has no TLS in this build; what matters is what was sent. */
            ZUH_CHECK(has(sent(&d, 0), "X-API-Key: k") && has(sent(&d, 0), "X-Tenant-Secret: s"));
            if (k < 2) {
                ZUH_CHECK_EQ_INT(rc, ZUH_OK);
                ZUH_CHECK(!has(sent(&d, 1), "X-API-Key") && !has(sent(&d, 1), "x-auth-token"));
                ZUH_CHECK(!has(sent(&d, 1), "Set-Cookie") && !has(sent(&d, 1), "X-Tenant-Secret"));
                ZUH_CHECK(has(sent(&d, 1), "X-Keep: yes"));
            }
            if (rc == ZUH_OK) zuh_result_free(&r);
            dialer_free(&d);
        }
    }

    ZUH_CASE("engine: two proxies that differ only past 512 bytes of credentials never share a connection (§26.1)");
    {
        /* The pool key's proxy identity was formatted into 512 bytes and the
         * truncation ignored, so a 510-byte username left host, port and
         * password out of it: a request meant for proxy B reused A's
         * connection. And ':' / '@' inside decoded credentials made two
         * different identities spell the same key. */
        static char a[700], b2[700], c1[700], c2[700];
        static char user[520];
        zuh_pool *pool = zuh_pool_new(NULL);
        zuh_pool_stats st;
        conn_script sc[] = { { OK200(1) "A", 0, 0, 1, NULL }, { OK200(1) "B", 0, 0, 1, NULL },
                             { OK200(1) "C", 0, 0, 1, NULL }, { OK200(1) "D", 0, 0, 1, NULL } };
        memset(user, 'u', 510); user[510] = '\0';
        snprintf(a,  sizeof a,  "http://%s:pa@proxy-a.test:3128", user);
        snprintf(b2, sizeof b2, "http://%s:pb@proxy-b.test:3129", user);
        /* Decoded, user "a:b" password "c" and user "a" password "b:c" both
         * joined as "a:b:c" in the old key. */
        snprintf(c1, sizeof c1, "http://a%%3Ab:c@proxy-c.test:3128");
        snprintf(c2, sizeof c2, "http://a:b%%3Ac@proxy-c.test:3128");
        dialer_init(&d, sc, 4); opts_for(&o, &d); o.pool = pool;
        o.proxy = a;
        ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "http://origin.test/", &o, &e), ZUH_OK); zuh_result_free(&r);
        o.proxy = b2;
        ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "http://origin.test/", &o, &e), ZUH_OK);
        ZUH_CHECK(r.body.len == 1 && r.body.data[0] == 'B');
        zuh_result_free(&r);
        ZUH_CHECK(strcmp(d.host[1], "proxy-b.test") == 0);
        o.proxy = c1;
        ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "http://origin.test/", &o, &e), ZUH_OK); zuh_result_free(&r);
        o.proxy = c2;
        ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "http://origin.test/", &o, &e), ZUH_OK); zuh_result_free(&r);
        ZUH_CHECK_EQ_INT(d.next, 4);
        zuh_pool_stats_get(pool, &st);
        ZUH_CHECK_EQ_INT(st.hits, 0);
        dialer_free(&d); zuh_pool_free(pool);
    }

    ZUH_CASE("engine: a same-origin redirect on a pooled connection reuses it and keeps credentials");
    {
        static const char *hn[] = { "Authorization" };
        static const char *hv[] = { "Bearer s3cret" };
        zuh_req_spec spec;
        zuh_pool *pool = zuh_pool_new(NULL);
        zuh_pool_stats st;
        conn_script s[] = {{ "HTTP/1.1 301 Moved\r\nLocation: /new\r\nContent-Length: 3\r\n\r\nold",
                             0, 0, 1, OK200(3) "new" }};
        memset(&spec, 0, sizeof spec);
        spec.header_names = hn; spec.header_values = hv; spec.n_headers = 1;
        dialer_init(&d, s, 1); opts_for(&o, &d); o.pool = pool;
        rc = zuh_engine_perform(&r, "http://example.test/old", &spec, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        ZUH_CHECK(r.body.len == 3 && memcmp(r.body.data, "new", 3) == 0);
        ZUH_CHECK_EQ_INT(d.next, 1);                          /* one connection, two hops */
        ZUH_CHECK(has(sent(&d, 0), "GET /new HTTP/1.1\r\n"));
        {   /* the Authorization header was sent on BOTH hops of the one connection */
            const char *all = sent(&d, 0);
            const char *second = strstr(all, "GET /new");
            ZUH_CHECK(second && strstr(second, "Authorization: Bearer s3cret"));
        }
        zuh_pool_stats_get(pool, &st);
        ZUH_CHECK_EQ_INT(st.hits, 1);
        zuh_result_free(&r); dialer_free(&d); zuh_pool_free(pool);
    }

    ZUH_CASE("engine: an exhausted redirect chain raises; max 0 returns the 3xx (§19.4)");
    {
        conn_script s[] = {
            { "HTTP/1.1 302 Found\r\nLocation: /a\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0, 0, 0, NULL },
            { "HTTP/1.1 302 Found\r\nLocation: /b\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0, 0, 0, NULL },
            { "HTTP/1.1 302 Found\r\nLocation: /c\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0, 0, 0, NULL } };
        dialer_init(&d, s, 3); opts_for(&o, &d); o.max_redirects = 2;
        rc = zuh_engine_get(&r, "http://example.test/", &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_ERR_TOO_MANY_REDIRECTS);
        dialer_free(&d);

        dialer_init(&d, s, 1); opts_for(&o, &d); o.max_redirects = 0;
        rc = zuh_engine_get(&r, "http://example.test/", &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        ZUH_CHECK_EQ_INT(r.status, 302);
        zuh_result_free(&r); dialer_free(&d);
    }

    ZUH_CASE("engine: 303 turns POST into a bodiless GET; 307 resends method and body (§19.1)");
    {
        zuh_req_spec spec;
        conn_script s303[] = {
            { "HTTP/1.1 303 See Other\r\nLocation: /done\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0, 0, 0, NULL },
            { "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0, 0, 0, NULL } };
        conn_script s307[] = {
            { "HTTP/1.1 307 Temporary Redirect\r\nLocation: /again\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0, 0, 0, NULL },
            { "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0, 0, 0, NULL } };
        memset(&spec, 0, sizeof spec);
        spec.method = "POST"; spec.body = "payload"; spec.body_len = 7;

        dialer_init(&d, s303, 2); opts_for(&o, &d);
        rc = zuh_engine_perform(&r, "http://example.test/submit", &spec, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        ZUH_CHECK(has(sent(&d, 0), "POST /submit") && has(sent(&d, 0), "payload"));
        ZUH_CHECK(has(sent(&d, 1), "GET /done") && !has(sent(&d, 1), "payload"));
        ZUH_CHECK(!has(sent(&d, 1), "Content-Length: 7"));
        zuh_result_free(&r); dialer_free(&d);

        dialer_init(&d, s307, 2); opts_for(&o, &d);
        rc = zuh_engine_perform(&r, "http://example.test/submit", &spec, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        ZUH_CHECK(has(sent(&d, 1), "POST /again") && has(sent(&d, 1), "payload"));
        zuh_result_free(&r); dialer_free(&d);
    }

    ZUH_CASE("engine: 1xx responses are skipped; HEAD and 204 have no body and stay poolable");
    {
        zuh_pool *pool = zuh_pool_new(NULL);
        zuh_req_spec head;
        zuh_pool_stats st;
        conn_script s1[] = {{ "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n"
                              "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok", 0, 0, 0, NULL }};
        conn_script s2[] = {{ "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n",
                              0, 0, 1, "HTTP/1.1 204 No Content\r\n\r\n" }};
        dialer_init(&d, s1, 1); opts_for(&o, &d);
        rc = zuh_engine_get(&r, "http://example.test/", &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        ZUH_CHECK_EQ_INT(r.status, 200);
        ZUH_CHECK(zuh_headers_get(&r.headers, "Link") == NULL);
        zuh_result_free(&r); dialer_free(&d);

        memset(&head, 0, sizeof head); head.method = "HEAD";
        dialer_init(&d, s2, 1); opts_for(&o, &d); o.pool = pool;
        rc = zuh_engine_perform(&r, "http://example.test/", &head, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        ZUH_CHECK_EQ_INT(r.body.len, 0);          /* Content-Length: 100 read nothing */
        zuh_result_free(&r);
        rc = zuh_engine_get(&r, "http://example.test/", &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        ZUH_CHECK_EQ_INT(r.status, 204);
        ZUH_CHECK_EQ_INT(d.next, 1);              /* the 204 came on the pooled connection */
        zuh_pool_stats_get(pool, &st);
        ZUH_CHECK_EQ_INT(st.hits, 1);
        zuh_result_free(&r); dialer_free(&d); zuh_pool_free(pool);
    }

    ZUH_CASE("engine: gzip is decoded; no_decode returns the wire bytes (§21)");
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
            rc = zuh_engine_get(&r, "http://example.test/", &o, &e);
            ZUH_CHECK_EQ_INT(rc, ZUH_OK);
            ZUH_CHECK(r.body.len == sizeof plain && memcmp(r.body.data, plain, sizeof plain) == 0);
            ZUH_CHECK_EQ_INT(r.timings.body_bytes_wire, gzlen);
            zuh_result_free(&r); dialer_free(&d);

            dialer_init(&d, s, 1); opts_for(&o, &d); o.no_decode = 1;
            rc = zuh_engine_get(&r, "http://example.test/", &o, &e);
            ZUH_CHECK_EQ_INT(rc, ZUH_OK);
            ZUH_CHECK(r.body.len == gzlen && memcmp(r.body.data, gz, gzlen) == 0);
            ZUH_CHECK(has(sent(&d, 0), "Accept-Encoding: identity"));
            zuh_result_free(&r); dialer_free(&d);
        }
    }

    ZUH_CASE("engine: a compressed body succeeds only when its stream is complete (§21, D-76)");
    {
        /* Each variant under each framing, and once more one byte per read.
         * A byte limit is not an integrity check: before D-76 the first three
         * returned 200 with an empty, a trailer-less and a half body. */
        static unsigned char plain[10000], gz[12000], two[200], zl[200];
        static char resp[16000];
        size_t gzlen, twolen, zllen, i;
        int how, slow;
        struct { const unsigned char *b; size_t n; zuh_code want; const char *body; } v[5];
        for (i = 0; i < sizeof plain; i++) plain[i] = (unsigned char)("abcdefghij"[i % 10]);
        gzlen  = squeeze(plain, sizeof plain, 31, gz, sizeof gz);
        twolen = squeeze("hello", 5, 31, two, sizeof two);
        twolen += squeeze("world", 5, 31, two + twolen, sizeof two - twolen);
        zllen  = squeeze("hello", 5, 15, zl, sizeof zl - 1);
        zl[zllen++] = 'X';                                     /* after the stream */
        v[0].b = gz;  v[0].n = 30;         v[0].want = ZUH_ERR_BODY_DECODE; v[0].body = NULL;
        v[1].b = gz;  v[1].n = gzlen - 8;  v[1].want = ZUH_ERR_BODY_DECODE; v[1].body = NULL;
        v[2].b = two; v[2].n = twolen;     v[2].want = ZUH_OK;              v[2].body = "helloworld";
        v[3].b = zl;  v[3].n = zllen;      v[3].want = ZUH_ERR_BODY_DECODE; v[3].body = NULL;
        v[4].b = gz;  v[4].n = gzlen;      v[4].want = ZUH_OK;              v[4].body = NULL;
        for (slow = 0; slow < 2; slow++)
        for (how = 0; how < 3; how++)
        for (i = 0; i < 5; i++) {
            const char *coding = (i == 3) ? "deflate" : "gzip";
            conn_script sc[1];
            sc[0].bytes = resp; sc[0].len = framed(resp, sizeof resp, how, coding, v[i].b, v[i].n);
            sc[0].max_read = slow ? 1 : 0; sc[0].not_readable = 0; sc[0].next = NULL;
            dialer_init(&d, sc, 1); opts_for(&o, &d);
            rc = zuh_engine_get(&r, "http://example.test/", &o, &e);
            ZUH_CHECK_EQ_INT(rc, v[i].want);
            if (rc == ZUH_OK) {
                if (v[i].body)
                    ZUH_CHECK(r.body.len == strlen(v[i].body) &&
                             memcmp(r.body.data, v[i].body, r.body.len) == 0);
                else
                    ZUH_CHECK(r.body.len == sizeof plain &&
                             memcmp(r.body.data, plain, sizeof plain) == 0);
                zuh_result_free(&r);
            } else {
                ZUH_CHECK_EQ_INT(e.code, rc);
            }
            dialer_free(&d);
        }
        /* An empty body under a coding decodes to nothing, successfully:
         * there is no stream to be incomplete. */
        {
            conn_script sc[] = {{ "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n"
                                  "Connection: close\r\n\r\n", 0, 0, 0, NULL }};
            dialer_init(&d, sc, 1); opts_for(&o, &d);
            ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "http://example.test/", &o, &e), ZUH_OK);
            ZUH_CHECK_EQ_INT(r.body.len, 0);
            zuh_result_free(&r); dialer_free(&d);
        }
    }

    ZUH_CASE("engine: a body larger than the header budget is sent whole (§17)");
    {
        /* The body used to be appended to the 64 KiB header buffer, so any
         * upload of 64 KiB or more failed before a byte was sent, with no
         * error object filled in. */
        static unsigned char big[200000];
        static const size_t sizes[3] = { 60000, 65536, sizeof big };
        zuh_req_spec spec;
        int k;
        for (k = 0; k < (int)sizeof big; k++) big[k] = (unsigned char)(k * 7);
        for (k = 0; k < 3; k++) {
            conn_script sc[] = {{ "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok", 0, 0, 0, NULL }};
            memset(&spec, 0, sizeof spec);
            spec.method = "POST"; spec.body = big; spec.body_len = sizes[k];
            dialer_init(&d, sc, 1); opts_for(&o, &d);
            rc = zuh_engine_perform(&r, "http://example.test/up", &spec, &o, &e);
            ZUH_CHECK_EQ_INT(rc, ZUH_OK);
            ZUH_CHECK(d.sent[0].len > sizes[k] &&
                     memcmp(d.sent[0].data + d.sent[0].len - sizes[k], big, sizes[k]) == 0);
            if (rc == ZUH_OK) zuh_result_free(&r);
            dialer_free(&d);
        }
        /* A request line and headers over the 64 KiB block are refused
         * before a byte is sent, as an overflow and with the error filled
         * in: each header is under its own limit, and the long target is
         * what tips the block over. */
        {
            static char val[8000], url[2100];
            static const char *hn[] = { "X-A", "X-B", "X-C", "X-D", "X-E", "X-F", "X-G", "X-H" };
            const char *hv[8];
            conn_script sc[] = {{ OK200(2) "ok", 0, 0, 0, NULL }};
            memset(val, 'v', sizeof val - 1); val[sizeof val - 1] = '\0';
            for (k = 0; k < 8; k++) hv[k] = val;
            memcpy(url, "http://example.test/", 20);
            memset(url + 20, 'a', sizeof url - 21); url[sizeof url - 1] = '\0';
            memset(&spec, 0, sizeof spec);
            spec.header_names = hn; spec.header_values = hv; spec.n_headers = 8;
            dialer_init(&d, sc, 1); opts_for(&o, &d);
            zuh_error_clear(&e);
            rc = zuh_engine_perform(&r, url, &spec, &o, &e);
            ZUH_CHECK_EQ_INT(rc, ZUH_ERR_OVERFLOW);
            ZUH_CHECK_EQ_INT(e.code, ZUH_ERR_OVERFLOW);
            ZUH_CHECK_EQ_INT(d.sent[0].len, 0);
            dialer_free(&d);
        }
    }

    ZUH_CASE("engine: HEAD and 304 keep their representation headers and decode nothing (RFC 9112 §6.3)");
    {
        zuh_req_spec spec;
        conn_script br[]  = {{ "HTTP/1.1 200 OK\r\nContent-Encoding: br\r\nContent-Length: 123\r\n\r\n", 0, 0, 0, NULL }};
        conn_script gz[]  = {{ "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 123\r\n\r\n", 0, 0, 0, NULL }};
        conn_script nm[]  = {{ "HTTP/1.1 304 Not Modified\r\nContent-Encoding: gzip\r\nContent-Length: 123\r\n\r\n", 0, 0, 0, NULL }};
        memset(&spec, 0, sizeof spec); spec.method = "HEAD";
        dialer_init(&d, br, 1); opts_for(&o, &d);
        ZUH_CHECK_EQ_INT(zuh_engine_perform(&r, "http://example.test/", &spec, &o, &e), ZUH_OK);
        ZUH_CHECK(zuh_headers_get(&r.headers, "Content-Encoding") != NULL);
        zuh_result_free(&r); dialer_free(&d);
        dialer_init(&d, gz, 1); opts_for(&o, &d);
        ZUH_CHECK_EQ_INT(zuh_engine_perform(&r, "http://example.test/", &spec, &o, &e), ZUH_OK);
        ZUH_CHECK(zuh_headers_get(&r.headers, "Content-Encoding") != NULL);
        ZUH_CHECK(zuh_headers_get(&r.headers, "Content-Length") != NULL &&
                 strcmp(zuh_headers_get(&r.headers, "Content-Length"), "123") == 0);
        zuh_result_free(&r); dialer_free(&d);
        dialer_init(&d, nm, 1); opts_for(&o, &d);
        ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "http://example.test/", &o, &e), ZUH_OK);
        ZUH_CHECK_EQ_INT(r.status, 304);
        ZUH_CHECK(zuh_headers_get(&r.headers, "Content-Encoding") != NULL);
        zuh_result_free(&r); dialer_free(&d);
    }

    ZUH_CASE("engine: a redirect body is drained undecoded, and one that cannot be drained closes the connection (§19.5)");
    {
        /* Three intermediate bodies that must not stop a valid Location being
         * followed: one over the 64 KiB drain budget, one in a coding this
         * client cannot decode, and one cut short. Each hop is on a pool: the
         * two that could not be drained must not be reused, while the
         * undecodable one drained cleanly and must be. */
        static char big[72000];
        size_t hl = (size_t)snprintf(big, sizeof big,
            "HTTP/1.1 302 Found\r\nLocation: /ok\r\nContent-Length: 70000\r\n\r\n");
        const char *firsts[3] = { big,
            "HTTP/1.1 302 Found\r\nLocation: /ok\r\nContent-Encoding: br\r\nContent-Length: 4\r\n\r\n\x01\x02\x03\x04",
            "HTTP/1.1 302 Found\r\nLocation: /ok\r\nContent-Length: 10\r\n\r\nabc" };
        const size_t lens[3] = { hl + 70000, 0, 0 };
        int k;
        memset(big + hl, 'x', 70000);
        for (k = 0; k < 3; k++) {
            zuh_pool *pool = zuh_pool_new(NULL);
            conn_script sc[2];
            sc[0].bytes = firsts[k]; sc[0].len = lens[k]; sc[0].max_read = 0;
            sc[0].not_readable = 1; sc[0].next = (k == 1) ? OK200(2) "ok" : NULL;
            sc[1].bytes = OK200(2) "ok"; sc[1].len = 0; sc[1].max_read = 0;
            sc[1].not_readable = 1; sc[1].next = NULL;
            dialer_init(&d, sc, 2); opts_for(&o, &d); o.pool = pool;
            rc = zuh_engine_get(&r, "http://example.test/start", &o, &e);
            ZUH_CHECK_EQ_INT(rc, ZUH_OK);
            if (rc == ZUH_OK) {
                ZUH_CHECK_EQ_INT(r.status, 200);
                ZUH_CHECK_EQ_INT(r.redirects, 1);
                ZUH_CHECK(r.body.len == 2 && memcmp(r.body.data, "ok", 2) == 0);
                zuh_result_free(&r);
            }
            ZUH_CHECK_EQ_INT(d.next, k == 1 ? 1 : 2);   /* a new connection unless drained */
            dialer_free(&d); zuh_pool_free(pool);
        }
    }

    ZUH_CASE("engine: truncated bodies are errors, and over-limit bodies are refused");
    {
        conn_script cl[] = {{ "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n01234", 0, 0, 0, NULL }};
        conn_script ch[] = {{ "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel", 0, 0, 0, NULL }};
        conn_script big[] = {{ "HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n01234567890123456789", 0, 0, 0, NULL }};
        dialer_init(&d, cl, 1); opts_for(&o, &d);
        ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "http://example.test/", &o, &e), ZUH_ERR_PARSE);
        dialer_free(&d);
        dialer_init(&d, ch, 1); opts_for(&o, &d);
        ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "http://example.test/", &o, &e), ZUH_ERR_PARSE);
        dialer_free(&d);
        dialer_init(&d, big, 1); opts_for(&o, &d); o.max_body = 10;
        ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "http://example.test/", &o, &e), ZUH_ERR_BODY_LIMIT);
        dialer_free(&d);
    }

    ZUH_CASE("engine: redirect bodies never reach the caller's sink (§19.5)");
    {
        zuh_buffer out;
        zuh_sink *sink;
        conn_script s[] = {
            { "HTTP/1.1 302 Found\r\nLocation: /f\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNOT-THIS!", 0, 0, 0, NULL },
            { "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nthis", 0, 0, 0, NULL } };
        zuh_buf_init(&out, 64, 1 << 16);
        sink = zuh_sink_memory(&out);
        dialer_init(&d, s, 2); opts_for(&o, &d); o.sink = sink;
        rc = zuh_engine_get(&r, "http://example.test/", &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        ZUH_CHECK(out.len == 4 && memcmp(out.data, "this", 4) == 0);
        zuh_result_free(&r); dialer_free(&d);
        zuh_sink_free(sink); zuh_buf_free(&out);
    }

    ZUH_CASE("engine: a stale pooled connection is discarded and a new one dialled (§26.2)");
    {
        zuh_pool *pool = zuh_pool_new(NULL);
        zuh_pool_stats st;
        /* The first connection answers once and then reads as readable: the
         * peer closed it while it sat in the pool. */
        conn_script s[] = {
            { OK200(1) "a", 0, 0, 0, NULL },
            { OK200(1) "b", 0, 0, 1, NULL } };
        dialer_init(&d, s, 2); opts_for(&o, &d); o.pool = pool;
        ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "http://example.test/", &o, &e), ZUH_OK);
        zuh_result_free(&r);
        ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "http://example.test/", &o, &e), ZUH_OK);
        ZUH_CHECK(r.body.len == 1 && r.body.data[0] == 'b');
        ZUH_CHECK_EQ_INT(d.next, 2);
        zuh_pool_stats_get(pool, &st);
        ZUH_CHECK_EQ_INT(st.discarded_stale, 1);
        zuh_result_free(&r); dialer_free(&d); zuh_pool_free(pool);
    }

    ZUH_CASE("engine: plain HTTP through a proxy uses absolute-form and Proxy-Authorization (§20)");
    {
        zuh_env env;
        envtab tab = {{ "http_proxy", "no_proxy", NULL }, { "http://u:p@proxy.test:3128", "direct.test", NULL }};
        conn_script s[] = {
            { "HTTP/1.1 302 Found\r\nLocation: http://direct.test/x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0, 0, 0, NULL },
            { "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0, 0, 0, NULL } };
        env.get = env_get; env.ctx = &tab;
        dialer_init(&d, s, 2); opts_for(&o, &d);
        o.proxy_set = 0; o.env = &env;
        rc = zuh_engine_get(&r, "http://example.test/start", &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        ZUH_CHECK(strcmp(d.host[0], "proxy.test") == 0 && d.port[0] == 3128);
        ZUH_CHECK(has(sent(&d, 0), "GET http://example.test/start HTTP/1.1\r\n"));
        ZUH_CHECK(has(sent(&d, 0), "Proxy-Authorization: Basic dTpw\r\n"));
        /* The redirect lands on a NO_PROXY host: direct, and no proxy credential. */
        ZUH_CHECK(strcmp(d.host[1], "direct.test") == 0 && d.port[1] == 80);
        ZUH_CHECK(has(sent(&d, 1), "GET /x HTTP/1.1\r\n"));
        ZUH_CHECK(!has(sent(&d, 1), "Proxy-Authorization"));
        zuh_result_free(&r); dialer_free(&d);
    }

    ZUH_CASE("engine: a request whose last hop is proxied frees the proxy, password included (§20, §42)");
    {
        /* The case above ends on a NO_PROXY host, whose hop never parses a
         * proxy, so it could not see that every exit after the response
         * leaked the one it had. Measured per request rather than left to the
         * end-of-main() check, which would name no path. The third exit
         * cannot parse "http://[x" as a URL, so it returns straight out of
         * the loop. */
        const char *finals[3] = {
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            "HTTP/1.1 302 Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 302 Found\r\nLocation: http://[x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" };
        const zuh_code want[3] = { ZUH_OK, ZUH_OK, ZUH_ERR_URL };
        int k;
        for (k = 0; k < 3; k++) {
            zuh_alloc_stats before, after;
            conn_script s[1];
            s[0].bytes = finals[k]; s[0].len = 0; s[0].max_read = 0;
            s[0].not_readable = 0; s[0].next = NULL;
            zuh_alloc_stats_get(&before);
            dialer_init(&d, s, 1); opts_for(&o, &d);
            o.proxy = "http://u:p@proxy.test:3128";
            ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "http://example.test/", &o, &e), want[k]);
            ZUH_CHECK(strcmp(d.host[0], "proxy.test") == 0);
            if (want[k] == ZUH_OK) zuh_result_free(&r);
            dialer_free(&d);
            zuh_alloc_stats_get(&after);
            ZUH_CHECK_EQ_INT(after.live_blocks, before.live_blocks);
        }
    }

    ZUH_CASE("engine: CONNECT outcomes for HTTPS through a proxy (§20.3)");
    {
        conn_script s407[] = {{ "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n", 0, 0, 0, NULL }};
        conn_script s502[] = {{ "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n", 0, 0, 0, NULL }};
        conn_script junk[] = {{ "HTTP/1.1 200 Connection Established\r\n\r\n\x16\x03\x01", 0, 0, 0, NULL }};
        conn_script ok[]   = {{ "HTTP/1.1 200 Connection Established\r\n\r\n", 0, 0, 0, NULL }};
        dialer_init(&d, s407, 1); opts_for(&o, &d); o.proxy = "http://proxy.test:3128";
        ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "https://example.test/", &o, &e), ZUH_ERR_PROXY_AUTH);
        ZUH_CHECK(has(sent(&d, 0), "CONNECT example.test:443 HTTP/1.1\r\n"));
        dialer_free(&d);
        dialer_init(&d, s502, 1); opts_for(&o, &d); o.proxy = "http://proxy.test:3128";
        ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "https://example.test/", &o, &e), ZUH_ERR_PROXY);
        dialer_free(&d);
        /* Bytes after the CONNECT response are origin TLS data the proxy had
         * no business sending: refused rather than spliced into a handshake. */
        dialer_init(&d, junk, 1); opts_for(&o, &d); o.proxy = "http://proxy.test:3128";
        ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "https://example.test/", &o, &e), ZUH_ERR_PROXY);
        dialer_free(&d);
        /* A clean tunnel reaches TLS, which this build does not have. */
        dialer_init(&d, ok, 1); opts_for(&o, &d); o.proxy = "http://proxy.test:3128";
        ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "https://example.test/", &o, &e), ZUH_ERR_TLS);
        dialer_free(&d);
    }

    ZUH_CASE("engine: bytes past a response's framing keep its connection out of the pool (§26.3)");
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
            zuh_pool *pool = zuh_pool_new(NULL);
            zuh_pool_stats st;
            conn_script s[] = { { cases[k], 0, 0, 1, NULL }, { OK200(2) "ok", 0, 0, 1, NULL } };
            dialer_init(&d, s, 2); opts_for(&o, &d); o.pool = pool;
            ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "http://example.test/", &o, &e), ZUH_OK);
            ZUH_CHECK(k == 2 || (r.body.len == 2 && memcmp(r.body.data, "ok", 2) == 0));
            zuh_result_free(&r);
            ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "http://example.test/", &o, &e), ZUH_OK);
            ZUH_CHECK(r.body.len == 2 && memcmp(r.body.data, "ok", 2) == 0);   /* never "evil" */
            ZUH_CHECK_EQ_INT(d.next, 2);
            zuh_pool_stats_get(pool, &st);
            ZUH_CHECK_EQ_INT(st.hits, 0);
            zuh_result_free(&r); dialer_free(&d); zuh_pool_free(pool);
        }
    }

    ZUH_CASE("engine: a connection failure is the dialer's error, and nothing is sent");
    {
        dialer_init(&d, NULL, 0); opts_for(&o, &d);
        ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "http://example.test/", &o, &e), ZUH_ERR_CONNECT);
        ZUH_CHECK_EQ_INT(d.sent[0].len, 0);
        dialer_free(&d);
    }

    ZUH_CASE("engine: §17.2 defaults: a bare User-Agent without a version, Connection follows the pool");
    {
        /* R passes "zuhttp/<version>"; C holds no version to go stale. */
        conn_script sc[] = {{ OK200(2) "ok", 0, 0, 0, NULL }};
        conn_script sk[] = {{ OK200(2) "ok", 0, 0, 1, NULL }};
        zuh_pool *pool = zuh_pool_new(NULL);
        dialer_init(&d, sc, 1); opts_for(&o, &d);
        ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "http://example.test/", &o, &e), ZUH_OK);
        ZUH_CHECK(has(sent(&d, 0), "User-Agent: zuhttp\r\n"));
        /* no pool: the connection is closed after the response, so say so */
        ZUH_CHECK(has(sent(&d, 0), "Connection: close\r\n"));
        ZUH_CHECK(!has(sent(&d, 0), "keep-alive"));
        zuh_result_free(&r); dialer_free(&d);
        dialer_init(&d, sk, 1); opts_for(&o, &d); o.pool = pool;
        o.user_agent = "zuhttp/9.9.9";
        ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "http://example.test/", &o, &e), ZUH_OK);
        ZUH_CHECK(has(sent(&d, 0), "User-Agent: zuhttp/9.9.9\r\n"));
        ZUH_CHECK(has(sent(&d, 0), "Connection: keep-alive\r\n"));
        zuh_result_free(&r); dialer_free(&d); zuh_pool_free(pool);
    }

    ZUH_CASE("engine: a request header is bounded by the 64 KiB block, not §40's response limits (§17)");
    {
        /* A 9 KB bearer token was refused as a "body limit" by the 8 KiB
         * per-value cap meant for untrusted responses. */
        static char tok[9100];
        static const char *hn[] = { "Authorization" };
        const char *hv[1];
        zuh_req_spec spec;
        conn_script sc[] = {{ OK200(2) "ok", 0, 0, 0, NULL }};
        memcpy(tok, "Bearer ", 7); memset(tok + 7, 'a', sizeof tok - 8); tok[sizeof tok - 1] = '\0';
        hv[0] = tok;
        memset(&spec, 0, sizeof spec);
        spec.header_names = hn; spec.header_values = hv; spec.n_headers = 1;
        dialer_init(&d, sc, 1); opts_for(&o, &d);
        rc = zuh_engine_perform(&r, "http://example.test/", &spec, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        ZUH_CHECK(has(sent(&d, 0), tok));
        if (rc == ZUH_OK) zuh_result_free(&r);
        dialer_free(&d);
    }

    ZUH_CASE("engine: a request header carrying CR/LF is refused before connecting, naming the header (§17.1)");
    {
        static const char *hn[]  = { "Accept", "X-Evil" };
        static const char *hv[]  = { "*/*", "a\r\nInjected: 1" };
        static const char *bn[]  = { "Bad Name" };
        static const char *bv[]  = { "v" };
        zuh_req_spec spec;
        conn_script sc[] = {{ OK200(2) "ok", 0, 0, 0, NULL }};
        memset(&spec, 0, sizeof spec);
        spec.header_names = hn; spec.header_values = hv; spec.n_headers = 2;
        dialer_init(&d, sc, 1); opts_for(&o, &d);
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", &spec, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_ERR_PARSE);
        ZUH_CHECK(has(e.message, "`X-Evil`") && has(e.message, "invalid value"));
        ZUH_CHECK(!has(e.message, "Injected"));      /* never the value */
        ZUH_CHECK_EQ_INT(d.next, 0);                  /* refused before connecting */
        dialer_free(&d);
        spec.header_names = bn; spec.header_values = bv; spec.n_headers = 1;
        dialer_init(&d, sc, 1); opts_for(&o, &d);
        zuh_error_clear(&e);
        rc = zuh_engine_perform(&r, "http://example.test/", &spec, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_ERR_PARSE);
        ZUH_CHECK(has(e.message, "header 1 has an invalid name"));
        ZUH_CHECK(!has(e.message, "Bad Name"));
        ZUH_CHECK_EQ_INT(d.next, 0);
        dialer_free(&d);
    }

    ZUH_CASE("engine: a redirect back to a URL already requested is a loop, raised at once (§19.4)");
    {
        conn_script self[] = {
            { "HTTP/1.1 302 Found\r\nLocation: /loop\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0, 0, 0, NULL },
            { "HTTP/1.1 302 Found\r\nLocation: /loop\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0, 0, 0, NULL } };
        conn_script ab[] = {
            { "HTTP/1.1 302 Found\r\nLocation: /b\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0, 0, 0, NULL },
            { "HTTP/1.1 302 Found\r\nLocation: /a\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0, 0, 0, NULL },
            { OK200(2) "no", 0, 0, 0, NULL } };
        conn_script see_other[] = {
            { "HTTP/1.1 303 See Other\r\nLocation: /x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0, 0, 0, NULL },
            { OK200(2) "ok", 0, 0, 0, NULL } };
        zuh_req_spec spec;
        /* /loop -> /loop: one round trip, not max_redirects of them */
        dialer_init(&d, self, 2); opts_for(&o, &d);
        zuh_error_clear(&e);
        ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "http://example.test/loop", &o, &e), ZUH_ERR_REDIRECT);
        ZUH_CHECK_EQ_INT(d.next, 1);
        ZUH_CHECK(has(e.message, "redirect loop"));
        dialer_free(&d);
        /* /a -> /b -> /a */
        dialer_init(&d, ab, 3); opts_for(&o, &d);
        ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "http://example.test/a", &o, &e), ZUH_ERR_REDIRECT);
        ZUH_CHECK_EQ_INT(d.next, 2);
        dialer_free(&d);
        /* the method is part of the pair: POST /x -> 303 -> GET /x is no loop */
        memset(&spec, 0, sizeof spec); spec.method = "POST";
        dialer_init(&d, see_other, 2); opts_for(&o, &d);
        rc = zuh_engine_perform(&r, "http://example.test/x", &spec, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) zuh_result_free(&r);
        dialer_free(&d);
    }

    ZUH_CASE("engine: a pooled connection still reports that it runs through the proxy (§35.2)");
    {
        zuh_pool *pool = zuh_pool_new(NULL);
        zuh_pool_stats st;
        conn_script sc[] = {{ OK200(1) "A", 0, 0, 1, OK200(1) "B" }};
        dialer_init(&d, sc, 1); opts_for(&o, &d); o.pool = pool;
        o.proxy = "http://proxy.test:3128";
        ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "http://origin.test/", &o, &e), ZUH_OK);
        ZUH_CHECK_EQ_INT(r.proxy_used, 1);
        ZUH_CHECK_EQ_INT(r.reused_connection, 0);
        zuh_result_free(&r);
        ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "http://origin.test/", &o, &e), ZUH_OK);
        ZUH_CHECK_EQ_INT(r.reused_connection, 1);
        ZUH_CHECK_EQ_INT(r.proxy_used, 1);            /* was 0 on every reuse */
        ZUH_CHECK(r.body.len == 1 && r.body.data[0] == 'B');
        zuh_result_free(&r);
        zuh_pool_stats_get(pool, &st);
        ZUH_CHECK_EQ_INT(st.hits, 1);
        dialer_free(&d); zuh_pool_free(pool);
    }

    ZUH_CASE("engine: a response header block over 64 KiB is refused (§40)");
    {
        static char big[80000];
        size_t k, n = 0;
        conn_script sc[1];
        n += (size_t)snprintf(big + n, sizeof big - n, "HTTP/1.1 200 OK\r\n");
        for (k = 0; k < 60; k++) {
            n += (size_t)snprintf(big + n, sizeof big - n, "X-%02lu: ", (unsigned long)k);
            memset(big + n, 'v', 1200); n += 1200;
            n += (size_t)snprintf(big + n, sizeof big - n, "\r\n");
        }
        n += (size_t)snprintf(big + n, sizeof big - n, "Content-Length: 0\r\n\r\n");
        memset(sc, 0, sizeof sc); sc[0].bytes = big; sc[0].len = n;
        dialer_init(&d, sc, 1); opts_for(&o, &d);
        zuh_error_clear(&e);
        ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "http://example.test/", &o, &e), ZUH_ERR_BODY_LIMIT);
        ZUH_CHECK(has(e.message, "header block exceeds"));
        dialer_free(&d);
    }

    ZUH_CASE("engine: protocol failures in the response head each raise their own error");
    {
        static const struct { const char *bytes; zuh_code want; const char *says; } cases[] = {
            { "HTTP/1.1 200 OK\r\nContent-Le",             ZUH_ERR_PARSE, "before the response headers ended" },
            { "HTTP/1.2 200 OK\r\nContent-Length: 0\r\n\r\n", ZUH_ERR_PARSE, "unsupported HTTP/1.2" },
            { "HTTP/1.1 999 Odd\r\nContent-Length: 0\r\n\r\n", ZUH_ERR_PARSE, "invalid status code 999" },
            { "HTTP/1.1 099 Odd\r\nContent-Length: 0\r\n\r\n", ZUH_ERR_PARSE, "invalid status code" } };
        size_t k;
        for (k = 0; k < sizeof cases / sizeof cases[0]; k++) {
            conn_script sc[1];
            memset(sc, 0, sizeof sc); sc[0].bytes = cases[k].bytes;
            dialer_init(&d, sc, 1); opts_for(&o, &d);
            zuh_error_clear(&e);
            ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "http://example.test/", &o, &e), cases[k].want);
            ZUH_CHECK(has(e.message, cases[k].says));
            dialer_free(&d);
        }
    }

    ZUH_CASE("engine: a CONNECT reply that never ends, or a proxy that hangs up, is a proxy error (§20.3)");
    {
        static char big[70000];
        size_t n;
        conn_script hang[] = {{ "HTTP/1.1 200 Connection est", 0, 0, 0, NULL }};
        conn_script huge[1];
        n = (size_t)snprintf(big, sizeof big, "HTTP/1.1 200 OK\r\n");
        while (n + 1200 < sizeof big) {
            n += (size_t)snprintf(big + n, sizeof big - n, "X-Pad: ");
            memset(big + n, 'p', 1000); n += 1000;
            n += (size_t)snprintf(big + n, sizeof big - n, "\r\n");
        }
        memset(huge, 0, sizeof huge); huge[0].bytes = big; huge[0].len = n;
        dialer_init(&d, hang, 1); opts_for(&o, &d); o.proxy = "http://proxy.test:3128";
        zuh_error_clear(&e);
        ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "https://origin.test/", &o, &e), ZUH_ERR_PROXY);
        ZUH_CHECK(has(e.message, "closed the connection during CONNECT"));
        dialer_free(&d);
        dialer_init(&d, huge, 1); opts_for(&o, &d); o.proxy = "http://proxy.test:3128";
        zuh_error_clear(&e);
        ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "https://origin.test/", &o, &e), ZUH_ERR_PROXY);
        ZUH_CHECK(has(e.message, "too large"));
        dialer_free(&d);
    }

    ZUH_CASE("engine: corrupt deflate data after a valid gzip header is a decode error (§21)");
    {
        /* D-76 covers a stream that ends early; this one is wrong from the
         * first block, which is inflate()'s Z_DATA_ERROR branch. */
        static const char resp[] =
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 18\r\n\r\n"
            "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03" "\xff\xff\xff\xff\xff\xff\xff\xff";
        conn_script sc[1];
        memset(sc, 0, sizeof sc); sc[0].bytes = resp; sc[0].len = sizeof resp - 1;
        dialer_init(&d, sc, 1); opts_for(&o, &d);
        zuh_error_clear(&e);
        ZUH_CHECK_EQ_INT(zuh_engine_get(&r, "http://example.test/", &o, &e), ZUH_ERR_BODY_DECODE);
        dialer_free(&d);
    }

    ZUH_CASE("engine: every allocation failure on a proxied, pooled redirect fails cleanly (§11, §43)");
    {
        /* The engine has dozens of hand-written exits on allocation failure.
         * Fail each allocation in turn: every run must succeed or report
         * ZUH_ERR_NOMEM with the error filled in, and leave nothing live —
         * the proxy password above all (§42). */
        conn_script sc[] = {
            { "HTTP/1.1 302 Found\r\nLocation: http://other.test/b\r\nContent-Length: 0\r\n\r\n", 0, 0, 1, NULL },
            { OK200(2) "ok", 0, 0, 1, NULL } };
        static const char *hn[] = { "Authorization", "Accept" };
        static const char *hv[] = { "Bearer s3cret", "*/*" };
        zuh_req_spec spec;
        zuh_alloc_stats before, after, counted;
        long n, total, failed_cleanly = 0, bad = 0;
        memset(&spec, 0, sizeof spec);
        spec.header_names = hn; spec.header_values = hv; spec.n_headers = 2;
        /* One clean run to count the allocations the scenario makes. */
        {
            zuh_pool *pool = zuh_pool_new(NULL);
            dialer_init(&d, sc, 2); opts_for(&o, &d); o.pool = pool;
            o.proxy = "http://u:p@proxy.test:3128";
            zuh_alloc_stats_get(&before);
            ZUH_CHECK_EQ_INT(zuh_engine_perform(&r, "http://example.test/a", &spec, &o, &e), ZUH_OK);
            zuh_alloc_stats_get(&counted);
            zuh_result_free(&r); dialer_free(&d); zuh_pool_free(pool);
            total = (long)(counted.total_allocs - before.total_allocs);
        }
        ZUH_CHECK(total > 20);
        for (n = 0; n < total; n++) {
            zuh_pool *pool;
            zuh_alloc_stats_get(&before);
            pool = zuh_pool_new(NULL);
            dialer_init(&d, sc, 2); opts_for(&o, &d); o.pool = pool;
            o.proxy = "http://u:p@proxy.test:3128";
            zuh_error_clear(&e);
            zuh_alloc_fail_after(n);
            rc = zuh_engine_perform(&r, "http://example.test/a", &spec, &o, &e);
            zuh_alloc_fail_after(-1);
            if (rc == ZUH_OK) zuh_result_free(&r);
            else if (rc == ZUH_ERR_NOMEM && e.code == ZUH_ERR_NOMEM) failed_cleanly++;
            else bad++;
            zuh_pool_free(pool); dialer_free(&d);
            zuh_alloc_stats_get(&after);
            if (after.live_blocks != before.live_blocks) bad++;
        }
        ZUH_CHECK(failed_cleanly > 0);   /* the sweep reached failures at all */
        ZUH_CHECK_EQ_INT(bad, 0);
    }

}

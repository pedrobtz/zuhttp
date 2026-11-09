/* The engine over the OpenSSL backend against tls_eof/server.py (D-86).
 *
 *   drive noclose  URL CA   one request; the close-delimited body arrives whole
 *   drive together URL CA   two requests on one pooled client; the second must
 *                           not be sent down the connection the server closed
 *   drive stale URL CA OTHER  a pooled request, a request that fails its
 *                           handshake (trusting OTHER), then the pooled
 *                           connection again: a failed handshake must not
 *                           leave an error that poisons the next read
 *   drive one URL CA        one request, which must come back 200 with the
 *                           body "ok": for the server that renegotiates
 *                           mid-response (#215, run under ASan) and for a
 *                           certificate that names only an IP address (#216)
 *
 * Exits 0 when the engine behaved, 1 otherwise, saying which. */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#  define _POSIX_C_SOURCE 200809L   /* nanosleep */
#endif
#include "zuh_engine.h"
#include "zuh_pool.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

static int stale(const char *url, const char *ca, const char *other) {
    zuh_get_opts o;
    zuh_result r;
    zuh_error e;
    zuh_code rc;
    zuh_pool_stats st;
    int bad = 0;
    zuh_pool *pool = zuh_pool_new(NULL);
    zuh_get_opts_init(&o);
    o.proxy_set = 1; o.timeout_ms = 10000; o.pool = pool;
    o.ca_file = ca;
    rc = zuh_engine_get(&r, url, &o, &e);
    if (rc == ZUH_OK) zuh_result_free(&r);
    else { printf("FAIL stale request 1: %s\n", e.message); bad = 1; }
    o.ca_file = other;      /* a different pool key: a new, failing handshake */
    rc = zuh_engine_get(&r, url, &o, &e);
    if (rc == ZUH_OK) { zuh_result_free(&r); printf("FAIL stale request 2 was trusted\n"); bad = 1; }
    else printf("stale request 2: refused as expected (%s)\n", e.message);
    o.ca_file = ca;         /* back to the pooled connection, no handshake */
    rc = zuh_engine_get(&r, url, &o, &e);
    if (rc != ZUH_OK) { printf("FAIL stale request 3: code %d, %s\n", rc, e.message); bad = 1; }
    else {
        printf("stale request 3: status %d, reused %d\n", r.status, r.reused_connection);
        zuh_result_free(&r);
    }
    zuh_pool_stats_get(pool, &st);
    if (st.hits != 1) { printf("FAIL the pooled connection was not reused\n"); bad = 1; }
    zuh_pool_free(pool);
    return bad;
}

static int one(const char *url, const char *ca) {
    zuh_get_opts o;
    zuh_result r;
    zuh_error e;
    zuh_code rc;
    int bad = 0;
    zuh_get_opts_init(&o);
    o.ca_file = ca; o.proxy_set = 1; o.timeout_ms = 10000;
    rc = zuh_engine_get(&r, url, &o, &e);
    if (rc != ZUH_OK) { printf("FAIL one %s: code %d, %s\n", url, rc, e.message); return 1; }
    printf("one %s: status %d, %lu body bytes\n", url, r.status, (unsigned long)r.body.len);
    if (r.status != 200 || r.body.len < 2 || memcmp(r.body.data, "ok", 2) != 0) {
        printf("FAIL one %s: not the 200 \"ok\" the server sent\n", url);
        bad = 1;
    }
    zuh_result_free(&r);
    return bad;
}

int main(int argc, char **argv) {
    zuh_get_opts o;
    zuh_result r;
    zuh_error e;
    zuh_code rc;
    int together, i, bad = 0;
    zuh_pool *pool = NULL;
    if (argc == 5 && strcmp(argv[1], "stale") == 0) return stale(argv[2], argv[3], argv[4]);
    if (argc == 4 && strcmp(argv[1], "one") == 0) return one(argv[2], argv[3]);
    if (argc != 4) { fprintf(stderr, "usage: drive noclose|together|one URL CA | stale URL CA OTHER\n"); return 2; }
    together = strcmp(argv[1], "together") == 0;
    zuh_get_opts_init(&o);
    o.ca_file = argv[3]; o.proxy_set = 1; o.timeout_ms = 10000;
    if (together) { pool = zuh_pool_new(NULL); o.pool = pool; }
    for (i = 0; i < (together ? 2 : 1); i++) {
        rc = zuh_engine_get(&r, argv[2], &o, &e);
        if (rc != ZUH_OK) {
            printf("FAIL %s request %d: code %d, %s\n", argv[1], i + 1, rc, e.message);
            bad = 1;
            continue;
        }
        printf("%s request %d: status %d, %lu body bytes, reused %d\n", argv[1], i + 1,
               r.status, (unsigned long)r.body.len, r.reused_connection);
        if (!together && r.body.len != 5000) {
            printf("FAIL the close-delimited body was cut short\n");
            bad = 1;
        }
        zuh_result_free(&r);
        if (together) {   /* let the close_notify arrive, as a real gap would */
            struct timespec ts = { 0, 300000000L };
            nanosleep(&ts, NULL);
        }
    }
    if (pool) {
        zuh_pool_stats st;
        zuh_pool_stats_get(pool, &st);
        if (st.hits != 0) {
            printf("FAIL a connection the server had closed was reused\n");
            bad = 1;
        }
        zuh_pool_free(pool);
    }
    return bad;
}

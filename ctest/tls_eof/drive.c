/* The engine over the OpenSSL backend against tls_eof/server.py (D-86).
 *
 *   drive noclose  URL CA   one request; the close-delimited body arrives whole
 *   drive together URL CA   two requests on one pooled client; the second must
 *                           not be sent down the connection the server closed
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

int main(int argc, char **argv) {
    zuh_get_opts o;
    zuh_result r;
    zuh_error e;
    zuh_code rc;
    int together, i, bad = 0;
    zuh_pool *pool = NULL;
    if (argc != 4) { fprintf(stderr, "usage: drive noclose|together URL CA\n"); return 2; }
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

/* The engine over a TLS backend against tls_eof/server.py (D-86): OpenSSL,
 * for the fork case Network.framework too (#249), and Schannel (#286),
 * which has no fork() and no ca_file: there CA is "-", and the certificate
 * is in the machine's Root store instead (run-sch.sh).
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
 *   drive refused URL CA    one request that must fail with a TLS class
 *                           and no body: Schannel's answer to a
 *                           renegotiation until #298
 *   drive hostname URL CA   #246: one request that must be refused with
 *                           ZUH_ERR_TLS_HOSTNAME, for a certificate naming a
 *                           different IP, or naming the IP only as a DNS name,
 *                           or naming the host only in its subject CN (#308)
 *   drive certificate URL CA  one request that must be refused with
 *                           ZUH_ERR_TLS_CERT: a client-authentication leaf
 *                           (#309)
 *   drive resume URL CA     #307: a request with verify off, then one that
 *                           verifies against CA, which must be refused as a
 *                           certificate failure: no session the first
 *                           handshake left behind may carry the second
 *   drive fork URL CA       #249: a pulled body open on one connection and a
 *                           second connection idle in the pool, then fork();
 *                           the child must not read the body, and frees both
 *                           without a byte reaching the server; the parent
 *                           then reads its body whole and reuses both
 *                           connections (fork.sh reads the server's log)
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
#ifdef _WIN32
#  include <windows.h>
#else
#  include <unistd.h>
#  include <sys/wait.h>
#endif

static void pause_ms(long ms) {
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    struct timespec ts;
    ts.tv_sec = ms / 1000; ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}

/* "-" is no ca_file: the system store decides, which is how Schannel runs. */
static const char *ca_opt(const char *ca) { return strcmp(ca, "-") == 0 ? NULL : ca; }

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
    o.ca_file = ca_opt(ca);
    rc = zuh_engine_get(&r, url, &o, &e);
    if (rc == ZUH_OK) zuh_result_free(&r);
    else { printf("FAIL stale request 1: %s\n", e.message); bad = 1; }
    o.ca_file = ca_opt(other);      /* a different pool key: a new, failing handshake */
    rc = zuh_engine_get(&r, url, &o, &e);
    if (rc == ZUH_OK) { zuh_result_free(&r); printf("FAIL stale request 2 was trusted\n"); bad = 1; }
    else printf("stale request 2: refused as expected (%s)\n", e.message);
    o.ca_file = ca_opt(ca);         /* back to the pooled connection, no handshake */
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

#ifndef _WIN32
/* Read a pulled body to its end. */
static zuh_code read_all(zuh_open_body *b, zuh_buffer *got, zuh_error *e) {
    for (;;) {
        size_t before = got->len;
        zuh_code rc = zuh_open_body_read(b, got, 7000, e);
        if (rc != ZUH_OK || got->len == before) return rc;
    }
}

static int forkcase(const char *url, const char *ca) {
    char big[512];
    zuh_get_opts o;
    zuh_result ra, rb, r1, r2;
    zuh_buffer got;
    zuh_error e;
    zuh_code rc;
    zuh_pool_stats st;
    pid_t kid;
    int bad = 0, status = -1;
    size_t i;
    zuh_pool *pool = zuh_pool_new(NULL);
    snprintf(big, sizeof big, "%sbig", url);
    zuh_get_opts_init(&o);
    o.proxy_set = 1; o.timeout_ms = 10000; o.pool = pool; o.ca_file = ca_opt(ca);
    zuh_buf_init(&got, 0, (size_t)-1);

    /* Connection 1 checked out into a pulled body, part-read; connection 2
     * idle in the pool. */
    o.stream_body = 1;
    rc = zuh_engine_perform(&ra, big, NULL, &o, &e);
    if (rc != ZUH_OK || !ra.open) { printf("FAIL fork: /big: %s\n", e.message); return 1; }
    if (zuh_open_body_read(ra.open, &got, 1000, &e) != ZUH_OK || got.len == 0) {
        printf("FAIL fork: the first read of /big: %s\n", e.message);
        return 1;
    }
    o.stream_body = 0;
    rc = zuh_engine_perform(&rb, url, NULL, &o, &e);
    if (rc != ZUH_OK) { printf("FAIL fork: request 2: %s\n", e.message); return 1; }
    zuh_result_free(&rb);
    if (zuh_pool_idle_count(pool) != 1) { printf("FAIL fork: nothing pooled\n"); return 1; }

    fflush(stdout);
    kid = fork();
    if (kid == 0) {
        /* The child reports the first check that failed in its status. */
        zuh_buffer cgot;
        zuh_pool_stats cst;
        int step = 0;
        zuh_buf_init(&cgot, 0, (size_t)-1);
        if (zuh_open_body_read(ra.open, &cgot, 1000, &e) != ZUH_ERR_FORK || cgot.len) step = 1;
        else if (zuh_open_body_read(ra.open, &cgot, 1000, &e) != ZUH_ERR_FORK) step = 2;
        else {
            zuh_open_body_abort(ra.open);                /* a no-op in a child */
            if (zuh_pool_check_fork(pool) != 1) step = 3;
            else {
                zuh_pool_stats_get(pool, &cst);
                if (zuh_pool_idle_count(pool) != 0 || cst.discarded_fork != 1) step = 4;
            }
        }
        /* The finalizers' path: the body and the pool freed in the child. */
        zuh_result_free(&ra);
        zuh_pool_free(pool);
        zuh_buf_free(&cgot);
        zuh_buf_free(&got);
        _exit(step);
    }
    if (kid < 0 || waitpid(kid, &status, 0) != kid || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
        printf("FAIL fork: the child failed at step %d\n",
               WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        bad = 1;
    }
    {   /* time for anything the child sent to reach the server and be acted on */
        pause_ms(300);
    }

    /* The parent's body is intact: every byte, in order, none consumed by
     * the child. */
    rc = read_all(ra.open, &got, &e);
    if (rc != ZUH_OK) { printf("FAIL fork: reading /big after the fork: %s\n", e.message); bad = 1; }
    if (got.len != 200000) {
        printf("FAIL fork: /big is %lu bytes, not 200000\n", (unsigned long)got.len);
        bad = 1;
    }
    for (i = 0; i < got.len && i < 200000; i++)
        if (got.data[i] != (unsigned char)(i % 251)) {
            printf("FAIL fork: /big differs at byte %lu\n", (unsigned long)i);
            bad = 1;
            break;
        }
    zuh_result_free(&ra);
    zuh_buf_free(&got);

    /* Both connections are still the parent's: two requests at once take
     * one each, and neither is a new connection. */
    o.stream_body = 1;
    rc = zuh_engine_perform(&r1, url, NULL, &o, &e);
    if (rc != ZUH_OK) { printf("FAIL fork: request 4: %s\n", e.message); zuh_pool_free(pool); return 1; }
    rc = zuh_engine_perform(&r2, url, NULL, &o, &e);
    if (rc != ZUH_OK) { printf("FAIL fork: request 5: %s\n", e.message); bad = 1; }
    else {
        if (!r1.reused_connection || !r2.reused_connection) {
            printf("FAIL fork: a connection the child inherited was not reusable (%d, %d)\n",
                   r1.reused_connection, r2.reused_connection);
            bad = 1;
        }
        zuh_buf_init(&got, 0, (size_t)-1);
        if (read_all(r2.open, &got, &e) != ZUH_OK || got.len != 2) bad = 1;
        zuh_buf_free(&got);
        zuh_result_free(&r2);
    }
    zuh_buf_init(&got, 0, (size_t)-1);
    if (read_all(r1.open, &got, &e) != ZUH_OK || got.len != 2) bad = 1;
    zuh_buf_free(&got);
    zuh_result_free(&r1);
    zuh_pool_stats_get(pool, &st);
    printf("fork: child exit %d, hits %lu, misses %lu\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1,
           (unsigned long)st.hits, (unsigned long)st.misses);
    if (st.hits != 2 || st.misses != 2) { printf("FAIL fork: expected 2 hits and 2 misses\n"); bad = 1; }
    zuh_pool_free(pool);
    return bad;
}
#endif

static int one(const char *url, const char *ca) {
    zuh_get_opts o;
    zuh_result r;
    zuh_error e;
    zuh_code rc;
    int bad = 0;
    zuh_get_opts_init(&o);
    o.ca_file = ca_opt(ca); o.proxy_set = 1; o.timeout_ms = 10000;
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

/* #246: the refusals #216's acceptance needs beside it. An IP literal is
 * matched against iPAddress SANs only (RFC 6125 §1.7.2, RFC 5280 §4.2.1.6),
 * so neither another address nor the same address spelled as a dNSName may
 * pass, and the failure is the hostname class, not "untrusted". */
static int refused_as(const char *what, zuh_code want, const char *url, const char *ca) {
    zuh_get_opts o;
    zuh_result r;
    zuh_error e;
    zuh_code rc;
    zuh_get_opts_init(&o);
    o.ca_file = ca_opt(ca); o.proxy_set = 1; o.timeout_ms = 10000;
    rc = zuh_engine_get(&r, url, &o, &e);
    if (rc == ZUH_OK) {
        printf("FAIL %s: %s was accepted (status %d)\n", what, url, r.status);
        zuh_result_free(&r);
        return 1;
    }
    if (rc != want) {
        printf("FAIL %s: code %d, not %d: %s\n", what, rc, want, e.message);
        return 1;
    }
    printf("%s: refused as expected (%s)\n", what, e.message);
    return 0;
}

static int refused(const char *url, const char *ca) {
    zuh_get_opts o;
    zuh_result r;
    zuh_error e;
    zuh_code rc;
    zuh_get_opts_init(&o);
    o.ca_file = ca_opt(ca); o.proxy_set = 1; o.timeout_ms = 10000;
    rc = zuh_engine_get(&r, url, &o, &e);
    if (rc == ZUH_OK) {
        printf("refused: %s now succeeds (status %d): #298 is fixed, run `one` here\n",
               url, r.status);
        zuh_result_free(&r);
        return 1;
    }
    if (rc < ZUH_ERR_TLS || rc > ZUH_ERR_TLS_PIN) {
        printf("FAIL refused: code %d is not a TLS class: %s\n", rc, e.message);
        return 1;
    }
    printf("refused: as expected, code %d (%s)\n", rc, e.message);
    return 0;
}

static int resume(const char *url, const char *ca) {
    zuh_get_opts o;
    zuh_result r;
    zuh_error e;
    zuh_code rc;
    zuh_get_opts_init(&o);
    o.proxy_set = 1; o.timeout_ms = 10000; o.verify = 0;
    rc = zuh_engine_get(&r, url, &o, &e);
    if (rc != ZUH_OK) { printf("FAIL resume request 1 (verify off): %s\n", e.message); return 1; }
    zuh_result_free(&r);
    o.verify = 1; o.ca_file = ca_opt(ca);
    rc = zuh_engine_get(&r, url, &o, &e);
    if (rc == ZUH_OK) {
        printf("FAIL resume request 2 was accepted (status %d): verification skipped\n", r.status);
        zuh_result_free(&r);
        return 1;
    }
    if (rc != ZUH_ERR_TLS_CERT) {
        printf("FAIL resume request 2: code %d, not a certificate failure: %s\n", rc, e.message);
        return 1;
    }
    printf("resume: request 2 refused as expected (%s)\n", e.message);
    return 0;
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
    if (argc == 4 && strcmp(argv[1], "refused") == 0) return refused(argv[2], argv[3]);
    if (argc == 4 && strcmp(argv[1], "hostname") == 0)
        return refused_as("hostname", ZUH_ERR_TLS_HOSTNAME, argv[2], argv[3]);
    if (argc == 4 && strcmp(argv[1], "certificate") == 0)
        return refused_as("certificate", ZUH_ERR_TLS_CERT, argv[2], argv[3]);
    if (argc == 4 && strcmp(argv[1], "resume") == 0) return resume(argv[2], argv[3]);
#ifndef _WIN32
    if (argc == 4 && strcmp(argv[1], "fork") == 0) return forkcase(argv[2], argv[3]);
#endif
    if (argc != 4) { fprintf(stderr, "usage: drive noclose|together|one|hostname|certificate|resume|fork URL CA | stale URL CA OTHER\n"); return 2; }
    together = strcmp(argv[1], "together") == 0;
    zuh_get_opts_init(&o);
    o.ca_file = ca_opt(argv[3]); o.proxy_set = 1; o.timeout_ms = 10000;
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
            pause_ms(300);
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

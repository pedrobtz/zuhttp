/* Connection pool — design §26.
 *
 * The pool is deliberately independent of TLS and sockets, so all of this
 * runs on the mock stream with no network (§50.1).
 *
 * The most important test here is the key field walk: §26.1 says a coarse key
 * is a security bug, so rather than trusting zu_pool_key_eq to be complete,
 * the suite changes every field in turn and asserts the key stops matching.
 */
#include "zu_test.h"
#include "zu_pool.h"
#include "zu_mock_stream.h"
#include "zu_alloc.h"
#include <string.h>
#include <stdio.h>
#if defined(ZU_POSIX)
#  include <unistd.h>
#  include <sys/wait.h>
#endif

void suite_pool(void);

/* A fake clock so idle expiry is testable without sleeping. */
static zu_millis g_now = 1000;
static zu_millis fake_now(void *ctx) { ZU_UNUSED(ctx); return g_now; }

/* An idle, clean connection: the script blocks, so the liveness probe says
 * "nothing waiting", which is what a healthy pooled socket looks like. */
static const zu_mock_step k_idle[] = { { ZU_MOCK_WOULDBLOCK, NULL, 0, ZU_OK } };

static zu_stream *idle_stream(void) {
    return zu_mock_stream_new(k_idle, 1, 0, 0);
}

static void basic_key(zu_pool_key *k, const char *host, uint16_t port) {
    zu_pool_key_init(k);
    k->scheme = (char *)zu_alloc(6); strcpy(k->scheme, "https");
    k->host   = (char *)zu_alloc(strlen(host) + 1); strcpy(k->host, host);
    k->port   = port;
    k->min_version = 12;
}

void suite_pool(void) {
    zu_pool_config cfg;
    zu_pool_stats  st;
    zu_pool *p;
    zu_pool_key a, b;
    zu_stream *s;

    /* ---- §26.1 the key ---- */

    ZU_CASE("identical settings compare equal (so two clients share a pool)");
    basic_key(&a, "example.com", 443);
    basic_key(&b, "example.com", 443);
    ZU_CHECK_EQ_INT(zu_pool_key_eq(&a, &b), 1);
    zu_pool_key_free(&b);

    /* Every field of §26.1 in turn. If zu_pool_key_eq ever forgets one, the
     * corresponding line here fails — which is the whole point. */
#define DIFFERS(setup) do {                                   \
        ZU_CHECK_EQ_INT(zu_pool_key_copy(&b, &a), 1);         \
        { setup; }                                            \
        ZU_CHECK_EQ_INT(zu_pool_key_eq(&a, &b), 0);           \
        zu_pool_key_free(&b);                                 \
    } while (0)

    ZU_CASE("a different host does not share");
    DIFFERS(zu_free(b.host); b.host = (char *)zu_alloc(9); strcpy(b.host, "evil.com"));
    ZU_CASE("a different port does not share");
    DIFFERS(b.port = 8443);
    ZU_CASE("a different scheme does not share");
    DIFFERS(zu_free(b.scheme); b.scheme = (char *)zu_alloc(5); strcpy(b.scheme, "http"));
    ZU_CASE("a different proxy identity does not share (§20.4)");
    DIFFERS(b.proxy = (char *)zu_alloc(20); strcpy(b.proxy, "http://u:p@px:8080"));
    ZU_CASE("verify_peer off does not share with verify_peer on");
    DIFFERS(b.verify_peer = 0);
    ZU_CASE("verify_hostname off does not share");
    DIFFERS(b.verify_hostname = 0);
    ZU_CASE("a different CA file does not share");
    DIFFERS(b.ca_file = (char *)zu_alloc(9); strcpy(b.ca_file, "/tmp/a.p"));
    ZU_CASE("an additive CA file is not the same as replacing trust (§14.2)");
    DIFFERS(b.ca_extra_file = (char *)zu_alloc(9); strcpy(b.ca_extra_file, "/tmp/b.p"));
    ZU_CASE("different inline CA bytes do not share");
    DIFFERS(b.ca_data_id = (char *)zu_alloc(5); strcpy(b.ca_data_id, "sha1"));
    ZU_CASE("a different pin set does not share (§14.4)");
    DIFFERS(b.pins = (char *)zu_alloc(12); strcpy(b.pins, "sha256//xy"));
    ZU_CASE("a different client certificate does not share");
    DIFFERS(b.client_cert = (char *)zu_alloc(6); strcpy(b.client_cert, "id-42"));
    ZU_CASE("a different minimum TLS version does not share");
    DIFFERS(b.min_version = 13);
    ZU_CASE("a different revocation setting does not share (§14.5)");
    DIFFERS(b.revocation = 1);
    ZU_CASE("a different ALPN does not share");
    DIFFERS(b.alpn = (char *)zu_alloc(9); strcpy(b.alpn, "http/1.1"));
#undef DIFFERS

    ZU_CASE("scheme and host compare case-insensitively");
    ZU_CHECK_EQ_INT(zu_pool_key_copy(&b, &a), 1);
    zu_free(b.host); b.host = (char *)zu_alloc(12); strcpy(b.host, "EXAMPLE.com");
    ZU_CHECK_EQ_INT(zu_pool_key_eq(&a, &b), 1);
    zu_pool_key_free(&b);

    ZU_CASE("an unset field and an empty one are not the same");
    ZU_CHECK_EQ_INT(zu_pool_key_copy(&b, &a), 1);
    b.ca_file = (char *)zu_alloc(1); b.ca_file[0] = '\0';
    ZU_CHECK_EQ_INT(zu_pool_key_eq(&a, &b), 0);
    zu_pool_key_free(&b);

    /* ---- §26.2 reuse and policy ---- */

    zu_pool_config_init(&cfg);
    cfg.idle_timeout_ms = 30000;
    p = zu_pool_new(&cfg);
    ZU_CHECK(p != NULL);
    zu_pool_set_clock(p, fake_now, NULL);

    ZU_CASE("an empty pool misses");
    ZU_CHECK(zu_pool_acquire(p, &a) == NULL);

    ZU_CASE("a released connection is reused for the same key");
    zu_pool_release(p, &a, idle_stream(), ZU_REUSE_OK);
    ZU_CHECK_EQ_INT(zu_pool_idle_count(p), 1);
    s = zu_pool_acquire(p, &a);
    ZU_CHECK(s != NULL);
    ZU_CHECK_EQ_INT(zu_pool_idle_count(p), 0);
    zu_pool_release(p, &a, s, ZU_REUSE_OK);

    ZU_CASE("a connection is NOT reused for a different key");
    basic_key(&b, "other.example", 443);
    ZU_CHECK(zu_pool_acquire(p, &b) == NULL);
    ZU_CHECK_EQ_INT(zu_pool_idle_count(p), 1);   /* still there for key a */
    zu_pool_key_free(&b);

    ZU_CASE("an idle connection past idle_timeout is discarded");
    g_now += 30001;
    ZU_CHECK(zu_pool_acquire(p, &a) == NULL);
    zu_pool_stats_get(p, &st);
    ZU_CHECK_EQ_INT(st.discarded_expired, 1);
    ZU_CHECK_EQ_INT(zu_pool_idle_count(p), 0);

    ZU_CASE("a connection readable before use is stale and discarded (§26.2)");
    {
        zu_stream *stale = idle_stream();
        zu_pool_release(p, &a, stale, ZU_REUSE_OK);
        ZU_CHECK_EQ_INT(zu_pool_idle_count(p), 1);
        /* the peer closed it while it sat idle */
        zu_mock_stream_set_readable(stale, 1, 1);
        ZU_CHECK(zu_pool_acquire(p, &a) == NULL);
        ZU_CHECK_EQ_INT(zu_pool_idle_count(p), 0);
        zu_pool_stats_get(p, &st);
        ZU_CHECK_EQ_INT(st.discarded_stale, 1);
    }

    ZU_CASE("a connection with unread bytes is not pooled at release");
    {
        zu_stream *dirty = idle_stream();
        zu_mock_stream_set_readable(dirty, 1, 1);
        zu_pool_release(p, &a, dirty, ZU_REUSE_OK);
        ZU_CHECK_EQ_INT(zu_pool_idle_count(p), 0);
    }

    /* ---- §26.3 every no-reuse rule closes ---- */

    ZU_CASE("every §26.3 reason closes rather than pools");
    {
        zu_reuse reasons[] = {
            ZU_NOREUSE_BODY_INCOMPLETE, ZU_NOREUSE_CANCELLED,
            ZU_NOREUSE_FRAMING, ZU_NOREUSE_CLOSE_FRAMED,
            ZU_NOREUSE_CONNECTION_CLOSE, ZU_NOREUSE_REDIRECT_BODY,
            ZU_NOREUSE_TLS_ERROR
        };
        size_t i;
        for (i = 0; i < sizeof reasons / sizeof *reasons; i++) {
            zu_pool_release(p, &a, idle_stream(), reasons[i]);
            ZU_CHECK_EQ_INT(zu_pool_idle_count(p), 0);
        }
        zu_pool_stats_get(p, &st);
        ZU_CHECK_EQ_INT(st.discarded_unusable, 7);
    }

    ZU_CASE("every reason has a distinct name for the trace (§42)");
    {
        int i, j, clash = 0;
        for (i = 0; i < ZU_REUSE_REASON_COUNT; i++)
            for (j = i + 1; j < ZU_REUSE_REASON_COUNT; j++)
                if (strcmp(zu_reuse_name((zu_reuse)i), zu_reuse_name((zu_reuse)j)) == 0) clash = 1;
        ZU_CHECK_EQ_INT(clash, 0);
        ZU_CHECK(strcmp(zu_reuse_name((zu_reuse)999), "unknown") == 0);
    }

    /* ---- §26.2 limits ---- */

    ZU_CASE("max_per_host is enforced");
    {
        size_t i;
        for (i = 0; i < 8; i++) zu_pool_release(p, &a, idle_stream(), ZU_REUSE_OK);
        ZU_CHECK_EQ_INT(zu_pool_idle_count(p), cfg.max_per_host);
    }
    zu_pool_clear(p);

    ZU_CASE("max_idle is enforced across hosts");
    {
        size_t i;
        for (i = 0; i < 40; i++) {
            zu_pool_key k;
            char host[32];
            /* 40 distinct hosts, so max_per_host cannot be what caps it */
            snprintf(host, sizeof host, "h%02u.example", (unsigned)i);
            basic_key(&k, host, 443);
            zu_pool_release(p, &k, idle_stream(), ZU_REUSE_OK);
            zu_pool_key_free(&k);
        }
        ZU_CHECK_EQ_INT(zu_pool_idle_count(p), cfg.max_idle);
    }
    zu_pool_clear(p);

    ZU_CASE("max_idle of 0 disables pooling entirely");
    {
        zu_pool_config off;
        zu_pool *q;
        zu_pool_config_init(&off);
        off.max_idle = 0;
        q = zu_pool_new(&off);
        zu_pool_release(q, &a, idle_stream(), ZU_REUSE_OK);
        ZU_CHECK_EQ_INT(zu_pool_idle_count(q), 0);
        zu_pool_free(q);
    }

    /* ---- §26.4 fork guard ---- */

    ZU_CASE("no fork means no drop");
    zu_pool_release(p, &a, idle_stream(), ZU_REUSE_OK);
    ZU_CHECK_EQ_INT(zu_pool_check_fork(p), 0);
    ZU_CHECK_EQ_INT(zu_pool_idle_count(p), 1);

    ZU_CASE("an unarmed guard cannot trip");
    {
        zu_fork_guard g;
        memset(&g, 0, sizeof g);
        ZU_CHECK_EQ_INT(zu_fork_guard_tripped(&g), 0);
    }

    ZU_CASE("an armed guard trips only when the pid differs");
    {
        zu_fork_guard g;
        zu_fork_guard_arm(&g);
        ZU_CHECK_EQ_INT(zu_fork_guard_tripped(&g), 0);
        g.owner_pid = zu_pid_current() + 1;   /* stand in for the child */
        ZU_CHECK_EQ_INT(zu_fork_guard_tripped(&g), 1);
    }

    ZU_CASE("the fork message names the cause and the two safe alternatives");
    {
        const char *m = zu_fork_message();
        ZU_CHECK(strstr(m, "fork()") != NULL);
        ZU_CHECK(strstr(m, "multisession") != NULL);
        ZU_CHECK(strstr(m, "PSOCK") != NULL);
    }

    /* The real thing. Everything above simulates a pid change by writing to
     * the guard; this actually forks, which is the §26.4 hazard-1 regression
     * test. The child cannot report through the harness counters, so it
     * encodes its result in the exit status. */
#if defined(ZU_POSIX)
    ZU_CASE("a real fork() drops inherited connections without a graceful close");
    {
        pid_t kid;
        ZU_CHECK_EQ_INT(zu_pool_idle_count(p), 1);
        kid = fork();
        if (kid == 0) {
            int ok = 1;
            /* Inherited one idle connection from the parent. */
            if (zu_pool_idle_count(p) != 1) ok = 0;
            if (zu_pool_check_fork(p) != 1) ok = 0;      /* fork detected */
            if (zu_pool_idle_count(p) != 0) ok = 0;      /* and dropped */
            {
                zu_pool_stats cst;
                zu_pool_stats_get(p, &cst);
                if (cst.discarded_fork != 1) ok = 0;
                if (cst.forks_detected != 1) ok = 0;
            }
            /* The guard re-armed, so the child owns an empty pool and a
             * second check is a no-op rather than a repeated drop. */
            if (zu_pool_check_fork(p) != 0) ok = 0;
            /* And the child can pool its own connections normally. */
            zu_pool_release(p, &a, idle_stream(), ZU_REUSE_OK);
            if (zu_pool_idle_count(p) != 1) ok = 0;
            _exit(ok ? 0 : 1);
        }
        ZU_CHECK(kid > 0);
        if (kid > 0) {
            int status = -1;
            ZU_CHECK(waitpid(kid, &status, 0) == kid);
            /* Not merely "exit 0": a SIGSEGV here is the R-12 failure mode. */
            ZU_CHECK(WIFEXITED(status));
            ZU_CHECK_EQ_INT(WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
        }
        /* The parent still holds its connection: the child dropped its own
         * copy of the descriptor, not the parent's. */
        ZU_CHECK_EQ_INT(zu_pool_idle_count(p), 1);
    }
#endif
    zu_pool_free(p);

    zu_pool_key_free(&a);

    ZU_CASE("no leaks across the suite");
    {
        zu_alloc_stats end;
        zu_alloc_stats_get(&end);
        ZU_CHECK_EQ_INT(end.live_blocks, 0);
    }
}

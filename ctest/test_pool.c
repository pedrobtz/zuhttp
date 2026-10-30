/* Connection pool — design §26.
 *
 * The pool is deliberately independent of TLS and sockets, so all of this
 * runs on the mock stream with no network (§50.1).
 *
 * The most important test here is the key field walk: §26.1 says a coarse key
 * is a security bug, so rather than trusting zuh_pool_key_eq to be complete,
 * the suite changes every field in turn and asserts the key stops matching.
 */
#include "zuh_test.h"
#include "zuh_pool.h"
#include "zuh_engine.h"
#include "zuh_mock_stream.h"
#include "zuh_alloc.h"
#include <string.h>
#include <stdio.h>
#if defined(ZUH_POSIX)
#  include <unistd.h>
#  include <sys/wait.h>
#endif

void suite_pool(void);

/* A fake clock so idle expiry is testable without sleeping. */
static zuh_millis g_now = 1000;
static zuh_millis fake_now(void *ctx) { ZUH_UNUSED(ctx); return g_now; }

/* An idle, clean connection: the script blocks, so the liveness probe says
 * "nothing waiting", which is what a healthy pooled socket looks like. */
static const zuh_mock_step k_idle[] = { { ZUH_MOCK_WOULDBLOCK, NULL, 0, ZUH_OK } };

static zuh_stream *idle_stream(void) {
    return zuh_mock_stream_new(k_idle, 1, 0, 0);
}

static void basic_key(zuh_pool_key *k, const char *host, uint16_t port) {
    zuh_pool_key_init(k);
    k->scheme = (char *)zuh_alloc(6); strcpy(k->scheme, "https");
    k->host   = (char *)zuh_alloc(strlen(host) + 1); strcpy(k->host, host);
    k->port   = port;
    k->min_version = 12;
}

void suite_pool(void) {
    zuh_pool_config cfg;
    zuh_pool_stats  st;
    zuh_pool *p;
    zuh_pool_key a, b;
    zuh_stream *s;

    /* ---- §26.1 the key ---- */

    ZUH_CASE("identical settings compare equal (so two clients share a pool)");
    basic_key(&a, "example.com", 443);
    basic_key(&b, "example.com", 443);
    ZUH_CHECK_EQ_INT(zuh_pool_key_eq(&a, &b), 1);
    zuh_pool_key_free(&b);

    /* Every field of §26.1 in turn. If zuh_pool_key_eq ever forgets one, the
     * corresponding line here fails — which is the whole point. */
#define DIFFERS(setup) do {                                   \
        ZUH_CHECK_EQ_INT(zuh_pool_key_copy(&b, &a), 1);         \
        { setup; }                                            \
        ZUH_CHECK_EQ_INT(zuh_pool_key_eq(&a, &b), 0);           \
        zuh_pool_key_free(&b);                                 \
    } while (0)

    ZUH_CASE("a different host does not share");
    DIFFERS(zuh_free(b.host); b.host = (char *)zuh_alloc(9); strcpy(b.host, "evil.com"));
    ZUH_CASE("a different port does not share");
    DIFFERS(b.port = 8443);
    ZUH_CASE("a different scheme does not share");
    DIFFERS(zuh_free(b.scheme); b.scheme = (char *)zuh_alloc(5); strcpy(b.scheme, "http"));
    ZUH_CASE("a different proxy identity does not share (§20.4)");
    DIFFERS(b.proxy = (char *)zuh_alloc(20); strcpy(b.proxy, "http://u:p@px:8080"));
    ZUH_CASE("verify_peer off does not share with verify_peer on");
    DIFFERS(b.verify_peer = 0);
    ZUH_CASE("verify_hostname off does not share");
    DIFFERS(b.verify_hostname = 0);
    ZUH_CASE("a different CA file does not share");
    DIFFERS(b.ca_file = (char *)zuh_alloc(9); strcpy(b.ca_file, "/tmp/a.p"));
    ZUH_CASE("an additive CA file is not the same as replacing trust (§14.2)");
    DIFFERS(b.ca_extra_file = (char *)zuh_alloc(9); strcpy(b.ca_extra_file, "/tmp/b.p"));
    ZUH_CASE("different inline CA bytes do not share");
    DIFFERS(b.ca_data_id = (char *)zuh_alloc(5); strcpy(b.ca_data_id, "sha1"));
    ZUH_CASE("a different pin set does not share (§14.4)");
    DIFFERS(b.pins = (char *)zuh_alloc(12); strcpy(b.pins, "sha256//xy"));
    ZUH_CASE("a different client certificate does not share");
    DIFFERS(b.client_cert = (char *)zuh_alloc(6); strcpy(b.client_cert, "id-42"));
    ZUH_CASE("a different minimum TLS version does not share");
    DIFFERS(b.min_version = 13);
    ZUH_CASE("a different revocation setting does not share (§14.5)");
    DIFFERS(b.revocation = 1);
    ZUH_CASE("a different ALPN does not share");
    DIFFERS(b.alpn = (char *)zuh_alloc(9); strcpy(b.alpn, "http/1.1"));
#undef DIFFERS

    /* The comparator is only half of §26.1. zuh_engine_pool_key() decides
     * which settings reach the key at all, and deleting every TLS field from
     * it left this suite green: only network tests would have noticed a
     * pinned request reusing an unpinned connection. Each setting below is
     * changed alone, from a baseline, and must change the key. */
    ZUH_CASE("§26.1: every per-request trust and proxy setting reaches the engine's key");
    {
        zuh_uri u;
        zuh_get_opts o0, o1;
        zuh_tls_config t0, t1;
        zuh_proxy px, px2;
        zuh_error pe;
        zuh_pool_key k0, k1;
        static const char *const pins_ab[] = { "sha256//A", "sha256//B" };
        static const char *const pins_ba[] = { "sha256//B", "sha256//A" };
        int ok;
        static const char url[] = "https://example.com/x";
        ZUH_CHECK_EQ_INT(zuh_uri_parse(&u, url, url + sizeof url - 1), ZUH_OK);
        zuh_get_opts_init(&o0); zuh_tls_config_init(&t0); o0.tls = &t0;
        zuh_proxy_init(&px); zuh_proxy_init(&px2);
        ZUH_CHECK_EQ_INT(zuh_engine_pool_key(&k0, &u, &o0, NULL), 1);
#define KEY_DIFFERS(setup, proxy) do {                                     \
        o1 = o0; t1 = t0; o1.tls = &t1;                                    \
        { setup; }                                                         \
        ok = zuh_engine_pool_key(&k1, &u, &o1, proxy);                     \
        ZUH_CHECK_EQ_INT(ok, 1);                                           \
        if (ok) { ZUH_CHECK_EQ_INT(zuh_pool_key_eq(&k0, &k1), 0); zuh_pool_key_free(&k1); } \
    } while (0)
        /* The baseline is reproducible, or every DIFFERS below is vacuous. */
        o1 = o0; t1 = t0; o1.tls = &t1;
        ZUH_CHECK_EQ_INT(zuh_engine_pool_key(&k1, &u, &o1, NULL), 1);
        ZUH_CHECK_EQ_INT(zuh_pool_key_eq(&k0, &k1), 1);
        zuh_pool_key_free(&k1);

        KEY_DIFFERS(o1.verify = 0, NULL);
        KEY_DIFFERS(o1.ca_file = "/tmp/ca.pem", NULL);
        KEY_DIFFERS(t1.ca_extra_file = "/tmp/extra.pem", NULL);
        KEY_DIFFERS(t1.min_version = 13, NULL);
        KEY_DIFFERS(t1.revocation = 1, NULL);
        KEY_DIFFERS(t1.alpn = "h2", NULL);          /* the default is http/1.1 */
        KEY_DIFFERS((t1.pins = pins_ab, t1.n_pins = 2), NULL);
        ZUH_CHECK_EQ_INT(zuh_proxy_parse(&px, "http://u:p@proxy.test:3128", &pe), ZUH_OK);
        ZUH_CHECK_EQ_INT(zuh_proxy_parse(&px2, "http://u:q@proxy.test:3128", &pe), ZUH_OK);
        KEY_DIFFERS((void)0, &px);
        {   /* pins in a different order, and proxies differing only in the
             * password, are different keys too */
            zuh_pool_key ka, kb;
            o1 = o0; t1 = t0; o1.tls = &t1; t1.pins = pins_ab; t1.n_pins = 2;
            ZUH_CHECK_EQ_INT(zuh_engine_pool_key(&ka, &u, &o1, NULL), 1);
            t1.pins = pins_ba;
            ZUH_CHECK_EQ_INT(zuh_engine_pool_key(&kb, &u, &o1, NULL), 1);
            ZUH_CHECK_EQ_INT(zuh_pool_key_eq(&ka, &kb), 0);
            zuh_pool_key_free(&ka); zuh_pool_key_free(&kb);
            o1 = o0;
            ZUH_CHECK_EQ_INT(zuh_engine_pool_key(&ka, &u, &o1, &px), 1);
            ZUH_CHECK_EQ_INT(zuh_engine_pool_key(&kb, &u, &o1, &px2), 1);
            ZUH_CHECK_EQ_INT(zuh_pool_key_eq(&ka, &kb), 0);
            zuh_pool_key_free(&ka); zuh_pool_key_free(&kb);
        }
#undef KEY_DIFFERS
        zuh_pool_key_free(&k0);
        zuh_proxy_free(&px); zuh_proxy_free(&px2);
        zuh_uri_free(&u);
    }

    ZUH_CASE("scheme and host compare case-insensitively");
    ZUH_CHECK_EQ_INT(zuh_pool_key_copy(&b, &a), 1);
    zuh_free(b.host); b.host = (char *)zuh_alloc(12); strcpy(b.host, "EXAMPLE.com");
    ZUH_CHECK_EQ_INT(zuh_pool_key_eq(&a, &b), 1);
    zuh_pool_key_free(&b);

    ZUH_CASE("an unset field and an empty one are not the same");
    ZUH_CHECK_EQ_INT(zuh_pool_key_copy(&b, &a), 1);
    b.ca_file = (char *)zuh_alloc(1); b.ca_file[0] = '\0';
    ZUH_CHECK_EQ_INT(zuh_pool_key_eq(&a, &b), 0);
    zuh_pool_key_free(&b);

    /* ---- §26.2 reuse and policy ---- */

    zuh_pool_config_init(&cfg);
    cfg.idle_timeout_ms = 30000;
    p = zuh_pool_new(&cfg);
    ZUH_CHECK(p != NULL);
    zuh_pool_set_clock(p, fake_now, NULL);

    ZUH_CASE("an empty pool misses");
    ZUH_CHECK(zuh_pool_acquire(p, &a) == NULL);

    ZUH_CASE("a released connection is reused for the same key");
    zuh_pool_release(p, &a, idle_stream(), ZUH_REUSE_OK);
    ZUH_CHECK_EQ_INT(zuh_pool_idle_count(p), 1);
    s = zuh_pool_acquire(p, &a);
    ZUH_CHECK(s != NULL);
    ZUH_CHECK_EQ_INT(zuh_pool_idle_count(p), 0);
    zuh_pool_release(p, &a, s, ZUH_REUSE_OK);

    ZUH_CASE("a connection is NOT reused for a different key");
    basic_key(&b, "other.example", 443);
    ZUH_CHECK(zuh_pool_acquire(p, &b) == NULL);
    ZUH_CHECK_EQ_INT(zuh_pool_idle_count(p), 1);   /* still there for key a */
    zuh_pool_key_free(&b);

    ZUH_CASE("an idle connection past idle_timeout is discarded");
    g_now += 30001;
    ZUH_CHECK(zuh_pool_acquire(p, &a) == NULL);
    zuh_pool_stats_get(p, &st);
    ZUH_CHECK_EQ_INT(st.discarded_expired, 1);
    ZUH_CHECK_EQ_INT(zuh_pool_idle_count(p), 0);

    ZUH_CASE("a connection readable before use is stale and discarded (§26.2)");
    {
        zuh_stream *stale = idle_stream();
        zuh_pool_release(p, &a, stale, ZUH_REUSE_OK);
        ZUH_CHECK_EQ_INT(zuh_pool_idle_count(p), 1);
        /* the peer closed it while it sat idle */
        zuh_mock_stream_set_readable(stale, 1, 1);
        ZUH_CHECK(zuh_pool_acquire(p, &a) == NULL);
        ZUH_CHECK_EQ_INT(zuh_pool_idle_count(p), 0);
        zuh_pool_stats_get(p, &st);
        ZUH_CHECK_EQ_INT(st.discarded_stale, 1);
    }

    ZUH_CASE("a connection with unread bytes is not pooled at release");
    {
        zuh_stream *dirty = idle_stream();
        zuh_mock_stream_set_readable(dirty, 1, 1);
        zuh_pool_release(p, &a, dirty, ZUH_REUSE_OK);
        ZUH_CHECK_EQ_INT(zuh_pool_idle_count(p), 0);
    }

    /* ---- §26.3 every no-reuse rule closes ---- */

    ZUH_CASE("every §26.3 reason closes rather than pools");
    {
        zuh_reuse reasons[] = {
            ZUH_NOREUSE_BODY_INCOMPLETE, ZUH_NOREUSE_CANCELLED,
            ZUH_NOREUSE_FRAMING, ZUH_NOREUSE_CLOSE_FRAMED,
            ZUH_NOREUSE_CONNECTION_CLOSE, ZUH_NOREUSE_REDIRECT_BODY,
            ZUH_NOREUSE_TLS_ERROR
        };
        size_t i;
        for (i = 0; i < sizeof reasons / sizeof *reasons; i++) {
            zuh_pool_release(p, &a, idle_stream(), reasons[i]);
            ZUH_CHECK_EQ_INT(zuh_pool_idle_count(p), 0);
        }
        zuh_pool_stats_get(p, &st);
        ZUH_CHECK_EQ_INT(st.discarded_unusable, 7);
    }

    ZUH_CASE("every reason has a distinct name for the trace (§42)");
    {
        int i, j, clash = 0;
        for (i = 0; i < ZUH_REUSE_REASON_COUNT; i++)
            for (j = i + 1; j < ZUH_REUSE_REASON_COUNT; j++)
                if (strcmp(zuh_reuse_name((zuh_reuse)i), zuh_reuse_name((zuh_reuse)j)) == 0) clash = 1;
        ZUH_CHECK_EQ_INT(clash, 0);
        ZUH_CHECK(strcmp(zuh_reuse_name((zuh_reuse)999), "unknown") == 0);
    }

    /* ---- §26.2 limits ---- */

    ZUH_CASE("max_per_host is enforced");
    {
        size_t i;
        for (i = 0; i < 8; i++) zuh_pool_release(p, &a, idle_stream(), ZUH_REUSE_OK);
        ZUH_CHECK_EQ_INT(zuh_pool_idle_count(p), cfg.max_per_host);
    }
    zuh_pool_clear(p);

    ZUH_CASE("max_idle is enforced across hosts");
    {
        size_t i;
        for (i = 0; i < 40; i++) {
            zuh_pool_key k;
            char host[32];
            /* 40 distinct hosts, so max_per_host cannot be what caps it */
            snprintf(host, sizeof host, "h%02u.example", (unsigned)i);
            basic_key(&k, host, 443);
            zuh_pool_release(p, &k, idle_stream(), ZUH_REUSE_OK);
            zuh_pool_key_free(&k);
        }
        ZUH_CHECK_EQ_INT(zuh_pool_idle_count(p), cfg.max_idle);
    }
    zuh_pool_clear(p);

    ZUH_CASE("max_idle of 0 disables pooling entirely");
    {
        zuh_pool_config off;
        zuh_pool *q;
        zuh_pool_config_init(&off);
        off.max_idle = 0;
        q = zuh_pool_new(&off);
        zuh_pool_release(q, &a, idle_stream(), ZUH_REUSE_OK);
        ZUH_CHECK_EQ_INT(zuh_pool_idle_count(q), 0);
        zuh_pool_free(q);
    }

    /* ---- §26.4 fork guard ---- */

    ZUH_CASE("no fork means no drop");
    zuh_pool_release(p, &a, idle_stream(), ZUH_REUSE_OK);
    ZUH_CHECK_EQ_INT(zuh_pool_check_fork(p), 0);
    ZUH_CHECK_EQ_INT(zuh_pool_idle_count(p), 1);

    ZUH_CASE("an unarmed guard cannot trip");
    {
        zuh_fork_guard g;
        memset(&g, 0, sizeof g);
        ZUH_CHECK_EQ_INT(zuh_fork_guard_tripped(&g), 0);
    }

    ZUH_CASE("an armed guard trips only when the pid differs");
    {
        zuh_fork_guard g;
        zuh_fork_guard_arm(&g);
        ZUH_CHECK_EQ_INT(zuh_fork_guard_tripped(&g), 0);
        g.owner_pid = zuh_pid_current() + 1;   /* stand in for the child */
        ZUH_CHECK_EQ_INT(zuh_fork_guard_tripped(&g), 1);
    }

    ZUH_CASE("the fork message names the cause and the two safe alternatives");
    {
        const char *m = zuh_fork_message();
        ZUH_CHECK(strstr(m, "fork()") != NULL);
        ZUH_CHECK(strstr(m, "multisession") != NULL);
        ZUH_CHECK(strstr(m, "PSOCK") != NULL);
    }

    /* The real thing. Everything above simulates a pid change by writing to
     * the guard; this actually forks, which is the §26.4 hazard-1 regression
     * test. The child cannot report through the harness counters, so it
     * encodes its result in the exit status. */
#if defined(ZUH_POSIX)
    ZUH_CASE("a real fork() drops inherited connections without a graceful close");
    {
        pid_t kid;
        ZUH_CHECK_EQ_INT(zuh_pool_idle_count(p), 1);
        kid = fork();
        if (kid == 0) {
            /* The child cannot use the harness counters, so it reports the
             * INDEX of the first failed check in its exit status. A single
             * pass/fail bit told us the child failed under valgrind and
             * nothing more, which is not a diagnostic. 0 means all passed. */
            int step = 0;
            zuh_pool_stats cst;

            if (zuh_pool_idle_count(p) != 1)     step = 1;   /* inherited one */
            else if (zuh_pool_check_fork(p) != 1) step = 2;  /* fork detected */
            else if (zuh_pool_idle_count(p) != 0) step = 3;  /* and dropped */
            else {
                zuh_pool_stats_get(p, &cst);
                if (cst.discarded_fork != 1)      step = 4;
                else if (cst.forks_detected != 1) step = 5;
                /* Re-armed, so a second check is a no-op, not a second drop. */
                else if (zuh_pool_check_fork(p) != 0) step = 6;
                else {
                    /* And the child can pool its own connections normally. */
                    zuh_pool_release(p, &a, idle_stream(), ZUH_REUSE_OK);
                    if (zuh_pool_idle_count(p) != 1) step = 7;
                }
            }

            /* Free the child's COPY of the inherited heap before _exit.
             * Without this valgrind follows the fork and reports the parent's
             * still-live allocations as leaked in the child — an artifact of
             * fork, not a defect, but one that hides real findings. Freeing
             * here touches only the child's copy-on-write pages. */
            zuh_pool_free(p);
            zuh_pool_key_free(&a);
            _exit(step);
        }
        ZUH_CHECK(kid > 0);
        if (kid > 0) {
            int status = -1;
            ZUH_CHECK(waitpid(kid, &status, 0) == kid);
            /* Not merely "exit 0": a SIGSEGV here is the R-12 failure mode. */
            ZUH_CHECK(WIFEXITED(status));
            /* A non-zero status names the check that failed, so a failure here
             * is actionable without re-running under a debugger. */
            ZUH_CHECK_EQ_INT(WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
        }
        /* The parent still holds its connection: the child dropped its own
         * copy of the descriptor, not the parent's. */
        ZUH_CHECK_EQ_INT(zuh_pool_idle_count(p), 1);
    }
#endif
    zuh_pool_free(p);

    zuh_pool_key_free(&a);

    /* --- §26.3, the decision itself ------------------------------------
     *
     * zuh_reuse_decide() is the policy the engine applies at the end of every
     * exchange. It lives here rather than in zuh_engine.c precisely so it can
     * be driven directly: the engine would need a server to produce these
     * responses, and half of them are cases a cooperative server never sends.
     */
    {
        zuh_framing ok_len   = { ZUH_FRAME_LENGTH, 5, 1 };
        zuh_framing closed   = { ZUH_FRAME_UNTIL_CLOSE, 0, 0 };
        zuh_headers h;

        ZUH_CASE("§26.3: a clean length-framed HTTP/1.1 response is reusable");
        zuh_headers_init(&h);
        ZUH_CHECK_EQ_INT(zuh_reuse_decide(ZUH_OK, &ok_len, &h, 1), ZUH_REUSE_OK);

        ZUH_CASE("§26.3: close-framed is never reusable");
        ZUH_CHECK_EQ_INT(zuh_reuse_decide(ZUH_OK, &closed, &h, 1),
                        ZUH_NOREUSE_CLOSE_FRAMED);

        ZUH_CASE("§26.3: HTTP/1.0 is not persistent unless the server opts in");
        ZUH_CHECK_EQ_INT(zuh_reuse_decide(ZUH_OK, &ok_len, &h, 0),
                        ZUH_NOREUSE_CONNECTION_CLOSE);
        zuh_headers_free(&h);

        ZUH_CASE("§26.3: HTTP/1.0 WITH keep-alive is reusable");
        zuh_headers_init(&h);
        zuh_headers_add_str(&h, "Connection", "keep-alive");
        ZUH_CHECK_EQ_INT(zuh_reuse_decide(ZUH_OK, &ok_len, &h, 0), ZUH_REUSE_OK);
        zuh_headers_free(&h);

        /* The bug this replaced: an exact-match test on the whole field value
         * reads every one of these as "not close" and pools the connection. */
        ZUH_CASE("§26.3: Connection is a token LIST, not a single value");
        {
            static const char *closing[] = {
                "close", "Close", "CLOSE", "keep-alive, close",
                "close, keep-alive", "Upgrade, close", " close ",
                "TE,close", "keep-alive,  Close", NULL
            };
            int i;
            for (i = 0; closing[i]; i++) {
                zuh_headers_init(&h);
                zuh_headers_add_str(&h, "Connection", closing[i]);
                ZUH_CHECK_EQ_INT(zuh_reuse_decide(ZUH_OK, &ok_len, &h, 1),
                                ZUH_NOREUSE_CONNECTION_CLOSE);
                zuh_headers_free(&h);
            }
        }

        ZUH_CASE("§26.3: a token merely CONTAINING \"close\" is not the close token");
        {
            static const char *fine[] = { "keep-alive", "closed", "disclose",
                                          "close-ish", "x-close", NULL };
            int i;
            for (i = 0; fine[i]; i++) {
                zuh_headers_init(&h);
                zuh_headers_add_str(&h, "Connection", fine[i]);
                ZUH_CHECK_EQ_INT(zuh_reuse_decide(ZUH_OK, &ok_len, &h, 1), ZUH_REUSE_OK);
                zuh_headers_free(&h);
            }
        }

        ZUH_CASE("§26.3: a second Connection header is read too");
        zuh_headers_init(&h);
        zuh_headers_add_str(&h, "Connection", "keep-alive");
        zuh_headers_add_str(&h, "Connection", "close");
        ZUH_CHECK_EQ_INT(zuh_reuse_decide(ZUH_OK, &ok_len, &h, 1),
                        ZUH_NOREUSE_CONNECTION_CLOSE);
        zuh_headers_free(&h);

        ZUH_CASE("§26.3: a failed request names WHY it cannot be reused");
        zuh_headers_init(&h);
        ZUH_CHECK_EQ_INT(zuh_reuse_decide(ZUH_ERR_TIMEOUT, &ok_len, &h, 1),
                        ZUH_NOREUSE_CANCELLED);
        ZUH_CHECK_EQ_INT(zuh_reuse_decide(ZUH_ERR_INTERRUPTED, &ok_len, &h, 1),
                        ZUH_NOREUSE_CANCELLED);
        ZUH_CHECK_EQ_INT(zuh_reuse_decide(ZUH_ERR_PARSE, &ok_len, &h, 1),
                        ZUH_NOREUSE_FRAMING);
        ZUH_CHECK_EQ_INT(zuh_reuse_decide(ZUH_ERR_TLS_CERT, &ok_len, &h, 1),
                        ZUH_NOREUSE_TLS_ERROR);
        ZUH_CHECK_EQ_INT(zuh_reuse_decide(ZUH_ERR_IO, &ok_len, &h, 1),
                        ZUH_NOREUSE_BODY_INCOMPLETE);
        /* An error outranks a clean framing: the body did not arrive, so the
         * framing that would have described it is irrelevant. */
        ZUH_CHECK_EQ_INT(zuh_reuse_decide(ZUH_ERR_TIMEOUT, &closed, &h, 1),
                        ZUH_NOREUSE_CANCELLED);
        zuh_headers_free(&h);
    }

    ZUH_CASE("no leaks across the suite");
    {
        zuh_alloc_stats end;
        zuh_alloc_stats_get(&end);
        ZUH_CHECK_EQ_INT(end.live_blocks, 0);
    }
}

/* Same feature-test requirement as zuh_net.c: glibc hides the POSIX socket
 * API under -std=c99 without it. Must precede every system header. */
#if !defined(_WIN32)
#  if defined(__APPLE__)
#    define _DARWIN_C_SOURCE
#  else
#    define _POSIX_C_SOURCE 200112L
#  endif
#endif

#include "zuh_test.h"
#include "zuh_net.h"
#include "zuh_alloc.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>   /* getenv */

#if defined(ZUH_WINDOWS)
#  include <winsock2.h>
#  include <ws2tcpip.h>
   typedef SOCKET tsock;
#  define TCLOSE closesocket
#  define TINVALID INVALID_SOCKET
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#  include <poll.h>
   typedef int tsock;
#  define TCLOSE close
#  define TINVALID (-1)
#endif

void suite_net(void);

/* A loopback listener on an ephemeral port, so tests need no fixed port and
 * no external network. */
static tsock listen_on(uint16_t *port_out) {
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    tsock ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls == TINVALID) return TINVALID;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;                                  /* kernel picks */
    if (bind(ls, (struct sockaddr *)&a, sizeof a) != 0) { TCLOSE(ls); return TINVALID; }
    if (listen(ls, 4) != 0) { TCLOSE(ls); return TINVALID; }
    if (getsockname(ls, (struct sockaddr *)&a, &al) != 0) { TCLOSE(ls); return TINVALID; }
    *port_out = ntohs(a.sin_port);
    return ls;
}

/* accept() with a bound.
 *
 * The listener is a BLOCKING socket, so a bare accept() waits forever when
 * nothing connects — and ZUH_CHECK records a failure and CONTINUES, so a
 * failed zuh_net_connect() above turns the next accept() into an infinite
 * block. That is exactly how the Linux c-core job hung for an hour: the
 * assertion failure was printed into a block-buffered stdout that never
 * flushed, and the suite stopped dead at the accept().
 *
 * A test may fail. A test may not hang. */
static tsock accept_bounded(tsock ls, int timeout_ms) {
#if defined(ZUH_WINDOWS)
    fd_set rf;
    struct timeval tv;
    FD_ZERO(&rf);
    FD_SET(ls, &rf);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (select(0, &rf, NULL, NULL, &tv) <= 0) return TINVALID;
#else
    struct pollfd p;
    p.fd = ls;
    p.events = POLLIN;
    p.revents = 0;
    if (poll(&p, 1, timeout_ms) <= 0) return TINVALID;
#endif
    return accept(ls, NULL, NULL);
}

/* Tick callback that cancels after N calls, and counts them. */
typedef struct { int calls; int cancel_at; } ticker;
static int tick_cb(void *ctx) {
    ticker *t = (ticker *)ctx;
    t->calls++;
    return t->cancel_at > 0 && t->calls >= t->cancel_at;
}

void suite_net(void) {
    zuh_net_opts o;
    zuh_error e;
    zuh_stream *s = NULL;

    ZUH_CHECK_EQ_INT(zuh_net_init(), ZUH_OK);
    zuh_net_opts_init(&o);
    o.tick_ms = 20;

    ZUH_CASE("loopback round-trip through the zu_stream interface");
    {
        uint16_t port = 0;
        tsock ls = listen_on(&port);
        tsock conn;
        char buf[64];
        zuh_deadline d = zuh_deadline_in(5000);
        ZUH_CHECK(ls != TINVALID);
        zuh_error_clear(&e);

        ZUH_CHECK_EQ_INT(zuh_net_connect(&s, "127.0.0.1", port, d, &o, &e), ZUH_OK);
        conn = accept_bounded(ls, 2000);
        ZUH_CHECK(conn != TINVALID);

        ZUH_CHECK(zuh_stream_write_all(s, "PING", 4, d, &e));
        {
            int n = (int)recv(conn, buf, 4, 0);
            ZUH_CHECK_EQ_INT(n, 4);
            ZUH_CHECK_MEM(buf, "PING", 4);
            send(conn, "PONG", 4, 0);
        }
        {
            zuh_ssize n = zuh_stream_read(s, buf, sizeof buf, d, &e);
            ZUH_CHECK_EQ_INT(n, 4);
            ZUH_CHECK_MEM(buf, "PONG", 4);
        }

        ZUH_CASE("§35.2: the peer address is recorded");
        {
            char ip[64];
            ZUH_CHECK(zuh_net_peer_ip(s, ip, sizeof ip));
            ZUH_CHECK(strcmp(ip, "127.0.0.1") == 0);
        }

        ZUH_CASE("an orderly close reads as 0, not as an error");
        TCLOSE(conn);
        {
            zuh_ssize n = zuh_stream_read(s, buf, sizeof buf, d, &e);
            ZUH_CHECK_EQ_INT(n, 0);
        }

        zuh_net_stream_free(s); s = NULL;
        TCLOSE(ls);
    }

    ZUH_CASE("a refused connection is zu_connect_error, not a hang");
    {
        uint16_t port = 0;
        tsock ls = listen_on(&port);
        zuh_deadline d = zuh_deadline_in(5000);
        TCLOSE(ls);                       /* nothing is listening now */
        zuh_error_clear(&e);
        ZUH_CHECK_EQ_INT(zuh_net_connect(&s, "127.0.0.1", port, d, &o, &e), ZUH_ERR_CONNECT);
        ZUH_CHECK_EQ_INT(e.phase, ZUH_PHASE_CONNECT);
        ZUH_CHECK(s == NULL);
    }

    /* This one needs a RESOLVER, which makes it a network test, and the
     * c-core suite is meant to be deterministic and offline. Worse, the
     * deadline cannot bound it: getaddrinfo() is not interruptible (D-30), so
     * on a host whose resolver blackholes the query this blocks forever
     * rather than failing. That is exactly what happened — the Linux c-core
     * jobs sat for an hour on it while macOS and Windows passed.
     *
     * Opt in with ZU_TEST_DNS=1; the network-enabled workflow sets it. */
    if (getenv("ZU_TEST_DNS")) {
        ZUH_CASE("an unresolvable host is zu_dns_error in the dns phase");
        {
            zuh_deadline d = zuh_deadline_in(5000);
            zuh_error_clear(&e);
            ZUH_CHECK_EQ_INT(zuh_net_connect(&s, "invalid.invalid.", 80, d, &o, &e), ZUH_ERR_DNS);
            ZUH_CHECK_EQ_INT(e.phase, ZUH_PHASE_DNS);
        }
    }

    /* §24: a stalled read must end at the deadline rather than blocking. */
    ZUH_CASE("§24: a read deadline fires on a connection that sends nothing");
    {
        uint16_t port = 0;
        tsock ls = listen_on(&port);
        tsock conn;
        char buf[16];
        zuh_deadline connd = zuh_deadline_in(5000);
        zuh_millis t0, elapsed;
        ZUH_CHECK(ls != TINVALID);
        zuh_error_clear(&e);
        ZUH_CHECK_EQ_INT(zuh_net_connect(&s, "127.0.0.1", port, connd, &o, &e), ZUH_OK);
        conn = accept_bounded(ls, 2000);    /* accept, then stay silent */
        ZUH_CHECK(conn != TINVALID);

        t0 = zuh_now_ms();
        {
            zuh_deadline rd = zuh_deadline_in(150);
            zuh_ssize n = zuh_stream_read(s, buf, sizeof buf, rd, &e);
            elapsed = zuh_now_ms() - t0;
            ZUH_CHECK_EQ_INT(n, -1);
            ZUH_CHECK_EQ_INT(e.code, ZUH_ERR_TIMEOUT);
            ZUH_CHECK_EQ_INT(e.phase, ZUH_PHASE_READ);
        }
        ZUH_CHECK(elapsed >= 100);            /* waited for the deadline */
        ZUH_CHECK(elapsed < 3000);            /* but did not hang */

        zuh_net_stream_free(s); s = NULL;
        TCLOSE(conn); TCLOSE(ls);
    }

    /* §25.1: the checkpoint is where R_CheckUserInterrupt() will live. */
    ZUH_CASE("§25.1: the tick callback fires at the configured cadence");
    {
        uint16_t port = 0;
        tsock ls = listen_on(&port);
        tsock conn;
        char buf[16];
        ticker t;
        zuh_net_opts to;
        zuh_deadline connd = zuh_deadline_in(5000);
        ZUH_CHECK(ls != TINVALID);
        zuh_net_opts_init(&to);
        to.tick_ms = 20;
        memset(&t, 0, sizeof t);
        to.tick = tick_cb; to.tick_ctx = &t;

        zuh_error_clear(&e);
        ZUH_CHECK_EQ_INT(zuh_net_connect(&s, "127.0.0.1", port, connd, &to, &e), ZUH_OK);
        conn = accept_bounded(ls, 2000);
        ZUH_CHECK(conn != TINVALID);

        {
            zuh_deadline rd = zuh_deadline_in(200);
            zuh_stream_read(s, buf, sizeof buf, rd, &e);
        }
        /* ~200ms of waiting at a 20ms tick must yield several checkpoints. */
        ZUH_CHECK(t.calls >= 4);

        zuh_net_stream_free(s); s = NULL;
        TCLOSE(conn); TCLOSE(ls);
    }

    ZUH_CASE("§25: the tick callback can cancel a stalled read");
    {
        uint16_t port = 0;
        tsock ls = listen_on(&port);
        tsock conn;
        char buf[16];
        ticker t;
        zuh_net_opts to;
        zuh_deadline connd = zuh_deadline_in(5000);
        ZUH_CHECK(ls != TINVALID);
        zuh_net_opts_init(&to);
        to.tick_ms = 10;
        memset(&t, 0, sizeof t);
        t.cancel_at = 3;                    /* cancel on the 3rd checkpoint */
        to.tick = tick_cb; to.tick_ctx = &t;

        zuh_error_clear(&e);
        ZUH_CHECK_EQ_INT(zuh_net_connect(&s, "127.0.0.1", port, connd, &to, &e), ZUH_OK);
        conn = accept_bounded(ls, 2000);
        ZUH_CHECK(conn != TINVALID);

        {
            /* A deadline far in the future: only the callback can stop this. */
            zuh_deadline rd = zuh_deadline_in(30000);
            zuh_ssize n = zuh_stream_read(s, buf, sizeof buf, rd, &e);
            ZUH_CHECK_EQ_INT(n, -1);
            ZUH_CHECK_EQ_INT(e.code, ZUH_ERR_CANCELLED);
        }
        ZUH_CHECK_EQ_INT(t.calls, 3);

        zuh_net_stream_free(s); s = NULL;
        TCLOSE(conn); TCLOSE(ls);
    }

    ZUH_CASE("no leaks across the suite");
    {
        zuh_alloc_stats st;
        zuh_alloc_stats_get(&st);
        ZUH_CHECK_EQ_INT(st.live_blocks, 0);
    }
}

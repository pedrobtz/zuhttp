#include "zu_test.h"
#include "zu_net.h"
#include "zu_alloc.h"
#include <string.h>
#include <stdio.h>

#if defined(ZU_WINDOWS)
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

/* Tick callback that cancels after N calls, and counts them. */
typedef struct { int calls; int cancel_at; } ticker;
static int tick_cb(void *ctx) {
    ticker *t = (ticker *)ctx;
    t->calls++;
    return t->cancel_at > 0 && t->calls >= t->cancel_at;
}

void suite_net(void) {
    zu_net_opts o;
    zu_error e;
    zu_stream *s = NULL;

    ZU_CHECK_EQ_INT(zu_net_init(), ZU_OK);
    zu_net_opts_init(&o);
    o.tick_ms = 20;

    ZU_CASE("loopback round-trip through the zu_stream interface");
    {
        uint16_t port = 0;
        tsock ls = listen_on(&port);
        tsock conn;
        char buf[64];
        zu_deadline d = zu_deadline_in(5000);
        ZU_CHECK(ls != TINVALID);
        zu_error_clear(&e);

        ZU_CHECK_EQ_INT(zu_net_connect(&s, "127.0.0.1", port, d, &o, &e), ZU_OK);
        conn = accept(ls, NULL, NULL);
        ZU_CHECK(conn != TINVALID);

        ZU_CHECK(zu_stream_write_all(s, "PING", 4, d, &e));
        {
            int n = (int)recv(conn, buf, 4, 0);
            ZU_CHECK_EQ_INT(n, 4);
            ZU_CHECK_MEM(buf, "PING", 4);
            send(conn, "PONG", 4, 0);
        }
        {
            zu_ssize n = zu_stream_read(s, buf, sizeof buf, d, &e);
            ZU_CHECK_EQ_INT(n, 4);
            ZU_CHECK_MEM(buf, "PONG", 4);
        }

        ZU_CASE("§35.2: the peer address is recorded");
        {
            char ip[64];
            ZU_CHECK(zu_net_peer_ip(s, ip, sizeof ip));
            ZU_CHECK(strcmp(ip, "127.0.0.1") == 0);
        }

        ZU_CASE("an orderly close reads as 0, not as an error");
        TCLOSE(conn);
        {
            zu_ssize n = zu_stream_read(s, buf, sizeof buf, d, &e);
            ZU_CHECK_EQ_INT(n, 0);
        }

        zu_net_stream_free(s); s = NULL;
        TCLOSE(ls);
    }

    ZU_CASE("a refused connection is zu_connect_error, not a hang");
    {
        uint16_t port = 0;
        tsock ls = listen_on(&port);
        zu_deadline d = zu_deadline_in(5000);
        TCLOSE(ls);                       /* nothing is listening now */
        zu_error_clear(&e);
        ZU_CHECK_EQ_INT(zu_net_connect(&s, "127.0.0.1", port, d, &o, &e), ZU_ERR_CONNECT);
        ZU_CHECK_EQ_INT(e.phase, ZU_PHASE_CONNECT);
        ZU_CHECK(s == NULL);
    }

    ZU_CASE("an unresolvable host is zu_dns_error in the dns phase");
    {
        zu_deadline d = zu_deadline_in(5000);
        zu_error_clear(&e);
        ZU_CHECK_EQ_INT(zu_net_connect(&s, "invalid.invalid.", 80, d, &o, &e), ZU_ERR_DNS);
        ZU_CHECK_EQ_INT(e.phase, ZU_PHASE_DNS);
    }

    /* §24: a stalled read must end at the deadline rather than blocking. */
    ZU_CASE("§24: a read deadline fires on a connection that sends nothing");
    {
        uint16_t port = 0;
        tsock ls = listen_on(&port);
        tsock conn;
        char buf[16];
        zu_deadline connd = zu_deadline_in(5000);
        zu_millis t0, elapsed;
        ZU_CHECK(ls != TINVALID);
        zu_error_clear(&e);
        ZU_CHECK_EQ_INT(zu_net_connect(&s, "127.0.0.1", port, connd, &o, &e), ZU_OK);
        conn = accept(ls, NULL, NULL);      /* accept, then stay silent */

        t0 = zu_now_ms();
        {
            zu_deadline rd = zu_deadline_in(150);
            zu_ssize n = zu_stream_read(s, buf, sizeof buf, rd, &e);
            elapsed = zu_now_ms() - t0;
            ZU_CHECK_EQ_INT(n, -1);
            ZU_CHECK_EQ_INT(e.code, ZU_ERR_TIMEOUT);
            ZU_CHECK_EQ_INT(e.phase, ZU_PHASE_READ);
        }
        ZU_CHECK(elapsed >= 100);            /* waited for the deadline */
        ZU_CHECK(elapsed < 3000);            /* but did not hang */

        zu_net_stream_free(s); s = NULL;
        TCLOSE(conn); TCLOSE(ls);
    }

    /* §25.1: the checkpoint is where R_CheckUserInterrupt() will live. */
    ZU_CASE("§25.1: the tick callback fires at the configured cadence");
    {
        uint16_t port = 0;
        tsock ls = listen_on(&port);
        tsock conn;
        char buf[16];
        ticker t;
        zu_net_opts to;
        zu_deadline connd = zu_deadline_in(5000);
        ZU_CHECK(ls != TINVALID);
        zu_net_opts_init(&to);
        to.tick_ms = 20;
        memset(&t, 0, sizeof t);
        to.tick = tick_cb; to.tick_ctx = &t;

        zu_error_clear(&e);
        ZU_CHECK_EQ_INT(zu_net_connect(&s, "127.0.0.1", port, connd, &to, &e), ZU_OK);
        conn = accept(ls, NULL, NULL);

        {
            zu_deadline rd = zu_deadline_in(200);
            zu_stream_read(s, buf, sizeof buf, rd, &e);
        }
        /* ~200ms of waiting at a 20ms tick must yield several checkpoints. */
        ZU_CHECK(t.calls >= 4);

        zu_net_stream_free(s); s = NULL;
        TCLOSE(conn); TCLOSE(ls);
    }

    ZU_CASE("§25: the tick callback can cancel a stalled read");
    {
        uint16_t port = 0;
        tsock ls = listen_on(&port);
        tsock conn;
        char buf[16];
        ticker t;
        zu_net_opts to;
        zu_deadline connd = zu_deadline_in(5000);
        ZU_CHECK(ls != TINVALID);
        zu_net_opts_init(&to);
        to.tick_ms = 10;
        memset(&t, 0, sizeof t);
        t.cancel_at = 3;                    /* cancel on the 3rd checkpoint */
        to.tick = tick_cb; to.tick_ctx = &t;

        zu_error_clear(&e);
        ZU_CHECK_EQ_INT(zu_net_connect(&s, "127.0.0.1", port, connd, &to, &e), ZU_OK);
        conn = accept(ls, NULL, NULL);

        {
            /* A deadline far in the future: only the callback can stop this. */
            zu_deadline rd = zu_deadline_in(30000);
            zu_ssize n = zu_stream_read(s, buf, sizeof buf, rd, &e);
            ZU_CHECK_EQ_INT(n, -1);
            ZU_CHECK_EQ_INT(e.code, ZU_ERR_CANCELLED);
        }
        ZU_CHECK_EQ_INT(t.calls, 3);

        zu_net_stream_free(s); s = NULL;
        TCLOSE(conn); TCLOSE(ls);
    }

    ZU_CASE("no leaks across the suite");
    {
        zu_alloc_stats st;
        zu_alloc_stats_get(&st);
        ZU_CHECK_EQ_INT(st.live_blocks, 0);
    }
}

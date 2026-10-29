/* Feature-test macros MUST precede every system header.
 *
 * -std=c99 defines __STRICT_ANSI__, under which glibc hides the POSIX
 * networking API: struct addrinfo, getnameinfo() and NI_NUMERICHOST are all
 * invisible without this. Darwin exposes them regardless, which is exactly why
 * this built on macOS and failed on Linux. */
#if !defined(_WIN32)
#  if defined(__APPLE__)
#    define _DARWIN_C_SOURCE
#  else
#    define _POSIX_C_SOURCE 200112L
#  endif
#endif

#include "zuh_net.h"
#include "zuh_alloc.h"
#include <string.h>
#include <stdio.h>

/* ---- platform shims, confined to this file (§10, §28) ---- */
#if defined(ZUH_WINDOWS)
#  include <winsock2.h>
#  include <ws2tcpip.h>
   typedef SOCKET zuh_sock;
#  define ZUH_INVALID_SOCK INVALID_SOCKET
#  define zuh_closesocket  closesocket
#  define zuh_poll         WSAPoll
#  define ZUH_EWOULDBLOCK  WSAEWOULDBLOCK
#  define ZUH_EINPROGRESS  WSAEWOULDBLOCK
#  define ZUH_EINTR        WSAEINTR
static int sock_errno(void) { return WSAGetLastError(); }
static int set_nonblocking(zuh_sock s) {
    u_long on = 1;
    /* FIONBIO expands to 0x8004667E (unsigned), but ioctlsocket takes a signed
     * long, so the conversion changes the value. The cast is explicit rather
     * than silencing the warning, because the bit pattern is what matters. */
    return ioctlsocket(s, (long)FIONBIO, &on) == 0;
}
#else
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <unistd.h>
#  include <fcntl.h>
#  include <poll.h>
#  include <errno.h>
   typedef int zuh_sock;
#  define ZUH_INVALID_SOCK (-1)
#  define zuh_closesocket  close
#  define zuh_poll         poll
#  define ZUH_EWOULDBLOCK  EWOULDBLOCK
#  define ZUH_EINPROGRESS  EINPROGRESS
#  define ZUH_EINTR        EINTR
static int sock_errno(void) { return errno; }
static int set_nonblocking(zuh_sock s) {
    int fl = fcntl(s, F_GETFL, 0);
    return fl != -1 && fcntl(s, F_SETFL, fl | O_NONBLOCK) == 0;
}
#endif

typedef struct {
    zuh_sock     fd;
    zuh_net_opts opts;
    char        peer[64];
} net_impl;

zuh_code zuh_net_init(void) {
#if defined(ZUH_WINDOWS)
    static int done = 0;
    WSADATA wsa;
    if (done) return ZUH_OK;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return ZUH_ERR_IO;
    done = 1;
#endif
    return ZUH_OK;
}

void zuh_net_shutdown(void) {
#if defined(ZUH_WINDOWS)
    /* Deliberately not calling WSACleanup: another package in the same R
     * process may still be using Winsock, and the counts are process-wide. */
#endif
}

void zuh_net_opts_init(zuh_net_opts *o) {
    memset(o, 0, sizeof *o);
    o->tick_ms = 100;
}

/* One bounded wait. §25.1: never block longer than a tick without giving the
 * caller a chance to cancel. */
static zuh_code wait_ready(net_impl *m, int want_write, zuh_deadline d, zuh_error *err) {
#if defined(ZUH_WINDOWS)
    WSAPOLLFD p;
#else
    struct pollfd p;
#endif
    for (;;) {
        int ms, rc;

        if (m->opts.tick && m->opts.tick(m->opts.tick_ctx)) {
            zuh_error_set(err, ZUH_ERR_CANCELLED, ZUH_PHASE_NONE, "operation cancelled");
            return ZUH_ERR_CANCELLED;
        }
        if (zuh_deadline_expired(d)) {
            zuh_error_set(err, ZUH_ERR_TIMEOUT, ZUH_PHASE_NONE, "deadline exceeded");
            return ZUH_ERR_TIMEOUT;
        }

        memset(&p, 0, sizeof p);
        p.fd = m->fd;
        p.events = (short)(want_write ? POLLOUT : POLLIN);

        ms = zuh_deadline_poll_ms(d, m->opts.tick_ms > 0 ? m->opts.tick_ms : 100);
        rc = zuh_poll(&p, 1, ms);

        if (rc > 0) return ZUH_OK;
        if (rc == 0) continue;                      /* tick expired; loop */
        if (sock_errno() == ZUH_EINTR) continue;
        zuh_error_set(err, ZUH_ERR_IO, ZUH_PHASE_NONE, "poll failed (%d)", sock_errno());
        return ZUH_ERR_IO;
    }
}

static zuh_ssize net_read(zuh_stream *s, void *buf, size_t n, zuh_deadline d, zuh_error *err) {
    net_impl *m = (net_impl *)s->impl;
    for (;;) {
        zuh_ssize r;
        zuh_code rc;
#if defined(ZUH_WINDOWS)
        int rn = recv(m->fd, (char *)buf, (int)(n > INT_MAX ? INT_MAX : n), 0);
        r = rn;
#else
        r = recv(m->fd, buf, n, 0);
#endif
        if (r >= 0) return r;                        /* 0 == orderly close */
        if (sock_errno() == ZUH_EINTR) continue;
        if (sock_errno() != ZUH_EWOULDBLOCK) {
            zuh_error_set(err, ZUH_ERR_IO, ZUH_PHASE_READ, "read failed (%d)", sock_errno());
            return -1;
        }
        rc = wait_ready(m, 0, d, err);
        if (rc != ZUH_OK) { if (err) err->phase = ZUH_PHASE_READ; return -1; }
    }
}

static zuh_ssize net_write(zuh_stream *s, const void *buf, size_t n, zuh_deadline d, zuh_error *err) {
    net_impl *m = (net_impl *)s->impl;
    for (;;) {
        zuh_ssize w;
        zuh_code rc;
#if defined(ZUH_WINDOWS)
        int wn = send(m->fd, (const char *)buf, (int)(n > INT_MAX ? INT_MAX : n), 0);
        w = wn;
#else
        w = send(m->fd, buf, n, 0);
#endif
        if (w >= 0) return w;
        if (sock_errno() == ZUH_EINTR) continue;
        if (sock_errno() != ZUH_EWOULDBLOCK) {
            zuh_error_set(err, ZUH_ERR_IO, ZUH_PHASE_WRITE, "write failed (%d)", sock_errno());
            return -1;
        }
        rc = wait_ready(m, 1, d, err);
        if (rc != ZUH_OK) { if (err) err->phase = ZUH_PHASE_WRITE; return -1; }
    }
}

static void net_close(zuh_stream *s) {
    net_impl *m = (net_impl *)s->impl;
    if (m && m->fd != ZUH_INVALID_SOCK) {
        zuh_closesocket(m->fd);
        m->fd = ZUH_INVALID_SOCK;
    }
}

static void net_destroy(zuh_stream *s);

/* §26.2 stale detection. POLLIN fires for readable data, a peer FIN, and an
 * error alike — all three mean "do not reuse", so they need no separation
 * here. Deliberately does NOT read: consuming a byte would corrupt the next
 * response if the connection turned out to be fine. */
static int net_readable(zuh_stream *s, int timeout_ms) {
    net_impl *m;
    struct pollfd p;
    int rc;
    if (!s || !s->impl) return -1;
    m = (net_impl *)s->impl;
    if (m->fd == ZUH_INVALID_SOCK) return 1;   /* closed counts as "do not reuse" */
    p.fd = m->fd;
    p.events = POLLIN;
    p.revents = 0;
    /* A negative timeout means "block forever" to poll(). This is a liveness
     * PROBE — blocking is never the right answer, and an unbounded one here
     * would hang the pool rather than report a stale connection. */
    if (timeout_ms < 0) timeout_ms = 0;
    do {
        rc = zuh_poll(&p, 1, timeout_ms);
    } while (rc < 0 && sock_errno() == ZUH_EINTR);
    if (rc < 0) return -1;
    return rc > 0 ? 1 : 0;
}

static const zuh_stream_vtable k_net_vt = {
    "tcp", net_read, net_write, net_close, net_destroy, net_readable
};

static void net_destroy(zuh_stream *s) {
    if (!s) return;
    net_close(s);
    zuh_free(s->impl);
    zuh_free(s);
}

static void record_peer(net_impl *m, const struct addrinfo *ai) {
    char host[64];
    m->peer[0] = '\0';
    if (getnameinfo(ai->ai_addr, (socklen_t)ai->ai_addrlen, host, sizeof host,
                    NULL, 0, NI_NUMERICHOST) == 0) {
        strncpy(m->peer, host, sizeof m->peer - 1);
        m->peer[sizeof m->peer - 1] = '\0';
    }
}

zuh_code zuh_net_connect(zuh_stream **out, const char *host, uint16_t port,
                       zuh_deadline deadline, const zuh_net_opts *opts,
                       zuh_error *err) {
    struct addrinfo hints, *res = NULL, *ai;
    char portstr[8];
    zuh_stream *st = NULL;
    net_impl *m = NULL;
    zuh_code last = ZUH_ERR_CONNECT;
    int gai;
    zuh_millis t_dns, t_conn = 0;

    if (!out || !host) return ZUH_ERR_PARSE;
    *out = NULL;
    if (zuh_net_init() != ZUH_OK) {
        zuh_error_set(err, ZUH_ERR_IO, ZUH_PHASE_CONNECT, "network stack unavailable");
        return ZUH_ERR_IO;
    }

    snprintf(portstr, sizeof portstr, "%u", (unsigned)port);
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;          /* §3.1: IPv4 and IPv6 */
    hints.ai_socktype = SOCK_STREAM;

    /* Synchronous and uninterruptible — see the header note and §25.4. That
     * is exactly why it is worth timing: a request that appears to hang here
     * is not hung, it is in a resolver call zuhttp cannot cancel, and the
     * trace is the only way to tell those apart. */
    zuh_trace_add(opts ? opts->trace : NULL, ZUH_EV_DNS_START, host, 0);
    t_dns = zuh_now_ms();
    gai = getaddrinfo(host, portstr, &hints, &res);
    if (opts && opts->timings)
        opts->timings->dns = (long)(zuh_now_ms() - t_dns);
    if (gai != 0 || !res) {
        zuh_error_set(err, ZUH_ERR_DNS, ZUH_PHASE_DNS, "cannot resolve '%s'", host);
        return ZUH_ERR_DNS;
    }
    zuh_trace_add(opts ? opts->trace : NULL, ZUH_EV_DNS_DONE, host, 0);
    t_conn = zuh_now_ms();

    st = (zuh_stream *)zuh_calloc(1, sizeof *st);
    m  = (net_impl *)zuh_calloc(1, sizeof *m);
    if (!st || !m) { zuh_free(st); zuh_free(m); freeaddrinfo(res); return ZUH_ERR_NOMEM; }
    m->fd = ZUH_INVALID_SOCK;
    if (opts) m->opts = *opts; else zuh_net_opts_init(&m->opts);
    if (m->opts.tick_ms <= 0) m->opts.tick_ms = 100;

    for (ai = res; ai; ai = ai->ai_next) {
        int one = 1;
        zuh_sock fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == ZUH_INVALID_SOCK) continue;
        if (!set_nonblocking(fd)) { zuh_closesocket(fd); continue; }
        /* Per candidate address, not once: getaddrinfo returns a list and
         * this loop walks it, so a host whose first AAAA is black-holed shows
         * up as several connect.start events rather than as one slow one. */
        zuh_trace_add(m->opts.trace, ZUH_EV_CONNECT_START, host, 0);
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
        m->fd = fd;

        if (connect(fd, ai->ai_addr, (socklen_t)ai->ai_addrlen) == 0) {
            record_peer(m, ai);
            zuh_trace_add(m->opts.trace, ZUH_EV_CONNECT_DONE, m->peer, 0);
            last = ZUH_OK;
            break;
        }
        if (sock_errno() == ZUH_EINPROGRESS || sock_errno() == ZUH_EWOULDBLOCK) {
            zuh_code rc = wait_ready(m, 1, deadline, err);
            if (rc == ZUH_OK) {
                int soerr = 0;
                socklen_t l = sizeof soerr;
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&soerr, &l) == 0 && soerr == 0) {
                    record_peer(m, ai);
                    zuh_trace_add(m->opts.trace, ZUH_EV_CONNECT_DONE, m->peer, 0);
                    last = ZUH_OK;
                    break;
                }
                zuh_error_set(err, ZUH_ERR_CONNECT, ZUH_PHASE_CONNECT,
                             "connection to %s:%u refused (%d)", host, (unsigned)port, soerr);
                last = ZUH_ERR_CONNECT;
            } else {
                /* A cancellation or a timeout is final: do not try the next
                 * address, or a deadline could be spent once per address. */
                if (err) err->phase = ZUH_PHASE_CONNECT;
                zuh_closesocket(fd);
                m->fd = ZUH_INVALID_SOCK;
                freeaddrinfo(res);
                zuh_free(m); zuh_free(st);
                return rc;
            }
        } else {
            zuh_error_set(err, ZUH_ERR_CONNECT, ZUH_PHASE_CONNECT,
                         "cannot connect to %s:%u (%d)", host, (unsigned)port, sock_errno());
            last = ZUH_ERR_CONNECT;
        }
        zuh_closesocket(fd);
        m->fd = ZUH_INVALID_SOCK;
    }
    /* After the address loop, so a host whose first candidate is black-holed
     * has that wait counted here rather than lost — which is precisely the
     * case someone reads this number to understand. */
    if (opts && opts->timings)
        opts->timings->connect = (long)(zuh_now_ms() - t_conn);
    freeaddrinfo(res);

    if (last != ZUH_OK) {
        zuh_free(m); zuh_free(st);
        return last;
    }

    st->vt = &k_net_vt;
    st->impl = m;
    *out = st;
    return ZUH_OK;
}

void zuh_net_stream_free(zuh_stream *s) { net_destroy(s); }

int zuh_net_peer_ip(const zuh_stream *s, char *out, size_t cap) {
    const net_impl *m;
    if (!s || !s->impl || !out || cap == 0) return 0;
    /* Only a TCP stream has a peer. Casting another stream's impl to net_impl
     * would read someone else's memory; with the engine's dial seam (§50.1)
     * the stream here may be a mock. */
    if (s->vt != &k_net_vt) return 0;
    m = (const net_impl *)s->impl;
    strncpy(out, m->peer, cap - 1);
    out[cap - 1] = '\0';
    return m->peer[0] != '\0';
}

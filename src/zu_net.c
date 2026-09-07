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

#include "zu_net.h"
#include "zu_alloc.h"
#include <string.h>
#include <stdio.h>

/* ---- platform shims, confined to this file (§10, §28) ---- */
#if defined(ZU_WINDOWS)
#  include <winsock2.h>
#  include <ws2tcpip.h>
   typedef SOCKET zu_sock;
#  define ZU_INVALID_SOCK INVALID_SOCKET
#  define zu_closesocket  closesocket
#  define zu_poll         WSAPoll
#  define ZU_EWOULDBLOCK  WSAEWOULDBLOCK
#  define ZU_EINPROGRESS  WSAEWOULDBLOCK
#  define ZU_EINTR        WSAEINTR
static int sock_errno(void) { return WSAGetLastError(); }
static int set_nonblocking(zu_sock s) {
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
   typedef int zu_sock;
#  define ZU_INVALID_SOCK (-1)
#  define zu_closesocket  close
#  define zu_poll         poll
#  define ZU_EWOULDBLOCK  EWOULDBLOCK
#  define ZU_EINPROGRESS  EINPROGRESS
#  define ZU_EINTR        EINTR
static int sock_errno(void) { return errno; }
static int set_nonblocking(zu_sock s) {
    int fl = fcntl(s, F_GETFL, 0);
    return fl != -1 && fcntl(s, F_SETFL, fl | O_NONBLOCK) == 0;
}
#endif

typedef struct {
    zu_sock     fd;
    zu_net_opts opts;
    char        peer[64];
} net_impl;

zu_code zu_net_init(void) {
#if defined(ZU_WINDOWS)
    static int done = 0;
    WSADATA wsa;
    if (done) return ZU_OK;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return ZU_ERR_IO;
    done = 1;
#endif
    return ZU_OK;
}

void zu_net_shutdown(void) {
#if defined(ZU_WINDOWS)
    /* Deliberately not calling WSACleanup: another package in the same R
     * process may still be using Winsock, and the counts are process-wide. */
#endif
}

void zu_net_opts_init(zu_net_opts *o) {
    memset(o, 0, sizeof *o);
    o->tick_ms = 100;
}

/* One bounded wait. §25.1: never block longer than a tick without giving the
 * caller a chance to cancel. */
static zu_code wait_ready(net_impl *m, int want_write, zu_deadline d, zu_error *err) {
#if defined(ZU_WINDOWS)
    WSAPOLLFD p;
#else
    struct pollfd p;
#endif
    for (;;) {
        int ms, rc;

        if (m->opts.tick && m->opts.tick(m->opts.tick_ctx)) {
            zu_error_set(err, ZU_ERR_CANCELLED, ZU_PHASE_NONE, "operation cancelled");
            return ZU_ERR_CANCELLED;
        }
        if (zu_deadline_expired(d)) {
            zu_error_set(err, ZU_ERR_TIMEOUT, ZU_PHASE_NONE, "deadline exceeded");
            return ZU_ERR_TIMEOUT;
        }

        memset(&p, 0, sizeof p);
        p.fd = m->fd;
        p.events = (short)(want_write ? POLLOUT : POLLIN);

        ms = zu_deadline_poll_ms(d, m->opts.tick_ms > 0 ? m->opts.tick_ms : 100);
        rc = zu_poll(&p, 1, ms);

        if (rc > 0) return ZU_OK;
        if (rc == 0) continue;                      /* tick expired; loop */
        if (sock_errno() == ZU_EINTR) continue;
        zu_error_set(err, ZU_ERR_IO, ZU_PHASE_NONE, "poll failed (%d)", sock_errno());
        return ZU_ERR_IO;
    }
}

static zu_ssize net_read(zu_stream *s, void *buf, size_t n, zu_deadline d, zu_error *err) {
    net_impl *m = (net_impl *)s->impl;
    for (;;) {
        zu_ssize r;
        zu_code rc;
#if defined(ZU_WINDOWS)
        int rn = recv(m->fd, (char *)buf, (int)(n > INT_MAX ? INT_MAX : n), 0);
        r = rn;
#else
        r = recv(m->fd, buf, n, 0);
#endif
        if (r >= 0) return r;                        /* 0 == orderly close */
        if (sock_errno() == ZU_EINTR) continue;
        if (sock_errno() != ZU_EWOULDBLOCK) {
            zu_error_set(err, ZU_ERR_IO, ZU_PHASE_READ, "read failed (%d)", sock_errno());
            return -1;
        }
        rc = wait_ready(m, 0, d, err);
        if (rc != ZU_OK) { if (err) err->phase = ZU_PHASE_READ; return -1; }
    }
}

static zu_ssize net_write(zu_stream *s, const void *buf, size_t n, zu_deadline d, zu_error *err) {
    net_impl *m = (net_impl *)s->impl;
    for (;;) {
        zu_ssize w;
        zu_code rc;
#if defined(ZU_WINDOWS)
        int wn = send(m->fd, (const char *)buf, (int)(n > INT_MAX ? INT_MAX : n), 0);
        w = wn;
#else
        w = send(m->fd, buf, n, 0);
#endif
        if (w >= 0) return w;
        if (sock_errno() == ZU_EINTR) continue;
        if (sock_errno() != ZU_EWOULDBLOCK) {
            zu_error_set(err, ZU_ERR_IO, ZU_PHASE_WRITE, "write failed (%d)", sock_errno());
            return -1;
        }
        rc = wait_ready(m, 1, d, err);
        if (rc != ZU_OK) { if (err) err->phase = ZU_PHASE_WRITE; return -1; }
    }
}

static void net_close(zu_stream *s) {
    net_impl *m = (net_impl *)s->impl;
    if (m && m->fd != ZU_INVALID_SOCK) {
        zu_closesocket(m->fd);
        m->fd = ZU_INVALID_SOCK;
    }
}

static const zu_stream_vtable k_net_vt = { "tcp", net_read, net_write, net_close };

static void record_peer(net_impl *m, const struct addrinfo *ai) {
    char host[64];
    m->peer[0] = '\0';
    if (getnameinfo(ai->ai_addr, (socklen_t)ai->ai_addrlen, host, sizeof host,
                    NULL, 0, NI_NUMERICHOST) == 0) {
        strncpy(m->peer, host, sizeof m->peer - 1);
        m->peer[sizeof m->peer - 1] = '\0';
    }
}

zu_code zu_net_connect(zu_stream **out, const char *host, uint16_t port,
                       zu_deadline deadline, const zu_net_opts *opts,
                       zu_error *err) {
    struct addrinfo hints, *res = NULL, *ai;
    char portstr[8];
    zu_stream *st = NULL;
    net_impl *m = NULL;
    zu_code last = ZU_ERR_CONNECT;
    int gai;

    if (!out || !host) return ZU_ERR_PARSE;
    *out = NULL;
    if (zu_net_init() != ZU_OK) {
        zu_error_set(err, ZU_ERR_IO, ZU_PHASE_CONNECT, "network stack unavailable");
        return ZU_ERR_IO;
    }

    snprintf(portstr, sizeof portstr, "%u", (unsigned)port);
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;          /* §3.1: IPv4 and IPv6 */
    hints.ai_socktype = SOCK_STREAM;

    /* Synchronous and uninterruptible — see the header note and §25.4. */
    gai = getaddrinfo(host, portstr, &hints, &res);
    if (gai != 0 || !res) {
        zu_error_set(err, ZU_ERR_DNS, ZU_PHASE_DNS, "cannot resolve '%s'", host);
        return ZU_ERR_DNS;
    }

    st = (zu_stream *)zu_calloc(1, sizeof *st);
    m  = (net_impl *)zu_calloc(1, sizeof *m);
    if (!st || !m) { zu_free(st); zu_free(m); freeaddrinfo(res); return ZU_ERR_NOMEM; }
    m->fd = ZU_INVALID_SOCK;
    if (opts) m->opts = *opts; else zu_net_opts_init(&m->opts);
    if (m->opts.tick_ms <= 0) m->opts.tick_ms = 100;

    for (ai = res; ai; ai = ai->ai_next) {
        int one = 1;
        zu_sock fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == ZU_INVALID_SOCK) continue;
        if (!set_nonblocking(fd)) { zu_closesocket(fd); continue; }
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
        m->fd = fd;

        if (connect(fd, ai->ai_addr, (socklen_t)ai->ai_addrlen) == 0) {
            record_peer(m, ai);
            last = ZU_OK;
            break;
        }
        if (sock_errno() == ZU_EINPROGRESS || sock_errno() == ZU_EWOULDBLOCK) {
            zu_code rc = wait_ready(m, 1, deadline, err);
            if (rc == ZU_OK) {
                int soerr = 0;
                socklen_t l = sizeof soerr;
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&soerr, &l) == 0 && soerr == 0) {
                    record_peer(m, ai);
                    last = ZU_OK;
                    break;
                }
                zu_error_set(err, ZU_ERR_CONNECT, ZU_PHASE_CONNECT,
                             "connection to %s:%u refused (%d)", host, (unsigned)port, soerr);
                last = ZU_ERR_CONNECT;
            } else {
                /* A cancellation or a timeout is final: do not try the next
                 * address, or a deadline could be spent once per address. */
                if (err) err->phase = ZU_PHASE_CONNECT;
                zu_closesocket(fd);
                m->fd = ZU_INVALID_SOCK;
                freeaddrinfo(res);
                zu_free(m); zu_free(st);
                return rc;
            }
        } else {
            zu_error_set(err, ZU_ERR_CONNECT, ZU_PHASE_CONNECT,
                         "cannot connect to %s:%u (%d)", host, (unsigned)port, sock_errno());
            last = ZU_ERR_CONNECT;
        }
        zu_closesocket(fd);
        m->fd = ZU_INVALID_SOCK;
    }
    freeaddrinfo(res);

    if (last != ZU_OK) {
        zu_free(m); zu_free(st);
        return last;
    }

    st->vt = &k_net_vt;
    st->impl = m;
    *out = st;
    return ZU_OK;
}

void zu_net_stream_free(zu_stream *s) {
    if (!s) return;
    net_close(s);
    zu_free(s->impl);
    zu_free(s);
}

int zu_net_peer_ip(const zu_stream *s, char *out, size_t cap) {
    const net_impl *m;
    if (!s || !s->impl || !out || cap == 0) return 0;
    m = (const net_impl *)s->impl;
    strncpy(out, m->peer, cap - 1);
    out[cap - 1] = '\0';
    return m->peer[0] != '\0';
}

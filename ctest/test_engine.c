/* The §63.2 vertical slice, against real servers.
 *
 * Network-dependent by nature, so this lives in its own binary and its own CI
 * job — c-core must stay deterministic and offline. Run with `make engine`.
 */
#include "zuh_test.h"
#include "zuh_engine.h"
#include "zuh_alloc.h"
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>

int zuh_test_fails = 0;
int zuh_test_checks = 0;
const char *zuh_test_current = "(none)";

static int contains(const zuh_buffer *b, const char *needle) {
    size_t n = strlen(needle), i;
    if (b->len < n) return 0;
    for (i = 0; i + n <= b->len; i++)
        if (memcmp(b->data + i, needle, n) == 0) return 1;
    return 0;
}

/* A real HTTP CONNECT proxy, one connection, on a thread: it records the
 * request head, opens the tunnel and relays bytes both ways until either side
 * closes. The fake proxy in tests/testthat answers but never tunnels; this
 * one is what shows HTTPS actually went through it (W13, §20.3). */
typedef struct {
    int  listen_fd;
    char head[2048];
    int  tunnelled;
    int  challenged;   /* answered 407 first, as a proxy needing auth does */
} connect_proxy;

static int dial_target(const char *authority) {
    char host[256], *colon;
    struct addrinfo hints, *res = NULL, *ai;
    int fd = -1;
    snprintf(host, sizeof host, "%s", authority);
    colon = strrchr(host, ':');
    if (!colon) return -1;
    *colon = '\0';
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, colon + 1, &hints, &res) != 0) return -1;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static void *connect_proxy_run(void *arg) {
    connect_proxy *p = (connect_proxy *)arg;
    size_t n = 0;
    int cli = -1, up = -1, attempt;
    char authority[300];
    /* A client that sends credentials up front (zuh_net plus a wrapping
     * backend) gets its tunnel at once; one that waits to be asked
     * (Network.framework) gets the 407 a real proxy would send, and comes
     * back with them. Either way the credentials must arrive. */
    for (attempt = 0; attempt < 2; attempt++) {
        struct pollfd lp;
        /* Bounded, so a request that never came this way fails the test
         * rather than hanging it in pthread_join(). */
        lp.fd = p->listen_fd; lp.events = POLLIN; lp.revents = 0;
        if (poll(&lp, 1, 15000) <= 0) return NULL;
        cli = accept(p->listen_fd, NULL, NULL);
        if (cli < 0) return NULL;
        n = 0;
        p->head[0] = '\0';
        while (n + 1 < sizeof p->head) {
            ssize_t k = read(cli, p->head + n, 1);
            if (k <= 0) break;
            n++;
            p->head[n] = '\0';
            if (n >= 4 && memcmp(p->head + n - 4, "\r\n\r\n", 4) == 0) break;
        }
        if (strstr(p->head, "Proxy-Authorization:") || attempt == 1) break;
        {
            const char *ask = "HTTP/1.1 407 Proxy Authentication Required\r\n"
                              "Proxy-Authenticate: Basic realm=\"zuhttp-test\"\r\n"
                              "Content-Length: 0\r\nConnection: close\r\n\r\n";
            (void)!write(cli, ask, strlen(ask));
        }
        p->challenged = 1;
        close(cli);
        cli = -1;
    }
    if (sscanf(p->head, "CONNECT %299s ", authority) == 1)
        up = dial_target(authority);
    if (up < 0) {
        const char *no = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
        (void)!write(cli, no, strlen(no));
        close(cli);
        return NULL;
    }
    {
        const char *ok = "HTTP/1.1 200 Connection established\r\n\r\n";
        (void)!write(cli, ok, strlen(ok));
    }
    p->tunnelled = 1;
    for (;;) {
        struct pollfd fds[2];
        char buf[16384];
        int i, done = 0;
        fds[0].fd = cli; fds[0].events = POLLIN; fds[0].revents = 0;
        fds[1].fd = up;  fds[1].events = POLLIN; fds[1].revents = 0;
        if (poll(fds, 2, 10000) <= 0) break;
        for (i = 0; i < 2 && !done; i++) {
            if (fds[i].revents & (POLLIN | POLLHUP | POLLERR)) {
                ssize_t k = read(fds[i].fd, buf, sizeof buf);
                if (k <= 0 || write(fds[1 - i].fd, buf, (size_t)k) != k) done = 1;
            }
        }
        if (done) break;
    }
    close(up);
    close(cli);
    return NULL;
}

/* §25.1: a tick that asks to stop after `after_ms`, and remembers when it
 * first did, so a test can measure how long the request took to notice. */
static zuh_millis g_tick_start, g_tick_fired;
static long g_tick_after;
static int stop_after(void *ctx) {
    zuh_millis now = zuh_now_ms();
    (void)ctx;
    if (now - g_tick_start < g_tick_after) return 0;
    if (!g_tick_fired) g_tick_fired = now;
    return 1;
}

/* Cancel a request to `url` 150 ms in, and return how long after the tick
 * first said stop the call came back (-1 if it did not end CANCELLED). */
static long cancel_latency(const char *url, const zuh_get_opts *base) {
    zuh_get_opts o = *base;
    zuh_result r;
    zuh_error e;
    zuh_code rc;
    g_tick_start = zuh_now_ms(); g_tick_fired = 0; g_tick_after = 150;
    o.tick = stop_after;
    o.timeout_ms = 10000;
    rc = zuh_engine_get(&r, url, &o, &e);
    if (rc == ZUH_OK) zuh_result_free(&r);
    printf("  -> %s after %ld ms\n", zuh_code_class(rc), (long)(zuh_now_ms() - g_tick_start));
    if (rc != ZUH_ERR_CANCELLED || !g_tick_fired) return -1;
    return (long)(zuh_now_ms() - g_tick_fired);
}

/* badssl.com resets connections from CI runners now and then (ECONNRESET,
 * "read failed"). A transport failure is retried twice; a TLS verdict, or
 * any other answer, never is -- so a flaky network can neither fail these
 * cases nor make one pass. */
static zuh_code get_retrying(zuh_result *r, const char *url, const zuh_get_opts *o,
                             zuh_error *e) {
    zuh_code rc = ZUH_ERR_IO;
    int attempt;
    for (attempt = 0; attempt < 3; attempt++) {
        rc = zuh_engine_get(r, url, o, e);
        if (rc != ZUH_ERR_IO && rc != ZUH_ERR_CONNECT && rc != ZUH_ERR_TIMEOUT) break;
        printf("  (transport failure, retrying: %s)\n", e->message);
    }
    return rc;
}

int main(void) {
    zuh_get_opts o;
    zuh_result r;
    zuh_error e;
    zuh_code rc;

    printf("zuhttp vertical slice (design 63.2)\n\n");
    setvbuf(stdout, NULL, _IONBF, 0);   /* a crash must not eat the last line */
    zuh_get_opts_init(&o);

    ZUH_CASE("HTTPS GET returns 200 with a body and a TLS version");
    rc = zuh_engine_get(&r, "https://example.com/", &o, &e);
    ZUH_CHECK_EQ_INT(rc, ZUH_OK);
    if (rc == ZUH_OK) {
        printf("  status=%d  bytes=%lu  tls=%s/%s  url=%s\n",
               r.status, (unsigned long)r.body.len,
               r.tls_version ? r.tls_version : "-",
               r.tls_cipher ? r.tls_cipher : "-", r.final_url);
        ZUH_CHECK_EQ_INT(r.status, 200);
        ZUH_CHECK(r.body.len > 0);
        ZUH_CHECK(contains(&r.body, "Example Domain"));
        ZUH_CHECK(r.tls_version != NULL);
        ZUH_CHECK(zuh_headers_get(&r.headers, "Content-Type") != NULL);
        zuh_result_free(&r);
    }

    ZUH_CASE("chunked transfer decodes");
    rc = zuh_engine_get(&r, "https://httpbin.org/stream/3", &o, &e);
    if (rc == ZUH_OK) {
        printf("  status=%d  bytes=%lu\n", r.status, (unsigned long)r.body.len);
        ZUH_CHECK_EQ_INT(r.status, 200);
        ZUH_CHECK(r.body.len > 0);
        zuh_result_free(&r);
    } else {
        printf("  skipped: %s (%s)\n", e.message, zuh_code_class(rc));
    }

    ZUH_CASE("gzip is requested and decoded transparently");
    rc = zuh_engine_get(&r, "https://httpbin.org/gzip", &o, &e);
    if (rc == ZUH_OK) {
        ZUH_CHECK_EQ_INT(r.status, 200);
        /* If decoding failed we would be holding compressed bytes. */
        ZUH_CHECK(contains(&r.body, "gzipped"));
        ZUH_CHECK(zuh_headers_get(&r.headers, "Content-Encoding") == NULL);
        zuh_result_free(&r);
    } else {
        printf("  skipped: %s\n", e.message);
    }

    ZUH_CASE("no_decode hands back the wire bytes (§21.2)");
    {
        zuh_get_opts nd = o;
        nd.no_decode = 1;
        rc = zuh_engine_get(&r, "https://httpbin.org/gzip", &nd, &e);
        if (rc == ZUH_OK) {
            const char *ce = zuh_headers_get(&r.headers, "Content-Encoding");
            ZUH_CHECK_EQ_INT(r.status, 200);
            /* The header still says gzip, and the body really starts with the
             * gzip magic number -- this endpoint encodes whatever we send in
             * Accept-Encoding, which is exactly why the flag cannot be only
             * about the request header. */
            ZUH_CHECK(ce != NULL && strcmp(ce, "gzip") == 0);
            ZUH_CHECK(r.body.len > 2 &&
                     r.body.data[0] == 0x1f && r.body.data[1] == 0x8b);
            ZUH_CHECK(!contains(&r.body, "gzipped"));
            zuh_result_free(&r);
        } else {
            printf("  skipped: %s\n", e.message);
        }
    }

    ZUH_CASE("one redirect is followed and the final URL reported");
    /* An http:// start that redirects to https:// also exercises the §19.3
     * direction that IS allowed (upgrade); the refused direction is a
     * downgrade, which zuh_redirect_decide covers in the offline suite. */
    rc = zuh_engine_get(&r, "http://github.com/", &o, &e);
    if (rc == ZUH_OK) {
        printf("  status=%d  redirects=%d  url=%s\n", r.status, r.redirects, r.final_url);
        ZUH_CHECK_EQ_INT(r.redirects, 1);
        ZUH_CHECK(strncmp(r.final_url, "https://", 8) == 0);
        /* §19.5: the redirect's own body must never reach the caller. */
        ZUH_CHECK(!contains(&r.body, "<html><body>You are being"));
        zuh_result_free(&r);
    } else {
        printf("  note: %s\n", e.message);
    }

    ZUH_CASE("the redirect budget is respected");
    {
        zuh_get_opts none = o;
        none.max_redirects = 0;
        rc = zuh_engine_get(&r, "http://github.com/", &none, &e);
        if (rc == ZUH_OK) {
            /* With no budget the 301 itself is returned, not followed. */
            ZUH_CHECK_EQ_INT(r.redirects, 0);
            ZUH_CHECK(r.status >= 300 && r.status < 400);
            printf("  unfollowed status=%d\n", r.status);
            zuh_result_free(&r);
        }
    }

    ZUH_CASE("certificate verification is on by default");
    rc = get_retrying(&r, "https://expired.badssl.com/", &o, &e);
    ZUH_CHECK_EQ_INT(rc, ZUH_ERR_TLS_CERT);
    printf("  -> %s: %s\n", zuh_code_class(rc), e.message);
    if (rc == ZUH_OK) zuh_result_free(&r);

    ZUH_CASE("a hostname mismatch is distinct from a bad chain");
    rc = get_retrying(&r, "https://wrong.host.badssl.com/", &o, &e);
    ZUH_CHECK_EQ_INT(rc, ZUH_ERR_TLS_HOSTNAME);
    if (rc == ZUH_OK) zuh_result_free(&r);

    ZUH_CASE("a bad URL is refused before any connection");
    rc = zuh_engine_get(&r, "ftp://example.com/", &o, &e);
    ZUH_CHECK_EQ_INT(rc, ZUH_ERR_URL);

    ZUH_CASE("the total deadline is enforced");
    {
        zuh_get_opts fast = o;
        fast.timeout_ms = 1;                     /* cannot possibly complete */
        rc = zuh_engine_get(&r, "https://example.com/", &fast, &e);
        ZUH_CHECK(rc != ZUH_OK);
        printf("  -> %s\n", zuh_code_class(rc));
        if (rc == ZUH_OK) zuh_result_free(&r);
    }

    /* --- S11: methods, headers and bodies --- */

    ZUH_CASE("POST with a JSON body round-trips");
    {
        static const char json[] = "{\"name\":\"alice\",\"n\":42}";
        static const char *const hn[] = { "Content-Type" };
        static const char *const hv[] = { "application/json" };
        zuh_req_spec req;
        memset(&req, 0, sizeof req);
        req.method = "POST";
        req.header_names = hn; req.header_values = hv; req.n_headers = 1;
        req.body = json; req.body_len = sizeof json - 1;

        rc = zuh_engine_perform(&r, "https://httpbin.org/post", &req, &o, &e);
        if (rc == ZUH_OK) {
            ZUH_CHECK_EQ_INT(r.status, 200);
            /* httpbin echoes what it received, so this proves the body and the
             * Content-Type both arrived rather than merely that we sent them. */
            ZUH_CHECK(contains(&r.body, "\"name\": \"alice\""));
            ZUH_CHECK(contains(&r.body, "application/json"));
            zuh_result_free(&r);
        } else {
            printf("  skipped: %s\n", e.message);
        }
    }

    ZUH_CASE("a caller header overrides the §17.2 default");
    {
        static const char *const hn[] = { "User-Agent" };
        static const char *const hv[] = { "zuhttp-test/1" };
        zuh_req_spec req;
        memset(&req, 0, sizeof req);
        req.header_names = hn; req.header_values = hv; req.n_headers = 1;
        rc = zuh_engine_perform(&r, "https://httpbin.org/headers", &req, &o, &e);
        if (rc == ZUH_OK) {
            ZUH_CHECK(contains(&r.body, "zuhttp-test/1"));
            zuh_result_free(&r);
        }
    }

    ZUH_CASE("HEAD gets no body whatever the headers claim (§18.1)");
    {
        zuh_req_spec req;
        memset(&req, 0, sizeof req);
        req.method = "HEAD";
        rc = zuh_engine_perform(&r, "https://example.com/", &req, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) {
            ZUH_CHECK_EQ_INT(r.status, 200);
            /* Content-Length is present and non-zero, and the body must still
             * be empty; getting this wrong hangs waiting for bytes that never
             * come. */
            ZUH_CHECK_EQ_INT((long long)r.body.len, 0);
            zuh_result_free(&r);
        }
    }

    ZUH_CASE("a header carrying CRLF is refused, not sent (§17.1)");
    {
        static const char *const hn[] = { "X-Evil" };
        static const char *const hv[] = { "a\r\nInjected: yes" };
        zuh_req_spec req;
        memset(&req, 0, sizeof req);
        req.header_names = hn; req.header_values = hv; req.n_headers = 1;
        rc = zuh_engine_perform(&r, "https://example.com/", &req, &o, &e);
        ZUH_CHECK(rc != ZUH_OK);
        printf("  -> %s\n", zuh_code_class(rc));
        if (rc == ZUH_OK) zuh_result_free(&r);
    }

    ZUH_CASE("HTTPS through a real CONNECT proxy, credentials to it alone (§20.3, §20.4)");
    {
        connect_proxy p;
        pthread_t th;
        struct sockaddr_in sa;
        socklen_t len = sizeof sa;
        char purl[96];
        memset(&p, 0, sizeof p);
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        p.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (p.listen_fd >= 0 && bind(p.listen_fd, (struct sockaddr *)&sa, sizeof sa) == 0
            && listen(p.listen_fd, 4) == 0
            && getsockname(p.listen_fd, (struct sockaddr *)&sa, &len) == 0
            && pthread_create(&th, NULL, connect_proxy_run, &p) == 0) {
            zuh_get_opts px = o;
            snprintf(purl, sizeof purl, "http://user:s3cret@127.0.0.1:%u",
                     (unsigned)ntohs(sa.sin_port));
            px.proxy = purl;
            px.proxy_set = 1;
            rc = zuh_engine_get(&r, "https://example.com/", &px, &e);
            ZUH_CHECK_EQ_INT(rc, ZUH_OK);
            if (rc == ZUH_OK) {
                ZUH_CHECK_EQ_INT(r.status, 200);
                ZUH_CHECK(r.proxy_used);
                ZUH_CHECK(contains(&r.body, "Example Domain"));
                zuh_result_free(&r);
            } else {
                printf("  -> %s: %s\n", zuh_code_class(rc), e.message);
            }
            pthread_join(th, NULL);
            printf("  proxy saw: %.*s%s\n", (int)strcspn(p.head, "\r"), p.head,
                   p.challenged ? "  (after a 407 challenge)" : "");
            ZUH_CHECK(p.tunnelled);
            ZUH_CHECK(strncmp(p.head, "CONNECT example.com:443 ", 24) == 0);
            /* Basic dXNlcjpzM2NyZXQ= is user:s3cret. */
            ZUH_CHECK(strstr(p.head, "Proxy-Authorization: Basic dXNlcjpzM2NyZXQ=") != NULL);
        } else {
            ZUH_CHECK(0);
        }
        if (p.listen_fd >= 0) close(p.listen_fd);
    }

    /* --- W13: cancellation is prompt in every phase the network owns --- */

    ZUH_CASE("a cancelled connect returns within 200 ms (§25.1)");
    {
        /* A non-routable address: the SYN goes nowhere and the connect never
         * completes on its own. */
        long ms = cancel_latency("https://10.255.255.1/", &o);
        ZUH_CHECK(ms >= 0);
        ZUH_CHECK(ms < 200);
    }

    ZUH_CASE("a cancelled TLS handshake returns within 200 ms (§25.1)");
    {
        /* A local listener that is never accepted: the kernel completes TCP
         * from the backlog, and the ClientHello is never answered. */
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sa;
        socklen_t len = sizeof sa;
        char url[64];
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ZUH_CHECK(fd >= 0);
        if (fd >= 0 && bind(fd, (struct sockaddr *)&sa, sizeof sa) == 0
            && listen(fd, 4) == 0
            && getsockname(fd, (struct sockaddr *)&sa, &len) == 0) {
            long ms;
            snprintf(url, sizeof url, "https://127.0.0.1:%u/", (unsigned)ntohs(sa.sin_port));
            ms = cancel_latency(url, &o);
            ZUH_CHECK(ms >= 0);
            ZUH_CHECK(ms < 200);
        } else {
            ZUH_CHECK(0);
        }
        if (fd >= 0) close(fd);
    }

#if defined(ZUH_NW_ASSUME_NO_PROXY_API) && ZUH_NW_ASSUME_NO_PROXY_API
    ZUH_CASE("below macOS 14, proxied HTTPS is refused, naming the version (D-71)");
    {
        zuh_get_opts px = o;
        px.proxy = "http://127.0.0.1:9";
        px.proxy_set = 1;
        rc = zuh_engine_get(&r, "https://example.com/", &px, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_ERR_PROXY);
        ZUH_CHECK(strstr(e.message, "macOS 14") != NULL);
        printf("  -> %s: %s\n", zuh_code_class(rc), e.message);
        if (rc == ZUH_OK) zuh_result_free(&r);
    }
#endif

    ZUH_CASE("no leaks across the run");
    {
        zuh_alloc_stats st;
        zuh_alloc_stats_get(&st);
        printf("  allocations: %lu made, %lu freed, %lu live\n",
               (unsigned long)st.total_allocs, (unsigned long)st.total_frees,
               (unsigned long)st.live_blocks);
        ZUH_CHECK_EQ_INT(st.live_blocks, 0);
    }

    printf("\n%d checks, %d failures\n", zuh_test_checks, zuh_test_fails);
    return zuh_test_fails ? 1 : 0;
}

/* zuhttp — macOS TLS backend: Network.framework + SecTrust (D-63, D-71, §13.2).
 *
 * Network.framework speaks the protocol; SecTrustEvaluateWithError, called
 * from our own verify block, decides trust (§13.1). It replaced Secure
 * Transport (W13), which was deprecated, stopped at TLS 1.2 and cost an
 * `--as-cran` NOTE.
 *
 * Network.framework owns the socket, so this backend DIALS (D-71): it is
 * handed host, port and proxy and opens the connection itself, resolving the
 * name and running the CONNECT tunnel too. The engine asks for that through
 * ZUH_TLS_CAP_DIALS and skips its own TCP and CONNECT for https://. Above the
 * stream nothing changes.
 *
 * Threading (§25.1, §29.1). Every completion -- state changes, receives,
 * sends, the verify block -- runs on this connection's serial dispatch queue.
 * A completion only updates C state under the mutex and writes one byte to a
 * pipe; the caller's thread poll()s that pipe in slices of at most one tick
 * and is the only place anything waits, so Ctrl-C is checked as it is for a
 * plain socket. No completion touches the R API, zuh_alloc's counters, or the
 * zuh_stream.
 *
 * Lifetime. The completions share `nw_shared` with the stream, and may run
 * after the stream is freed, so it is reference-counted: one reference for
 * the stream, one for the connection (dropped by the cancelled state, the
 * last event Network.framework delivers), one per outstanding receive or
 * send. It is allocated with plain malloc because it can be freed on the
 * queue's thread, where zuh_alloc's bookkeeping must not run.
 *
 * Fork (§26.4, §13.2.1). libdispatch refuses to run in a forked child: any
 * Network.framework call there is SIGILL (F-19). The guard is checked before
 * the first such call in zuh_tls_dial(), and a stream inherited across fork()
 * is freed without one.
 */
#include "zuh_tls.h"
#include "zuh_alloc.h"
#include "zuh_fork.h"
#include "zuh_trace.h"

#include <Network/Network.h>
#include <Security/Security.h>
#include <dispatch/dispatch.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* For the test of the macOS < 14 path (W13): build with this defined and a
 * proxied HTTPS hop takes the "needs macOS 14" branch on any macOS. */
#ifndef ZUH_NW_ASSUME_NO_PROXY_API
#  define ZUH_NW_ASSUME_NO_PROXY_API 0
#endif

#define NW_RX_CHUNK 65536u

/* --- trust (§14), shared with nothing: the same SecTrust calls the Secure
 *     Transport backend made after kSSLSessionOptionBreakOnServerAuth -------- */

/* What the verify block needs, copied out of zuh_tls_config so that it does
 * not point into memory the caller may free while the handshake runs. */
typedef struct {
    char *hostname;
    char *ca_file;
    char *ca_extra_file;
    int   source_file;      /* ZUH_TRUST_FILE */
    int   verify_peer;
    int   verify_hostname;
    int   revocation;
} nw_trust_cfg;

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;                      /* whitespace, '=', or junk */
}

/* Decode base64, skipping whitespace, which is what makes it a PEM decoder.
 * CoreFoundation has no public base64 API, and Foundation's would make this
 * file Objective-C. Runs on the verify block's thread: plain malloc. */
static unsigned char *b64_decode(const char *src, size_t n, size_t *out_len) {
    unsigned char *out = (unsigned char *)malloc(n / 4 * 3 + 3);
    size_t i, len = 0;
    int acc = 0, bits = 0;
    if (!out) return NULL;
    for (i = 0; i < n; i++) {
        int v = b64_val(src[i]);
        if (v < 0) continue;
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[len++] = (unsigned char)((acc >> bits) & 0xFF);
        }
    }
    *out_len = len;
    return out;
}

/* A CA bundle in PEM, as SecCertificateRefs; NULL if unreadable or empty. */
static CFArrayRef anchors_from_pem_file(const char *path) {
    static const char BEGIN[] = "-----BEGIN CERTIFICATE-----";
    static const char END[]   = "-----END CERTIFICATE-----";
    CFMutableArrayRef out;
    char *text;
    long size;
    FILE *f = fopen(path, "rb");
    const char *p;

    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    size = ftell(f);
    if (size <= 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    text = (char *)malloc((size_t)size + 1);
    if (!text) { fclose(f); return NULL; }
    if (fread(text, 1, (size_t)size, f) != (size_t)size) {
        free(text); fclose(f); return NULL;
    }
    text[size] = '\0';
    fclose(f);

    out = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    for (p = text; (p = strstr(p, BEGIN)) != NULL; ) {
        const char *b64 = p + sizeof BEGIN - 1;
        const char *end = strstr(b64, END);
        size_t der_len = 0;
        unsigned char *der;
        if (!end) break;
        der = b64_decode(b64, (size_t)(end - b64), &der_len);
        if (der && der_len) {
            CFDataRef d = CFDataCreate(NULL, der, (CFIndex)der_len);
            if (d) {
                SecCertificateRef c = SecCertificateCreateWithData(NULL, d);
                if (c) { CFArrayAppendValue(out, c); CFRelease(c); }
                CFRelease(d);
            }
        }
        free(der);
        p = end + sizeof END - 1;
    }
    free(text);
    if (CFArrayGetCount(out) == 0) { CFRelease(out); return NULL; }
    return out;
}

/* Evaluate under an SSL policy, optionally checking the hostname. */
static int evaluate_under_policy(SecTrustRef trust, const char *hostname,
                                 int check_host, int revocation,
                                 char *detail, size_t detail_len, long *os_code) {
    CFStringRef h = NULL;
    SecPolicyRef policy;
    CFMutableArrayRef policies;
    CFErrorRef err = NULL;
    int ok;

    if (check_host && hostname)
        h = CFStringCreateWithCString(NULL, hostname, kCFStringEncodingUTF8);
    policy = SecPolicyCreateSSL(true, h);
    policies = CFArrayCreateMutable(NULL, 2, &kCFTypeArrayCallBacks);
    CFArrayAppendValue(policies, policy);
    /* §14.5 / S0 F-4: an SSL policy does NOT check revocation. It is added
     * explicitly, and off by default (D-31): it costs 7-15x and makes a
     * network call we can neither deadline nor cancel. */
    if (revocation) {
        SecPolicyRef rev = SecPolicyCreateRevocation(
            kSecRevocationUseAnyAvailableMethod | kSecRevocationRequirePositiveResponse);
        if (rev) { CFArrayAppendValue(policies, rev); CFRelease(rev); }
    }
    SecTrustSetPolicies(trust, policies);

    ok = SecTrustEvaluateWithError(trust, &err) ? 1 : 0;
    if (err) {
        CFStringRef d = CFErrorCopyDescription(err);
        if (os_code) *os_code = (long)CFErrorGetCode(err);
        if (d && detail) CFStringGetCString(d, detail, (CFIndex)detail_len,
                                            kCFStringEncodingUTF8);
        if (d) CFRelease(d);
        CFRelease(err);
    }
    CFRelease(policies);
    CFRelease(policy);
    if (h) CFRelease(h);
    return ok;
}

/* §14.2 anchors, then the evaluation. A bad chain and a good chain for the
 * wrong name are told apart by evaluating twice rather than by reading
 * message text: §34.1 gives them separate classes because the fixes differ. */
static zuh_code check_trust(SecTrustRef trust, const nw_trust_cfg *cfg,
                            zuh_error *err) {
    char detail[256];
    long os_code = 0;
    const char *host = cfg->hostname;

    detail[0] = '\0';
    if (cfg->source_file && cfg->ca_file) {
        CFArrayRef anchors = anchors_from_pem_file(cfg->ca_file);
        if (!anchors) {
            zuh_error_set(err, ZUH_ERR_TLS, ZUH_PHASE_TLS,
                          "cannot read CA file '%s'", cfg->ca_file);
            return ZUH_ERR_TLS;
        }
        /* §14.2: ca_extra ADDS to whatever was selected, a ca_file included,
         * and the result stays exclusive of the system store (D-81's fix). */
        if (cfg->ca_extra_file) {
            CFArrayRef extra = anchors_from_pem_file(cfg->ca_extra_file);
            CFMutableArrayRef all = NULL;
            if (extra) {
                all = CFArrayCreateMutableCopy(kCFAllocatorDefault, 0, anchors);
                if (all) CFArrayAppendArray(all, extra,
                                            CFRangeMake(0, CFArrayGetCount(extra)));
                CFRelease(extra);
            }
            CFRelease(anchors);
            if (!all) {
                zuh_error_set(err, ZUH_ERR_TLS, ZUH_PHASE_TLS,
                              "cannot read additional CA file '%s'", cfg->ca_extra_file);
                return ZUH_ERR_TLS;
            }
            anchors = all;
        }
        SecTrustSetAnchorCertificates(trust, anchors);
        SecTrustSetAnchorCertificatesOnly(trust, true);    /* REPLACES (S0 F-6) */
        CFRelease(anchors);
    } else if (cfg->ca_extra_file) {
        CFArrayRef anchors = anchors_from_pem_file(cfg->ca_extra_file);
        if (!anchors) {
            zuh_error_set(err, ZUH_ERR_TLS, ZUH_PHASE_TLS,
                          "cannot read additional CA file '%s'", cfg->ca_extra_file);
            return ZUH_ERR_TLS;
        }
        SecTrustSetAnchorCertificates(trust, anchors);
        SecTrustSetAnchorCertificatesOnly(trust, false);   /* ADDS */
        CFRelease(anchors);
    }

    if (!cfg->verify_peer) return ZUH_OK;

    if (evaluate_under_policy(trust, host, cfg->verify_hostname, cfg->revocation,
                              detail, sizeof detail, &os_code))
        return ZUH_OK;

    if (cfg->verify_hostname &&
        evaluate_under_policy(trust, NULL, 0, cfg->revocation, NULL, 0, NULL)) {
        zuh_error_set(err, ZUH_ERR_TLS_HOSTNAME, ZUH_PHASE_TLS,
                      "certificate is valid but not for '%s': %s",
                      host ? host : "(unknown)", detail);
        zuh_error_set_backend(err, "sectrust", (int)os_code);
        return ZUH_ERR_TLS_HOSTNAME;
    }
    zuh_error_set(err, ZUH_ERR_TLS_CERT, ZUH_PHASE_TLS,
                  "certificate verification failed for '%s': %s",
                  host ? host : "(unknown)", detail);
    zuh_error_set_backend(err, "sectrust", (int)os_code);
    return ZUH_ERR_TLS_CERT;
}

static char *dup_plain(const char *s) {
    size_t n;
    char *d;
    if (!s) return NULL;
    n = strlen(s) + 1;
    d = (char *)malloc(n);
    if (d) memcpy(d, s, n);
    return d;
}

/* --- state shared with the completions ----------------------------------- */

enum { NW_SETUP = 0, NW_READY, NW_FAILED, NW_CANCELLED };

typedef struct {
    pthread_mutex_t mu;
    int             refs;
    int             pipe_r, pipe_w;

    int             state;
    int             nw_domain, nw_code;     /* the failure, when there is one */

    unsigned char  *rx;                     /* received, not yet read */
    size_t          rx_len, rx_cap, rx_off;
    int             rx_pending, rx_eof, rx_failed;

    int             sends_pending, send_failed;

    nw_trust_cfg    trust;
    int             verify_ran;
    zuh_error       verify_err;             /* set when the block said no */

    int             report_done;            /* §35.1 establishment report */
    long            t_dns, t_connect, t_tls;
} nw_shared;

static void shared_free(nw_shared *sh) {
    if (sh->pipe_r >= 0) close(sh->pipe_r);
    if (sh->pipe_w >= 0) close(sh->pipe_w);
    free(sh->rx);
    free(sh->trust.hostname);
    free(sh->trust.ca_file);
    free(sh->trust.ca_extra_file);
    pthread_mutex_destroy(&sh->mu);
    free(sh);
}

static void shared_retain(nw_shared *sh) {
    pthread_mutex_lock(&sh->mu);
    sh->refs++;
    pthread_mutex_unlock(&sh->mu);
}

static void shared_release(nw_shared *sh) {
    int last;
    pthread_mutex_lock(&sh->mu);
    last = (--sh->refs == 0);
    pthread_mutex_unlock(&sh->mu);
    if (last) shared_free(sh);
}

/* Wake the caller's poll loop. Non-blocking: if the pipe is full the reader
 * already has a wake-up pending, which is all one byte means. */
static void wake(nw_shared *sh) {
    char c = 1;
    ssize_t r = write(sh->pipe_w, &c, 1);
    (void)r;
}

static void drain(nw_shared *sh) {
    char buf[64];
    while (read(sh->pipe_r, buf, sizeof buf) > 0) {}
}

/* Append under the lock; plain realloc, see the file comment. */
static int rx_append(nw_shared *sh, const void *data, size_t n) {
    if (sh->rx_off && sh->rx_off == sh->rx_len) sh->rx_off = sh->rx_len = 0;
    if (sh->rx_len + n > sh->rx_cap) {
        size_t cap = sh->rx_cap ? sh->rx_cap : NW_RX_CHUNK;
        unsigned char *p;
        while (cap < sh->rx_len + n) cap *= 2;
        p = (unsigned char *)realloc(sh->rx, cap);
        if (!p) return 0;
        sh->rx = p;
        sh->rx_cap = cap;
    }
    memcpy(sh->rx + sh->rx_len, data, n);
    sh->rx_len += n;
    return 1;
}

/* --- the stream ----------------------------------------------------------- */

typedef struct {
    nw_shared        *sh;
    nw_connection_t   conn;
    dispatch_queue_t  queue;
    long              pid;          /* the creating process (§26.4) */
    zuh_tick_fn       tick;
    void             *tick_ctx;
    int               tick_ms;
    zuh_tls_info      info;
    char              peer_ip[64];
} nw_impl;

typedef int (*nw_pred)(const nw_shared *sh);

/* Wait until `pred` holds, the deadline passes or the tick asks to stop. The
 * only blocking call in the backend, and it is poll() on our own pipe in
 * slices of one tick, so §25.1 holds. */
static zuh_code wait_for(nw_impl *m, nw_pred pred, zuh_deadline d, zuh_phase phase,
                         zuh_error *err) {
    nw_shared *sh = m->sh;
    for (;;) {
        int done, ms;
        struct pollfd p;
        pthread_mutex_lock(&sh->mu);
        done = pred(sh);
        pthread_mutex_unlock(&sh->mu);
        if (done) return ZUH_OK;
        if (m->tick && m->tick(m->tick_ctx)) {
            zuh_error_set(err, ZUH_ERR_CANCELLED, phase, "request cancelled");
            return ZUH_ERR_CANCELLED;
        }
        if (zuh_deadline_expired(d)) {
            zuh_error_set(err, ZUH_ERR_TIMEOUT, phase, "timed out");
            return ZUH_ERR_TIMEOUT;
        }
        ms = zuh_deadline_poll_ms(d, m->tick_ms > 0 ? m->tick_ms : 100);
        p.fd = sh->pipe_r; p.events = POLLIN; p.revents = 0;
        if (poll(&p, 1, ms) > 0) drain(sh);
    }
}

static int pred_rx(const nw_shared *sh) {
    return sh->rx_len > sh->rx_off || sh->rx_eof || sh->rx_failed
        || sh->state == NW_FAILED || sh->state == NW_CANCELLED;
}
static int pred_sent(const nw_shared *sh) {
    return sh->sends_pending == 0 || sh->send_failed
        || sh->state == NW_FAILED || sh->state == NW_CANCELLED;
}
static int pred_settled(const nw_shared *sh) { return sh->state != NW_SETUP; }
static int pred_cancelled(const nw_shared *sh) { return sh->state == NW_CANCELLED; }
static int pred_report(const nw_shared *sh) { return sh->report_done; }

/* Keep exactly one receive outstanding while the connection lives. Arriving
 * bytes are buffered for read(), and a peer's close is noticed while the
 * connection sits idle in the pool, which is what readable() reports (§26.2).
 * Caller holds the lock. */
static void arm_receive_locked(nw_impl *m) {
    nw_shared *sh = m->sh;
    if (sh->rx_pending || sh->rx_eof || sh->rx_failed || sh->state != NW_READY) return;
    sh->rx_pending = 1;
    sh->refs++;
    nw_connection_receive(m->conn, 1, NW_RX_CHUNK,
        ^(dispatch_data_t content, nw_content_context_t ctx, bool complete,
          nw_error_t error) {
        (void)ctx;
        pthread_mutex_lock(&sh->mu);
        if (content) {
            dispatch_data_apply(content,
                ^bool(dispatch_data_t r, size_t off, const void *buf, size_t len) {
                (void)r; (void)off;
                if (!rx_append(sh, buf, len)) sh->rx_failed = 1;
                return !sh->rx_failed;
            });
        }
        if (error) {
            sh->rx_failed = 1;
            sh->nw_domain = (int)nw_error_get_error_domain(error);
            sh->nw_code   = nw_error_get_error_code(error);
        } else if (complete) {
            sh->rx_eof = 1;            /* the peer closed its side */
        }
        sh->rx_pending = 0;
        pthread_mutex_unlock(&sh->mu);
        wake(sh);
        shared_release(sh);
    });
}

static zuh_ssize nw_stream_read(zuh_stream *s, void *buf, size_t n, zuh_deadline d,
                                zuh_error *err) {
    nw_impl *m = (nw_impl *)s->impl;
    nw_shared *sh = m->sh;
    zuh_code rc;
    size_t take;

    pthread_mutex_lock(&sh->mu);
    arm_receive_locked(m);
    pthread_mutex_unlock(&sh->mu);
    rc = wait_for(m, pred_rx, d, ZUH_PHASE_READ, err);
    if (rc != ZUH_OK) return -1;

    pthread_mutex_lock(&sh->mu);
    take = sh->rx_len - sh->rx_off;
    if (take > 0) {
        if (take > n) take = n;
        memcpy(buf, sh->rx + sh->rx_off, take);
        sh->rx_off += take;
        arm_receive_locked(m);
        pthread_mutex_unlock(&sh->mu);
        return (zuh_ssize)take;
    }
    if (sh->rx_eof) { pthread_mutex_unlock(&sh->mu); return 0; }
    pthread_mutex_unlock(&sh->mu);
    zuh_error_set(err, ZUH_ERR_IO, ZUH_PHASE_READ,
                  "connection failed while reading (Network.framework domain %d, code %d)",
                  sh->nw_domain, sh->nw_code);
    return -1;
}

static zuh_ssize nw_stream_write(zuh_stream *s, const void *buf, size_t n,
                                 zuh_deadline d, zuh_error *err) {
    nw_impl *m = (nw_impl *)s->impl;
    nw_shared *sh = m->sh;
    dispatch_data_t data;
    zuh_code rc;
    int failed;

    if (n == 0) return 0;
    pthread_mutex_lock(&sh->mu);
    if (sh->state != NW_READY) {
        pthread_mutex_unlock(&sh->mu);
        zuh_error_set(err, ZUH_ERR_IO, ZUH_PHASE_WRITE, "connection is not open");
        return -1;
    }
    sh->sends_pending++;
    sh->refs++;
    pthread_mutex_unlock(&sh->mu);

    /* DISPATCH_DATA_DESTRUCTOR_DEFAULT copies `buf`, so the caller's buffer
     * is free the moment this returns, whatever the completion does. */
    data = dispatch_data_create(buf, n, NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
    nw_connection_send(m->conn, data, NW_CONNECTION_DEFAULT_STREAM_CONTEXT, false,
        ^(nw_error_t error) {
        pthread_mutex_lock(&sh->mu);
        sh->sends_pending--;
        if (error) {
            sh->send_failed = 1;
            sh->nw_domain = (int)nw_error_get_error_domain(error);
            sh->nw_code   = nw_error_get_error_code(error);
        }
        pthread_mutex_unlock(&sh->mu);
        wake(sh);
        shared_release(sh);
    });
    dispatch_release(data);

    /* A write returns when Network.framework has taken the bytes, as a
     * blocking send() would, so the caller's deadline covers the transfer. */
    rc = wait_for(m, pred_sent, d, ZUH_PHASE_WRITE, err);
    if (rc != ZUH_OK) return -1;
    pthread_mutex_lock(&sh->mu);
    failed = sh->send_failed || sh->state != NW_READY;
    pthread_mutex_unlock(&sh->mu);
    if (failed) {
        zuh_error_set(err, ZUH_ERR_IO, ZUH_PHASE_WRITE,
                      "connection failed while writing (Network.framework domain %d, code %d)",
                      sh->nw_domain, sh->nw_code);
        return -1;
    }
    return (zuh_ssize)n;
}

/* §26.2: is anything waiting on an idle connection? Data, a close or a
 * failure all mean "do not reuse". With no descriptor to probe, the answer
 * comes from the receive kept outstanding by arm_receive_locked(). */
static int nw_stream_readable(zuh_stream *s, int timeout_ms) {
    nw_impl *m = (nw_impl *)s->impl;
    nw_shared *sh = m->sh;
    int r;
    pthread_mutex_lock(&sh->mu);
    arm_receive_locked(m);
    r = pred_rx(sh);
    pthread_mutex_unlock(&sh->mu);
    if (r || timeout_ms <= 0) return r;
    {
        struct pollfd p;
        p.fd = sh->pipe_r; p.events = POLLIN; p.revents = 0;
        if (poll(&p, 1, timeout_ms) > 0) drain(sh);
    }
    pthread_mutex_lock(&sh->mu);
    r = pred_rx(sh);
    pthread_mutex_unlock(&sh->mu);
    return r;
}

/* Cancel, and wait briefly for the cancelled state so the shared state is
 * normally freed here rather than later on the queue. Not bounded by the
 * request's deadline, which may already have passed: a second at most, and
 * the 2026-09-26 probe measured 0.4 ms (F-16). */
static void nw_cancel_and_settle(nw_impl *m) {
    if (!m->conn) return;
    nw_connection_cancel(m->conn);
    {
        zuh_error ignored;
        zuh_tick_fn tick = m->tick;
        zuh_error_clear(&ignored);
        m->tick = NULL;
        (void)wait_for(m, pred_cancelled, zuh_deadline_in(1000), ZUH_PHASE_NONE, &ignored);
        m->tick = tick;
    }
}

static void nw_impl_free(nw_impl *m) {
    if (!m) return;
    if (zuh_pid_current() != m->pid) {
        /* Inherited across fork(): every Network.framework and libdispatch
         * call here would kill the child (F-19), and the connection is the
         * parent's anyway. Leak it, as the pool's fork drop intends. */
        zuh_free(m);
        return;
    }
    if (m->conn) {
        nw_cancel_and_settle(m);
        nw_release(m->conn);
        m->conn = NULL;
    }
    if (m->queue) dispatch_release(m->queue);
    if (m->sh) shared_release(m->sh);
    zuh_free(m);
}

static void nw_stream_close(zuh_stream *s) {
    nw_impl *m = (nw_impl *)s->impl;
    if (!m || !m->conn || zuh_pid_current() != m->pid) return;
    nw_cancel_and_settle(m);
}

static void nw_stream_destroy(zuh_stream *s) {
    if (!s) return;
    nw_impl_free((nw_impl *)s->impl);
    zuh_free(s);
}

static const zuh_stream_vtable k_nw_vt = {
    "tls-network-framework",
    nw_stream_read, nw_stream_write, nw_stream_close, nw_stream_destroy,
    nw_stream_readable
};

/* --- backend identity ----------------------------------------------------- */

int zuh_tls_available(void) { return 1; }

const char *zuh_tls_backend_name(void) { return "network-framework"; }

/* Pins wait for W9's DER walker, which gives the leaf's SPKI without
 * OpenSSL; until then they are refused (D-56). Everything else is honoured:
 * TLS 1.3 through sec_protocol_options (F-14), and ca_file, ca_extra and
 * revocation through SecTrust in the verify block (F-13). */
unsigned zuh_tls_backend_caps(void) {
    return ZUH_TLS_CAP_TLS13 | ZUH_TLS_CAP_CA_FILE | ZUH_TLS_CAP_CA_EXTRA
         | ZUH_TLS_CAP_REVOCATION | ZUH_TLS_CAP_DIALS;
}

/* The engine dials HTTPS on this backend (ZUH_TLS_CAP_DIALS) and never asks
 * to wrap a stream; this exists because every backend defines it. */
zuh_code zuh_tls_connect(zuh_stream **out, zuh_stream *inner, const char *hostname,
                         const zuh_tls_config *cfg, zuh_deadline deadline,
                         zuh_error *err) {
    (void)inner; (void)hostname; (void)cfg; (void)deadline;
    if (out) *out = NULL;
    zuh_error_set(err, ZUH_ERR_TLS, ZUH_PHASE_TLS,
                  "the Network.framework backend opens its own connections (D-71)");
    return ZUH_ERR_TLS;
}

void zuh_tls_stream_free(zuh_stream *s) { nw_stream_destroy(s); }

int zuh_tls_get_info(const zuh_stream *s, zuh_tls_info *out) {
    if (!s || s->vt != &k_nw_vt || !out) return 0;
    *out = ((const nw_impl *)s->impl)->info;
    return 1;
}

int zuh_tls_peer_ip(const zuh_stream *s, char *buf, size_t n) {
    const nw_impl *m;
    if (!s || s->vt != &k_nw_vt || !buf || n == 0) return 0;
    m = (const nw_impl *)s->impl;
    if (!m->peer_ip[0]) return 0;
    snprintf(buf, n, "%s", m->peer_ip);
    return 1;
}

/* --- dialling ------------------------------------------------------------- */

/* §35.2: protocol and cipher from the negotiated session. */
static void record_info(nw_impl *m) {
    nw_protocol_definition_t def = nw_protocol_copy_tls_definition();
    nw_protocol_metadata_t md = nw_connection_copy_protocol_metadata(m->conn, def);
    memset(&m->info, 0, sizeof m->info);
    snprintf(m->info.trust_backend, sizeof m->info.trust_backend, "sectrust");
    if (md) {
        sec_protocol_metadata_t sm = nw_tls_copy_sec_protocol_metadata(md);
        if (sm) {
            tls_protocol_version_t v =
                sec_protocol_metadata_get_negotiated_tls_protocol_version(sm);
            const char *name;
            snprintf(m->info.protocol, sizeof m->info.protocol, "%s",
                     v == tls_protocol_version_TLSv13 ? "TLSv1.3"
                   : v == tls_protocol_version_TLSv12 ? "TLSv1.2" : "TLS");
            name = zuh_tls_cipher_name(
                (unsigned)sec_protocol_metadata_get_negotiated_tls_ciphersuite(sm));
            if (name) snprintf(m->info.cipher, sizeof m->info.cipher, "%s", name);
            sec_release(sm);
        }
        nw_release(md);
    }
    nw_release(def);
}

/* §35.2 remote_ip. Through a proxy this is the PROXY's address, which is
 * who we are connected to, as on the other backends. */
static void record_peer(nw_impl *m) {
    nw_path_t path = nw_connection_copy_current_path(m->conn);
    m->peer_ip[0] = '\0';
    if (!path) return;
    {
        nw_endpoint_t ep = nw_path_copy_effective_remote_endpoint(path);
        if (ep) {
            if (nw_endpoint_get_type(ep) == nw_endpoint_type_address) {
                const struct sockaddr *sa = nw_endpoint_get_address(ep);
                if (sa && getnameinfo(sa, (socklen_t)sa->sa_len, m->peer_ip,
                                      sizeof m->peer_ip, NULL, 0, NI_NUMERICHOST) != 0)
                    m->peer_ip[0] = '\0';
            }
            nw_release(ep);
        }
    }
    nw_release(path);
}

/* §35.1 dns, connect and tls, and the §35.3 events that bound them, from the
 * establishment report: only Network.framework can see those boundaries now,
 * as only zuh_net could for a plain socket. The events are laid out from
 * `t0`, the moment the dial began, using the reported durations; a phase the
 * report does not give takes no time and its timing stays -1. */
static void record_phases(nw_impl *m, const zuh_net_opts *opts, zuh_millis t0,
                          zuh_deadline d) {
    nw_shared *sh = m->sh;
    zuh_timings *t = opts ? opts->timings : NULL;
    zuh_trace *tr = opts ? opts->trace : NULL;
    const char *host = sh->trust.hostname;
    zuh_error ignored;
    long dns = -1, tcp = -1, tls = -1;
    zuh_millis at = t0;

    if (!t && !tr) return;
    sh->t_dns = sh->t_connect = sh->t_tls = -1;
    shared_retain(sh);
    nw_connection_access_establishment_report(m->conn, m->queue,
        ^(nw_establishment_report_t report) {
        if (report) {
            __block long r_dns = -1, r_tcp = -1, r_tls = -1;
            nw_protocol_definition_t tcpdef = nw_protocol_copy_tcp_definition();
            nw_protocol_definition_t tlsdef = nw_protocol_copy_tls_definition();
            nw_establishment_report_enumerate_resolutions(report,
                ^bool(nw_report_resolution_source_t source, uint64_t ms,
                      uint32_t count, nw_endpoint_t ok, nw_endpoint_t pref) {
                (void)source; (void)count; (void)ok; (void)pref;
                r_dns = (r_dns < 0 ? 0 : r_dns) + (long)ms;
                return true;
            });
            nw_establishment_report_enumerate_protocols(report,
                ^bool(nw_protocol_definition_t p, uint64_t ms, uint64_t rtt) {
                (void)rtt;
                if (nw_protocol_definition_is_equal(p, tcpdef)) r_tcp = (long)ms;
                else if (nw_protocol_definition_is_equal(p, tlsdef)) r_tls = (long)ms;
                return true;
            });
            nw_release(tcpdef);
            nw_release(tlsdef);
            pthread_mutex_lock(&sh->mu);
            sh->t_dns = r_dns; sh->t_connect = r_tcp; sh->t_tls = r_tls;
            pthread_mutex_unlock(&sh->mu);
        }
        pthread_mutex_lock(&sh->mu);
        sh->report_done = 1;
        pthread_mutex_unlock(&sh->mu);
        wake(sh);
        shared_release(sh);
    });
    zuh_error_clear(&ignored);
    (void)wait_for(m, pred_report, zuh_deadline_min(d, zuh_deadline_in(250)),
                   ZUH_PHASE_TLS, &ignored);
    pthread_mutex_lock(&sh->mu);
    if (sh->report_done) { dns = sh->t_dns; tcp = sh->t_connect; tls = sh->t_tls; }
    pthread_mutex_unlock(&sh->mu);

    if (t) {
        if (dns >= 0) t->dns = dns;
        if (tcp >= 0) t->connect = tcp;
        if (tls >= 0) t->tls = tls;
    }
    zuh_trace_add_at(tr, ZUH_EV_DNS_START, host, 0, at);
    at += dns > 0 ? dns : 0;
    zuh_trace_add_at(tr, ZUH_EV_DNS_DONE, host, 0, at);
    zuh_trace_add_at(tr, ZUH_EV_CONNECT_START, host, 0, at);
    at += tcp > 0 ? tcp : 0;
    zuh_trace_add_at(tr, ZUH_EV_CONNECT_DONE, m->peer_ip[0] ? m->peer_ip : host, 0, at);
    zuh_trace_add_at(tr, ZUH_EV_TLS_START, host, 0, at);
    at += tls > 0 ? tls : 0;
    zuh_trace_add_at(tr, ZUH_EV_TLS_DONE,
                     m->info.protocol[0] ? m->info.protocol : "tls", 0, at);
}

/* Map a failed or waiting connection to the §34.1 class it deserves. The
 * verify block's own verdict wins: it knows a hostname mismatch from a bad
 * chain, which a TLS alert code does not say. */
static zuh_code failure_error(const nw_shared *sh, const char *host, uint16_t port,
                              int via_proxy, zuh_error *err) {
    if (sh->verify_err.code != ZUH_OK) {
        *err = sh->verify_err;
        return sh->verify_err.code;
    }
    if (sh->nw_domain == (int)nw_error_domain_dns) {
        zuh_error_set(err, ZUH_ERR_DNS, ZUH_PHASE_DNS,
                      "could not resolve '%s' (DNS error %d)", host, sh->nw_code);
        zuh_error_set_backend(err, "network-framework", sh->nw_code);
        return ZUH_ERR_DNS;
    }
    if (sh->nw_domain == (int)nw_error_domain_tls) {
        zuh_error_set(err, ZUH_ERR_TLS_HANDSHAKE, ZUH_PHASE_TLS,
                      "TLS handshake with '%s' failed (OSStatus %d)", host, sh->nw_code);
        zuh_error_set_backend(err, "network-framework", sh->nw_code);
        return ZUH_ERR_TLS_HANDSHAKE;
    }
    if (via_proxy && sh->nw_domain == (int)nw_error_domain_posix
        && sh->nw_code == EAUTH) {
        /* Network.framework's report of a 407 to our CONNECT. */
        zuh_error_set(err, ZUH_ERR_PROXY_AUTH, ZUH_PHASE_CONNECT,
                      "the proxy refused the tunnel to '%s:%u': it requires "
                      "authentication (HTTP 407), and the credentials given, if any, "
                      "were not accepted", host, (unsigned)port);
        zuh_error_set_backend(err, "network-framework", sh->nw_code);
        return ZUH_ERR_PROXY_AUTH;
    }
    if (via_proxy) {
        /* §20.3 asks for the proxy's own status; Network.framework does not
         * report it, only that the tunnel was not opened. */
        zuh_error_set(err, ZUH_ERR_PROXY, ZUH_PHASE_CONNECT,
                      "the proxy did not open a tunnel to '%s:%u' (%s); "
                      "Network.framework does not report the proxy's HTTP status",
                      host, (unsigned)port,
                      sh->nw_code ? strerror(sh->nw_code) : "connection failed");
        zuh_error_set_backend(err, "network-framework", sh->nw_code);
        return ZUH_ERR_PROXY;
    }
    zuh_error_set(err, ZUH_ERR_CONNECT, ZUH_PHASE_CONNECT,
                  "could not connect to '%s:%u': %s", host, (unsigned)port,
                  sh->nw_code ? strerror(sh->nw_code) : "connection failed");
    zuh_error_set_backend(err, "network-framework", sh->nw_code);
    return ZUH_ERR_CONNECT;
}

static int set_cloexec_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) return 0;
    return fcntl(fd, F_SETFD, FD_CLOEXEC) == 0;
}

zuh_code zuh_tls_dial(zuh_stream **out, const char *host, uint16_t port,
                      const zuh_proxy *proxy, const zuh_tls_config *cfg,
                      zuh_deadline deadline, const zuh_net_opts *opts,
                      zuh_error *err) {
    static zuh_fork_guard g_guard;
    static int g_armed = 0;
    int via_proxy = proxy && proxy->in_use;
    nw_shared *sh = NULL;
    nw_impl *m = NULL;
    zuh_stream *s = NULL;
    nw_parameters_t params = NULL;
    nw_endpoint_t endpoint = NULL;
    char portstr[8];
    int fds[2];
    zuh_code rc;
    zuh_millis t0;

    if (!out || !host || !cfg) return ZUH_ERR_TLS;
    *out = NULL;

    /* §26.4, §13.2.1: in a forked child of a process that already used
     * Network.framework, the next call into it is SIGILL. Checked before the
     * first one, so the child gets a condition instead (F-19). */
    if (g_armed && zuh_fork_guard_tripped(&g_guard)) {
        zuh_error_set(err, ZUH_ERR_FORK, ZUH_PHASE_TLS, "%s", zuh_fork_message());
        return ZUH_ERR_FORK;
    }

    rc = zuh_tls_config_check(cfg, zuh_tls_backend_caps(), zuh_tls_backend_name(), err);
    if (rc != ZUH_OK) return rc;

    if (via_proxy) {
        int have_api = 0;
        if (!ZUH_NW_ASSUME_NO_PROXY_API) {
            if (__builtin_available(macOS 14.0, *)) have_api = 1;
        }
        if (!have_api) {
            /* D-71: HTTP CONNECT is Network.framework's to do, and its API
             * for it is macOS 14+. Refused rather than sent direct, which is
             * what an unset proxy would do (D-56's rule, applied here). */
            zuh_error_set(err, ZUH_ERR_PROXY, ZUH_PHASE_CONNECT,
                          "HTTPS through a proxy needs macOS 14 or later: on macOS "
                          "zuhttp's TLS engine is Network.framework, whose HTTP CONNECT "
                          "support starts there. Plain http:// through the proxy, and "
                          "direct HTTPS, work on this system.");
            return ZUH_ERR_PROXY;
        }
    }

    if (pipe(fds) != 0) {
        zuh_error_set(err, ZUH_ERR_IO, ZUH_PHASE_CONNECT, "pipe() failed: %s",
                      strerror(errno));
        return ZUH_ERR_IO;
    }
    sh = (nw_shared *)calloc(1, sizeof *sh);
    m  = (nw_impl *)zuh_alloc(sizeof *m);
    s  = (zuh_stream *)zuh_alloc(sizeof *s);
    if (!sh || !m || !s) {
        free(sh); zuh_free(m); zuh_free(s);
        close(fds[0]); close(fds[1]);
        return ZUH_ERR_NOMEM;
    }
    memset(m, 0, sizeof *m);
    pthread_mutex_init(&sh->mu, NULL);
    sh->refs = 1;                         /* the stream's */
    sh->pipe_r = fds[0];
    sh->pipe_w = fds[1];
    zuh_error_clear(&sh->verify_err);
    if (!set_cloexec_nonblock(fds[0]) || !set_cloexec_nonblock(fds[1])) {
        shared_free(sh); zuh_free(m); zuh_free(s);
        zuh_error_set(err, ZUH_ERR_IO, ZUH_PHASE_CONNECT, "cannot configure pipe");
        return ZUH_ERR_IO;
    }
    sh->trust.hostname        = dup_plain(host);
    sh->trust.ca_file         = dup_plain(cfg->ca_file);
    sh->trust.ca_extra_file   = dup_plain(cfg->ca_extra_file);
    sh->trust.source_file     = (cfg->source == ZUH_TRUST_FILE);
    sh->trust.verify_peer     = cfg->verify_peer;
    sh->trust.verify_hostname = cfg->verify_hostname;
    sh->trust.revocation      = cfg->revocation;

    m->sh       = sh;
    m->pid      = zuh_pid_current();
    m->tick     = opts ? opts->tick : NULL;
    m->tick_ctx = opts ? opts->tick_ctx : NULL;
    m->tick_ms  = opts && opts->tick_ms > 0 ? opts->tick_ms : 100;
    s->vt   = &k_nw_vt;
    s->impl = m;

    if (!g_armed) { zuh_fork_guard_arm(&g_guard); g_armed = 1; }
    m->queue = dispatch_queue_create("org.zuhttp.network", DISPATCH_QUEUE_SERIAL);

    {
        int min13 = cfg->min_version >= 13;
        dispatch_queue_t q = m->queue;
        params = nw_parameters_create_secure_tcp(
            ^(nw_protocol_options_t tls) {
            sec_protocol_options_t so = nw_tls_copy_sec_protocol_options(tls);
            sec_protocol_options_set_min_tls_protocol_version(so,
                min13 ? tls_protocol_version_TLSv13 : tls_protocol_version_TLSv12);
            sec_protocol_options_add_tls_application_protocol(so, "http/1.1");
            /* §13.1: the engine is Apple's, the trust decision is ours. On
             * the connection's own queue, so it is ordered with every other
             * completion and runs before the cancelled state. */
            sec_protocol_options_set_verify_block(so,
                ^(sec_protocol_metadata_t md, sec_trust_t st,
                  sec_protocol_verify_complete_t done) {
                SecTrustRef tr = sec_trust_copy_ref(st);
                zuh_error verdict;
                zuh_code v;
                (void)md;
                zuh_error_clear(&verdict);
                v = tr ? check_trust(tr, &sh->trust, &verdict) : ZUH_ERR_TLS_CERT;
                if (!tr) zuh_error_set(&verdict, ZUH_ERR_TLS_CERT, ZUH_PHASE_TLS,
                                       "the server presented no certificate");
                if (tr) CFRelease(tr);
                pthread_mutex_lock(&sh->mu);
                sh->verify_ran = 1;
                if (v != ZUH_OK) sh->verify_err = verdict;
                pthread_mutex_unlock(&sh->mu);
                done(v == ZUH_OK);
            }, q);
            sec_release(so);
        }, NW_PARAMETERS_DEFAULT_CONFIGURATION);
    }

    if (via_proxy) {
        if (__builtin_available(macOS 14.0, *)) {
            char pport[8];
            nw_endpoint_t pe;
            nw_proxy_config_t pc;
            nw_privacy_context_t ctx;
            snprintf(pport, sizeof pport, "%u", (unsigned)proxy->port);
            pe  = nw_endpoint_create_host(proxy->host, pport);
            pc  = nw_proxy_config_create_http_connect(pe, NULL);
            /* §20.4: Basic credentials go to the proxy and nowhere else. */
            if (proxy->username)
                nw_proxy_config_set_username_and_password(pc, proxy->username,
                    proxy->password ? proxy->password : "");
            ctx = nw_privacy_context_create("org.zuhttp.proxy");
            nw_privacy_context_add_proxy(ctx, pc);
            nw_parameters_set_privacy_context(params, ctx);
            nw_release(ctx); nw_release(pc); nw_release(pe);
        }
    } else {
        /* zuhttp has already decided this hop goes direct (§20.1). This is a
         * preference, not a guarantee, against a system proxy (F-20). */
        nw_parameters_set_prefer_no_proxy(params, true);
    }

    snprintf(portstr, sizeof portstr, "%u", (unsigned)port);
    endpoint = nw_endpoint_create_host(host, portstr);
    m->conn = nw_connection_create(endpoint, params);
    nw_release(endpoint);
    nw_release(params);
    if (!m->conn) {
        zuh_error_set(err, ZUH_ERR_CONNECT, ZUH_PHASE_CONNECT,
                      "could not create a connection to '%s'", host);
        nw_stream_destroy(s);
        return ZUH_ERR_CONNECT;
    }
    nw_connection_set_queue(m->conn, m->queue);

    sh->refs++;                           /* the connection's; see file comment */
    nw_connection_set_state_changed_handler(m->conn,
        ^(nw_connection_state_t state, nw_error_t error) {
        int release = 0;
        pthread_mutex_lock(&sh->mu);
        if (error) {
            sh->nw_domain = (int)nw_error_get_error_domain(error);
            sh->nw_code   = nw_error_get_error_code(error);
        }
        switch (state) {
        case nw_connection_state_ready:
            if (sh->state == NW_SETUP) sh->state = NW_READY;
            break;
        case nw_connection_state_waiting:
            /* Network.framework waits and retries on, for example, a refused
             * connection. zuhttp reports it instead: the caller's retry
             * policy decides about retrying (§33). */
            if (error && sh->state == NW_SETUP) sh->state = NW_FAILED;
            break;
        case nw_connection_state_failed:
            if (sh->state != NW_CANCELLED) sh->state = NW_FAILED;
            break;
        case nw_connection_state_cancelled:
            sh->state = NW_CANCELLED;
            release = 1;
            break;
        default:
            break;
        }
        pthread_mutex_unlock(&sh->mu);
        wake(sh);
        if (release) shared_release(sh);
    });

    t0 = zuh_now_ms();
    nw_connection_start(m->conn);

    rc = wait_for(m, pred_settled, deadline, ZUH_PHASE_CONNECT, err);
    if (rc == ZUH_OK) {
        int ready;
        pthread_mutex_lock(&sh->mu);
        ready = (sh->state == NW_READY);
        pthread_mutex_unlock(&sh->mu);
        if (!ready) rc = failure_error(sh, host, port, via_proxy, err);
    } else if (rc == ZUH_ERR_TIMEOUT) {
        int verified;
        pthread_mutex_lock(&sh->mu);
        verified = sh->verify_ran;
        pthread_mutex_unlock(&sh->mu);
        if (err) err->phase = verified ? ZUH_PHASE_TLS : ZUH_PHASE_CONNECT;
    }
    if (rc != ZUH_OK) {
        nw_stream_destroy(s);
        return rc;
    }

    record_info(m);
    record_peer(m);
    record_phases(m, opts, t0, deadline);
    pthread_mutex_lock(&sh->mu);
    arm_receive_locked(m);
    pthread_mutex_unlock(&sh->mu);
    *out = s;
    return ZUH_OK;
}

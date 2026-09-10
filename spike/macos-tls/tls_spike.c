/*
 * zuhttp — Stage S0: macOS TLS feasibility spike
 * See .agents/roadmap.md (S0) and .agents/zuhttp-design.md §13.2, Appendix B R-1.
 *
 * Question this program answers:
 *
 *   Can we establish a TLS connection on macOS, evaluate the certificate
 *   chain against the *system Keychain*, and drive the whole thing from a
 *   synchronous non-blocking poll loop that WE own, with no background
 *   thread and no dispatch queue?
 *
 * It implements two engines behind one interface:
 *
 *   openssl  — portable protocol engine + SecTrustEvaluateWithError trust
 *              (the design's preferred D-4 split, §13.1)
 *   st       — Secure Transport + SecTrustEvaluateWithError trust
 *              (the §13.2 fallback; deprecated since macOS 10.15)
 *
 * Both route trust through the same sectrust_evaluate() so the trust side
 * is compared on equal terms.
 *
 * NOT production code. No cleanup on error paths beyond what is needed to
 * keep the measurements honest. Leaks on failure are acceptable here.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <poll.h>
#include <netdb.h>
#include <sys/socket.h>

#include <mach/mach.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <Security/SecureTransport.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

/* ------------------------------------------------------------------ */
/* options                                                             */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *host;
    const char *port;
    const char *engine;      /* "openssl" | "st" */
    const char *anchor_pem;  /* extra/replacement anchor, or NULL */
    int         anchor_only; /* 1 = replace system trust, 0 = add to it */
    int         revocation;  /* 1 = add an explicit revocation policy */
    int         tick_ms;     /* poll interval == interrupt checkpoint cadence */
    int         total_ms;    /* overall deadline */
    int         quiet;
} opts;

/* ------------------------------------------------------------------ */
/* measurements                                                        */
/* ------------------------------------------------------------------ */

typedef struct {
    long checkpoints;        /* times we returned to an R-safe point */
    long max_block_us;       /* longest single blocking call */
    int  threads_start;
    int  threads_after_trust;
    int  threads_end;
    double t_connect_ms, t_handshake_ms, t_trust_ms, t_total_ms;
} metrics;

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static int thread_count(void) {
    thread_act_array_t list;
    mach_msg_type_number_t n = 0;
    if (task_threads(mach_task_self(), &list, &n) != KERN_SUCCESS) return -1;
    vm_deallocate(mach_task_self(), (vm_address_t)list, n * sizeof(thread_act_t));
    return (int)n;
}

/* ------------------------------------------------------------------ */
/* connection                                                          */
/* ------------------------------------------------------------------ */

typedef struct {
    int      fd;
    opts    *o;
    metrics *m;
    double   deadline;
} conn;

/* One bounded wait. This is precisely where R_CheckUserInterrupt() would go
 * in the real implementation (§25.1 step 3). */
static int wait_fd(conn *c, short events) {
    if (now_ms() > c->deadline) return -2;
    struct pollfd p = { .fd = c->fd, .events = events };
    double a = now_ms();
    int r = poll(&p, 1, c->o->tick_ms);
    double blocked_us = (now_ms() - a) * 1000.0;
    if (blocked_us > c->m->max_block_us) c->m->max_block_us = (long)blocked_us;
    c->m->checkpoints++;               /* <-- R_CheckUserInterrupt() here */
    return r;
}

static int tcp_connect(conn *c, const char *host, const char *port) {
    struct addrinfo hints, *res = NULL, *ai;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    /* NOTE: getaddrinfo() is synchronous and not interruptible. This is the
     * documented gap in design §8.4 / §25.4, and the spike does not fix it. */
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;

    for (ai = res; ai; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
        c->fd = fd;

        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            freeaddrinfo(res);
            return 0;
        }
        if (errno == EINPROGRESS) {
            for (;;) {
                int r = wait_fd(c, POLLOUT);
                if (r == -2) { close(fd); freeaddrinfo(res); return -2; }
                if (r > 0) {
                    int err = 0; socklen_t el = sizeof err;
                    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
                    if (err == 0) { freeaddrinfo(res); return 0; }
                    break;
                }
                if (r < 0) break;
            }
        }
        close(fd);
        c->fd = -1;
    }
    freeaddrinfo(res);
    return -1;
}

/* ------------------------------------------------------------------ */
/* trust: the part that must be native                                 */
/* ------------------------------------------------------------------ */

typedef struct {
    int   trusted;
    long  os_code;
    char  detail[512];
} trust_result;

static SecCertificateRef der_to_sec(const unsigned char *der, int len) {
    CFDataRef d = CFDataCreate(NULL, der, len);
    if (!d) return NULL;
    SecCertificateRef c = SecCertificateCreateWithData(NULL, d);
    CFRelease(d);
    return c;
}

/* Load a PEM bundle into a CFArray of SecCertificateRef (for --anchor). */
static CFArrayRef load_anchors(const char *pem_path) {
    FILE *f = fopen(pem_path, "r");
    if (!f) return NULL;
    CFMutableArrayRef arr = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    X509 *x;
    while ((x = PEM_read_X509(f, NULL, NULL, NULL)) != NULL) {
        unsigned char *der = NULL;
        int len = i2d_X509(x, &der);
        if (len > 0) {
            SecCertificateRef sc = der_to_sec(der, len);
            if (sc) { CFArrayAppendValue(arr, sc); CFRelease(sc); }
            OPENSSL_free(der);
        }
        X509_free(x);
    }
    fclose(f);
    if (CFArrayGetCount(arr) == 0) { CFRelease(arr); return NULL; }
    return arr;
}

/*
 * Evaluate a DER chain (leaf first) against the system Keychain.
 * This is SecTrustEvaluateWithError — API_AVAILABLE(macos(10.14)),
 * NOT deprecated. It is the whole point of the D-4 design.
 */
static void sectrust_evaluate(const unsigned char **ders, const int *lens, int n,
                              const char *hostname, const opts *o,
                              trust_result *out)
{
    memset(out, 0, sizeof *out);
    snprintf(out->detail, sizeof out->detail, "(no detail)");

    CFMutableArrayRef certs = CFArrayCreateMutable(NULL, n, &kCFTypeArrayCallBacks);
    for (int i = 0; i < n; i++) {
        SecCertificateRef sc = der_to_sec(ders[i], lens[i]);
        if (!sc) { snprintf(out->detail, sizeof out->detail, "bad DER at %d", i); goto done_certs; }
        CFArrayAppendValue(certs, sc);
        CFRelease(sc);
    }

    {
        CFStringRef h = CFStringCreateWithCString(NULL, hostname, kCFStringEncodingUTF8);
        SecPolicyRef policy = SecPolicyCreateSSL(true, h);   /* true => hostname is checked */
        SecTrustRef trust = NULL;

        /* An SSL policy alone does NOT check revocation (FINDINGS.md F-4).
         * A revocation policy must be added explicitly and combined. */
        CFMutableArrayRef policies = CFArrayCreateMutable(NULL, 2, &kCFTypeArrayCallBacks);
        CFArrayAppendValue(policies, policy);
        if (o->revocation) {
            SecPolicyRef rev = SecPolicyCreateRevocation(
                kSecRevocationUseAnyAvailableMethod | kSecRevocationRequirePositiveResponse);
            if (rev) { CFArrayAppendValue(policies, rev); CFRelease(rev); }
        }

        OSStatus st = SecTrustCreateWithCertificates(certs, policies, &trust);
        if (st != errSecSuccess || !trust) {
            snprintf(out->detail, sizeof out->detail, "SecTrustCreateWithCertificates failed (%d)", (int)st);
            out->os_code = st;
        } else {
            if (o->anchor_pem) {
                CFArrayRef anchors = load_anchors(o->anchor_pem);
                if (anchors) {
                    SecTrustSetAnchorCertificates(trust, anchors);
                    /* false => anchors are ADDITIVE to the system store (§14.2 ca_extra)
                     * true  => anchors REPLACE the system store   (§14.2 ca_file)  */
                    SecTrustSetAnchorCertificatesOnly(trust, o->anchor_only ? true : false);
                    CFRelease(anchors);
                }
            }

            CFErrorRef err = NULL;
            out->trusted = SecTrustEvaluateWithError(trust, &err) ? 1 : 0;
            if (err) {
                out->os_code = (long)CFErrorGetCode(err);
                CFStringRef d = CFErrorCopyDescription(err);
                if (d) {
                    CFStringGetCString(d, out->detail, sizeof out->detail, kCFStringEncodingUTF8);
                    CFRelease(d);
                }
                CFRelease(err);
            } else if (out->trusted) {
                snprintf(out->detail, sizeof out->detail, "trusted");
            }
            CFRelease(trust);
        }
        CFRelease(policies);
        CFRelease(policy);
        CFRelease(h);
    }

done_certs:
    CFRelease(certs);
}

/* ------------------------------------------------------------------ */
/* engine: OpenSSL protocol + SecTrust verification                     */
/* ------------------------------------------------------------------ */

typedef struct {
    conn         *c;
    trust_result  tr;
    int           trust_ran;
    double        t_trust_ms;
} ossl_state;

/* Called by OpenSSL during the handshake, in place of its own chain
 * verification. We hand the peer chain straight to the Keychain. */
static int ossl_verify_cb(X509_STORE_CTX *sctx, void *arg) {
    ossl_state *s = (ossl_state *)arg;

    STACK_OF(X509) *untrusted = X509_STORE_CTX_get0_untrusted(sctx);
    X509 *leaf = X509_STORE_CTX_get0_cert(sctx);

    const unsigned char *ders[16];
    int lens[16], n = 0;
    unsigned char *bufs[16];

    if (leaf) {
        unsigned char *d = NULL; int l = i2d_X509(leaf, &d);
        if (l > 0) { bufs[n] = d; ders[n] = d; lens[n] = l; n++; }
    }
    for (int i = 0; untrusted && i < sk_X509_num(untrusted) && n < 16; i++) {
        X509 *x = sk_X509_value(untrusted, i);
        if (x == leaf) continue;
        unsigned char *d = NULL; int l = i2d_X509(x, &d);
        if (l > 0) { bufs[n] = d; ders[n] = d; lens[n] = l; n++; }
    }

    double a = now_ms();
    sectrust_evaluate(ders, lens, n, s->c->o->host, s->c->o, &s->tr);
    s->t_trust_ms = now_ms() - a;
    s->trust_ran = 1;
    s->c->m->threads_after_trust = thread_count();

    for (int i = 0; i < n; i++) OPENSSL_free(bufs[i]);
    return s->tr.trusted ? 1 : 0;
}

/* Move bytes between our socket and OpenSSL's memory BIOs. */
static int flush_out(conn *c, BIO *wbio) {
    char buf[16384];
    int n;
    while ((n = BIO_read(wbio, buf, sizeof buf)) > 0) {
        int off = 0;
        while (off < n) {
            ssize_t w = send(c->fd, buf + off, n - off, 0);
            if (w > 0) { off += (int)w; continue; }
            if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                int r = wait_fd(c, POLLOUT);
                if (r == -2) return -2;
                if (r < 0)  return -1;
                continue;
            }
            return -1;
        }
    }
    return 0;
}

static int fill_in(conn *c, BIO *rbio) {
    char buf[16384];
    for (;;) {
        ssize_t r = recv(c->fd, buf, sizeof buf, 0);
        if (r > 0) { BIO_write(rbio, buf, (int)r); return 0; }
        if (r == 0) return -1;                       /* peer closed */
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            int p = wait_fd(c, POLLIN);
            if (p == -2) return -2;
            if (p < 0)   return -1;
            if (p == 0)  continue;                   /* tick expired; loop */
            continue;
        }
        return -1;
    }
}

static int run_openssl(conn *c, char *verdict, size_t vlen) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { snprintf(verdict, vlen, "SSL_CTX_new failed"); return 1; }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    ossl_state st = { .c = c };
    SSL_CTX_set_cert_verify_callback(ctx, ossl_verify_cb, &st);
    /* CRITICAL. Without SSL_VERIFY_PEER the client default is SSL_VERIFY_NONE,
     * under which returning 0 from the cert_verify_callback records the failure
     * but does NOT abort the handshake — every bad certificate is accepted.
     * See FINDINGS.md F-3: this is a silent verification bypass. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    SSL *ssl = SSL_new(ctx);
    BIO *rbio = BIO_new(BIO_s_mem());
    BIO *wbio = BIO_new(BIO_s_mem());
    BIO_set_mem_eof_return(rbio, -1);
    BIO_set_mem_eof_return(wbio, -1);
    SSL_set_bio(ssl, rbio, wbio);
    SSL_set_connect_state(ssl);
    SSL_set_tlsext_host_name(ssl, c->o->host);
    SSL_set1_host(ssl, c->o->host);

    double hs_start = now_ms();
    int rc = 1;
    for (;;) {
        int r = SSL_do_handshake(ssl);
        if (r == 1) { rc = 0; break; }
        int e = SSL_get_error(ssl, r);
        if (e == SSL_ERROR_WANT_READ) {
            if (flush_out(c, wbio) < 0) { snprintf(verdict, vlen, "write failed"); break; }
            int f = fill_in(c, rbio);
            if (f == -2) { snprintf(verdict, vlen, "deadline exceeded"); break; }
            if (f < 0)   { snprintf(verdict, vlen, "connection closed during handshake"); break; }
        } else if (e == SSL_ERROR_WANT_WRITE) {
            if (flush_out(c, wbio) < 0) { snprintf(verdict, vlen, "write failed"); break; }
        } else {
            unsigned long oe = ERR_peek_last_error();
            char eb[256]; ERR_error_string_n(oe, eb, sizeof eb);
            if (st.trust_ran && !st.tr.trusted)
                snprintf(verdict, vlen, "TRUST REJECTED: %s", st.tr.detail);
            else
                snprintf(verdict, vlen, "handshake failed: %s", eb);
            break;
        }
    }
    c->m->t_handshake_ms = now_ms() - hs_start;
    c->m->t_trust_ms     = st.t_trust_ms;

    if (rc == 0) {
        snprintf(verdict, vlen, "OK %s / %s / trust=%s",
                 SSL_get_version(ssl), SSL_get_cipher(ssl),
                 st.trust_ran ? (st.tr.trusted ? "SecTrust:yes" : "SecTrust:no") : "not-run");

        /* one real request/response, still on our poll loop */
        char req[512];
        int rl = snprintf(req, sizeof req,
                          "HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n"
                          "User-Agent: zuhttp-spike/0\r\n\r\n", c->o->host);
        int w = SSL_write(ssl, req, rl);
        if (w > 0) {
            flush_out(c, wbio);
            char resp[1024]; int got = 0;
            for (;;) {
                int n = SSL_read(ssl, resp + got, (int)sizeof resp - 1 - got);
                if (n > 0) { got += n; break; }
                int e = SSL_get_error(ssl, n);
                if (e == SSL_ERROR_WANT_READ) {
                    if (flush_out(c, wbio) < 0) break;
                    if (fill_in(c, rbio) < 0) break;
                    continue;
                }
                break;
            }
            if (got > 0) {
                resp[got] = 0;
                char *nl = strpbrk(resp, "\r\n");
                if (nl) *nl = 0;
                size_t used = strlen(verdict);
                snprintf(verdict + used, vlen - used, " | %s", resp);
            }
        }
    }

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return rc;
}

/* ------------------------------------------------------------------ */
/* engine: Secure Transport (the deprecated fallback)                  */
/* ------------------------------------------------------------------ */

static OSStatus st_read(SSLConnectionRef connection, void *data, size_t *dataLength) {
    conn *c = (conn *)connection;
    size_t want = *dataLength, got = 0;
    while (got < want) {
        ssize_t n = recv(c->fd, (char *)data + got, want - got, 0);
        if (n > 0) { got += (size_t)n; continue; }
        if (n == 0) { *dataLength = got; return errSSLClosedGraceful; }
        if (errno == EAGAIN || errno == EWOULDBLOCK) { *dataLength = got; return errSSLWouldBlock; }
        *dataLength = got; return errSSLInternal;
    }
    *dataLength = got;
    return noErr;
}

static OSStatus st_write(SSLConnectionRef connection, const void *data, size_t *dataLength) {
    conn *c = (conn *)connection;
    size_t want = *dataLength, put = 0;
    while (put < want) {
        ssize_t n = send(c->fd, (const char *)data + put, want - put, 0);
        if (n > 0) { put += (size_t)n; continue; }
        if (errno == EAGAIN || errno == EWOULDBLOCK) { *dataLength = put; return errSSLWouldBlock; }
        *dataLength = put; return errSSLInternal;
    }
    *dataLength = put;
    return noErr;
}

static int run_securetransport(conn *c, char *verdict, size_t vlen) {
    SSLContextRef ctx = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
    if (!ctx) { snprintf(verdict, vlen, "SSLCreateContext failed"); return 1; }

    SSLSetIOFuncs(ctx, st_read, st_write);
    SSLSetConnection(ctx, c);
    SSLSetPeerDomainName(ctx, c->o->host, strlen(c->o->host));
    SSLSetProtocolVersionMin(ctx, kTLSProtocol12);
    /* Hand trust to us rather than to Secure Transport's internal evaluation. */
    SSLSetSessionOption(ctx, kSSLSessionOptionBreakOnServerAuth, true);

    trust_result tr = {0};
    int trust_ran = 0, rc = 1;
    double hs_start = now_ms();

    for (;;) {
        OSStatus s = SSLHandshake(ctx);

        if (s == noErr) { rc = 0; break; }

        if (s == errSSLWouldBlock) {
            int r = wait_fd(c, POLLIN | POLLOUT);   /* our loop, our checkpoint */
            if (r == -2) { snprintf(verdict, vlen, "deadline exceeded"); break; }
            continue;
        }

        if (s == errSSLPeerAuthCompleted) {
            SecTrustRef trust = NULL;
            if (SSLCopyPeerTrust(ctx, &trust) == errSecSuccess && trust) {
                /* Re-evaluate through the same path the OpenSSL engine uses, so
                 * the two engines are compared on identical trust semantics. */
                CFIndex n = SecTrustGetCertificateCount(trust);
                const unsigned char *ders[16]; int lens[16], k = 0;
                CFArrayRef chain = SecTrustCopyCertificateChain(trust);
                for (CFIndex i = 0; i < n && k < 16 && chain; i++) {
                    SecCertificateRef sc = (SecCertificateRef)CFArrayGetValueAtIndex(chain, i);
                    CFDataRef d = SecCertificateCopyData(sc);
                    if (d) {
                        ders[k] = CFDataGetBytePtr(d);
                        lens[k] = (int)CFDataGetLength(d);
                        k++;
                        /* deliberately leaked for the lifetime of the call */
                    }
                }
                double a = now_ms();
                sectrust_evaluate(ders, lens, k, c->o->host, c->o, &tr);
                c->m->t_trust_ms = now_ms() - a;
                c->m->threads_after_trust = thread_count();
                trust_ran = 1;
                if (chain) CFRelease(chain);
                CFRelease(trust);
            }
            if (!tr.trusted) {
                snprintf(verdict, vlen, "TRUST REJECTED: %s", tr.detail);
                break;
            }
            continue;   /* trusted: resume handshake */
        }

        snprintf(verdict, vlen, "SSLHandshake failed: OSStatus %d", (int)s);
        break;
    }
    c->m->t_handshake_ms = now_ms() - hs_start;

    if (rc == 0) {
        SSLProtocol pv = kSSLProtocolUnknown;
        SSLGetNegotiatedProtocolVersion(ctx, &pv);
        const char *pname = pv == kTLSProtocol12 ? "TLSv1.2" :
                            pv == kTLSProtocol11 ? "TLSv1.1" :
                            pv == kTLSProtocol1  ? "TLSv1.0" : "other/unknown";
        SSLCipherSuite cs = 0;
        SSLGetNegotiatedCipher(ctx, &cs);
        snprintf(verdict, vlen, "OK %s / cipher 0x%04x / trust=%s",
                 pname, (unsigned)cs,
                 trust_ran ? (tr.trusted ? "SecTrust:yes" : "SecTrust:no") : "not-run");
    }

    SSLClose(ctx);
    CFRelease(ctx);
    return rc;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

static void usage(void) {
    fprintf(stderr,
        "usage: tls_spike --host H [--port P] [--engine openssl|st]\n"
        "                 [--anchor file.pem] [--anchor-only] [--revocation]\n"
        "                 [--tick-ms N] [--total-ms N] [--quiet]\n");
}

int main(int argc, char **argv) {
    opts o = { .port = "443", .engine = "openssl", .tick_ms = 100, .total_ms = 15000 };
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--host")   && i + 1 < argc) o.host = argv[++i];
        else if (!strcmp(argv[i], "--port")   && i + 1 < argc) o.port = argv[++i];
        else if (!strcmp(argv[i], "--engine") && i + 1 < argc) o.engine = argv[++i];
        else if (!strcmp(argv[i], "--anchor") && i + 1 < argc) o.anchor_pem = argv[++i];
        else if (!strcmp(argv[i], "--tick-ms")  && i + 1 < argc) o.tick_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--total-ms") && i + 1 < argc) o.total_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--anchor-only")) o.anchor_only = 1;
        else if (!strcmp(argv[i], "--revocation"))  o.revocation = 1;
        else if (!strcmp(argv[i], "--quiet")) o.quiet = 1;
        else { usage(); return 2; }
    }
    if (!o.host) { usage(); return 2; }

    metrics m = {0};
    m.threads_start = thread_count();

    conn c = { .fd = -1, .o = &o, .m = &m };
    double t0 = now_ms();
    c.deadline = t0 + o.total_ms;

    char verdict[1024] = "not run";
    int rc;

    double tc = now_ms();
    if (tcp_connect(&c, o.host, o.port) != 0) {
        snprintf(verdict, sizeof verdict, "TCP connect failed");
        rc = 1;
    } else {
        m.t_connect_ms = now_ms() - tc;
        if (!strcmp(o.engine, "st"))
            rc = run_securetransport(&c, verdict, sizeof verdict);
        else
            rc = run_openssl(&c, verdict, sizeof verdict);
    }

    m.t_total_ms = now_ms() - t0;
    m.threads_end = thread_count();
    if (c.fd >= 0) close(c.fd);

    printf("host=%-28s engine=%-8s rc=%d  %s\n", o.host, o.engine, rc, verdict);
    if (!o.quiet) {
        printf("    timing   connect=%.1fms handshake=%.1fms trust=%.1fms total=%.1fms\n",
               m.t_connect_ms, m.t_handshake_ms, m.t_trust_ms, m.t_total_ms);
        printf("    loop     checkpoints=%ld  longest_block=%ldus  (tick=%dms)\n",
               m.checkpoints, m.max_block_us, o.tick_ms);
        printf("    threads  start=%d after_trust=%d end=%d\n",
               m.threads_start, m.threads_after_trust, m.threads_end);
    }
    return rc;
}

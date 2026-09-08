/* zuhttp — macOS TLS: Secure Transport engine + SecTrust trust (§13.2, D-4).
 *
 * R-13 resolved (spike/macos-engine/FINDINGS.md): macOS offers no TLS 1.3 API
 * that can run over a socket the caller owns. Network.framework has TLS 1.3
 * but is created from an endpoint and needs a dispatch queue, so it breaks §9,
 * §13.1, and — decisively — §20.3 proxy CONNECT, which is TLS over a socket we
 * already established. Static OpenSSL has TLS 1.3 but bundles 4.64 MB of
 * cryptography, which is the thing §2 exists to avoid.
 *
 * So: Secure Transport, whose ceiling is TLS 1.2 (measured, F-10), driven over
 * the caller's zu_stream through SSLSetIOFuncs. Deprecated by Apple but fully
 * functional; if it is ever removed, D-4 must be reopened, and §62 tracks that.
 *
 * Trust is SecTrustEvaluateWithError against the system Keychain — NOT
 * deprecated, and the half of §13.1 that delivers enterprise roots, inspection
 * proxies and OS-managed certificate updates.
 */
#include "zu_tls.h"
#include "zu_alloc.h"
#include "zu_stream.h"
#include "zu_fork.h"
#include <string.h>
#include <stdio.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <Security/SecureTransport.h>

/* Secure Transport is deprecated by Apple and used deliberately (D-4, R-13).
 * Unsuppressed it produces ~44 deprecation warnings, and all three available
 * options cost something under `R CMD check --as-cran`:
 *
 *   no suppression                -> WARNING (install produces warnings)
 *   -Wno-* in PKG_CPPFLAGS        -> WARNING (non-portable flag)
 *   #pragma, scoped to this file  -> NOTE
 *
 * The pragma is chosen because a NOTE can be explained in a submission and a
 * WARNING cannot, and because CI runs with error_on = "warning". The scope is
 * this file only, so every other translation unit still reports everything.
 *
 * This does NOT make the deprecation less real: Appendix B R-15 tracks it, and
 * if these calls ever become hard errors, D-4 reopens.
 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

typedef struct {
    SSLContextRef ctx;
    zu_stream    *inner;        /* owned once the handshake succeeds */
    zu_deadline   deadline;     /* current, for the I/O callbacks */
    zu_error     *err;          /* current, for the I/O callbacks */
    zu_code       io_code;      /* our error, when a callback fails */
    int           io_failed;
    char          protocol[16];
    char          cipher[64];
    int           closed;
} st_impl;

/* --- I/O bridge ----------------------------------------------------------
 *
 * Secure Transport calls these; they read and write the caller's zu_stream,
 * which already enforces the deadline and runs the §25.1 interrupt tick. That
 * makes a blocking call here correct rather than a problem: the bounded wait
 * and the interrupt checkpoint both live one layer down. */

static OSStatus st_read(SSLConnectionRef c, void *data, size_t *len) {
    st_impl *t = (st_impl *)(void *)(uintptr_t)c;
    size_t want = *len, got = 0;
    *len = 0;
    while (got < want) {
        zu_ssize n = zu_stream_read(t->inner, (char *)data + got, want - got,
                                    t->deadline, t->err);
        if (n < 0) {
            t->io_failed = 1;
            t->io_code = t->err->code;
            *len = got;
            return errSSLClosedAbort;
        }
        if (n == 0) { *len = got; return errSSLClosedGraceful; }
        got += (size_t)n;
    }
    *len = got;
    return noErr;
}

static OSStatus st_write(SSLConnectionRef c, const void *data, size_t *len) {
    st_impl *t = (st_impl *)(void *)(uintptr_t)c;
    size_t want = *len;
    *len = 0;
    if (!zu_stream_write_all(t->inner, data, want, t->deadline, t->err)) {
        t->io_failed = 1;
        t->io_code = t->err->code;
        return errSSLClosedAbort;
    }
    *len = want;
    return noErr;
}

/* --- trust ---------------------------------------------------------------- */

static CFArrayRef anchors_from_pem_file(const char *path);

/* Evaluate `trust` under an SSL policy, optionally checking the hostname.
 * Returns 1 if trusted. `detail` receives the OS description. */
static int evaluate_under_policy(SecTrustRef trust, const char *hostname,
                                 int check_host, const zu_tls_config *cfg,
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
    /* §14.5 / S0 F-4: an SSL policy does NOT check revocation. It must be
     * added explicitly, and it is off by default (D-31) because it costs
     * 7-15x and makes a network call we can neither deadline nor cancel. */
    if (cfg->revocation) {
        SecPolicyRef rev = SecPolicyCreateRevocation(
            kSecRevocationUseAnyAvailableMethod | kSecRevocationRequirePositiveResponse);
        if (rev) { CFArrayAppendValue(policies, rev); CFRelease(rev); }
    }
    SecTrustSetPolicies(trust, policies);

    ok = SecTrustEvaluateWithError(trust, &err) ? 1 : 0;
    if (err) {
        CFStringRef d = CFErrorCopyDescription(err);
        if (os_code) *os_code = (long)CFErrorGetCode(err);
        if (d && detail) {
            CFStringGetCString(d, detail, (CFIndex)detail_len, kCFStringEncodingUTF8);
            CFRelease(d);
        }
        CFRelease(err);
    }
    CFRelease(policies);
    CFRelease(policy);
    if (h) CFRelease(h);
    return ok;
}

/* Distinguish "the chain is bad" from "the chain is fine but the name is
 * wrong" by evaluating twice rather than by matching on message text: if it
 * fails WITH the hostname policy and passes WITHOUT it, the name is the
 * problem. §34.1 gives these separate classes because the user actions
 * differ. */
static zu_code check_trust(SecTrustRef trust, const char *hostname,
                           const zu_tls_config *cfg, zu_error *err) {
    char detail[256];
    long os_code = 0;

    detail[0] = '\0';

    if (cfg->source == ZU_TRUST_FILE && cfg->ca_file) {
        CFArrayRef anchors = anchors_from_pem_file(cfg->ca_file);
        if (!anchors) {
            zu_error_set(err, ZU_ERR_TLS, ZU_PHASE_TLS,
                         "cannot read CA file '%s'", cfg->ca_file);
            return ZU_ERR_TLS;
        }
        SecTrustSetAnchorCertificates(trust, anchors);
        /* S0 F-6: true REPLACES the system store (ca_file), false ADDS to it
         * (ca_extra_file). D-12 keeps these separate so they cannot be
         * confused. */
        SecTrustSetAnchorCertificatesOnly(trust, true);
        CFRelease(anchors);
    } else if (cfg->ca_extra_file) {
        CFArrayRef anchors = anchors_from_pem_file(cfg->ca_extra_file);
        if (!anchors) {
            zu_error_set(err, ZU_ERR_TLS, ZU_PHASE_TLS,
                         "cannot read additional CA file '%s'", cfg->ca_extra_file);
            return ZU_ERR_TLS;
        }
        SecTrustSetAnchorCertificates(trust, anchors);
        SecTrustSetAnchorCertificatesOnly(trust, false);   /* additive */
        CFRelease(anchors);
    }

    if (!cfg->verify_peer) return ZU_OK;

    if (evaluate_under_policy(trust, hostname, cfg->verify_hostname, cfg,
                              detail, sizeof detail, &os_code))
        return ZU_OK;

    if (cfg->verify_hostname &&
        evaluate_under_policy(trust, NULL, 0, cfg, NULL, 0, NULL)) {
        zu_error_set(err, ZU_ERR_TLS_HOSTNAME, ZU_PHASE_TLS,
                     "certificate is valid but not for '%s': %s",
                     hostname ? hostname : "(unknown)", detail);
        zu_error_set_backend(err, "sectrust", (int)os_code);
        return ZU_ERR_TLS_HOSTNAME;
    }

    zu_error_set(err, ZU_ERR_TLS_CERT, ZU_PHASE_TLS,
                 "certificate verification failed for '%s': %s",
                 hostname ? hostname : "(unknown)", detail);
    zu_error_set_backend(err, "sectrust", (int)os_code);
    return ZU_ERR_TLS_CERT;
}

/* base64, for the PEM reader below. CoreFoundation exposes no public base64
 * API, and pulling in Foundation for NSData would make this file Objective-C. */
static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;                      /* whitespace, '=', or junk */
}

/* Decode `n` bytes of base64 into a fresh buffer; *out_len receives the size.
 * Whitespace is skipped, which is what makes it a PEM decoder. */
static unsigned char *b64_decode(const char *src, size_t n, size_t *out_len) {
    unsigned char *out = (unsigned char *)zu_alloc(n / 4 * 3 + 3);
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

/* Minimal PEM reader: a CA bundle, and nothing more. The OpenSSL backend uses
 * OpenSSL's own reader; this is the macOS equivalent. */
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
    text = (char *)zu_alloc((size_t)size + 1);
    if (!text) { fclose(f); return NULL; }
    if (fread(text, 1, (size_t)size, f) != (size_t)size) {
        zu_free(text); fclose(f); return NULL;
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
        zu_free(der);
        p = end + sizeof END - 1;
    }
    zu_free(text);
    if (CFArrayGetCount(out) == 0) { CFRelease(out); return NULL; }
    return out;
}

/* --- stream vtable -------------------------------------------------------- */

static zu_ssize st_stream_read(zu_stream *s, void *buf, size_t n,
                               zu_deadline d, zu_error *err) {
    st_impl *t = (st_impl *)s->impl;
    size_t got = 0;
    OSStatus os;

    t->deadline = d;
    t->err = err;
    t->io_failed = 0;

    os = SSLRead(t->ctx, buf, n, &got);
    if (os == noErr || (os == errSSLWouldBlock && got > 0)) return (zu_ssize)got;
    if (os == errSSLClosedGraceful || os == errSSLClosedNoNotify) return 0;
    if (t->io_failed) return -1;                 /* our error is already set */
    zu_error_set(err, ZU_ERR_TLS, ZU_PHASE_READ, "TLS read failed (OSStatus %d)", (int)os);
    zu_error_set_backend(err, "securetransport", (int)os);
    return -1;
}

static zu_ssize st_stream_write(zu_stream *s, const void *buf, size_t n,
                                zu_deadline d, zu_error *err) {
    st_impl *t = (st_impl *)s->impl;
    size_t put = 0;
    OSStatus os;

    t->deadline = d;
    t->err = err;
    t->io_failed = 0;

    os = SSLWrite(t->ctx, buf, n, &put);
    if (os == noErr) return (zu_ssize)put;
    if (t->io_failed) return -1;
    zu_error_set(err, ZU_ERR_TLS, ZU_PHASE_WRITE, "TLS write failed (OSStatus %d)", (int)os);
    zu_error_set_backend(err, "securetransport", (int)os);
    return -1;
}

static void st_stream_close(zu_stream *s) {
    st_impl *t = (st_impl *)s->impl;
    if (!t || t->closed) return;
    t->closed = 1;
    if (t->ctx) {
        zu_error scratch;
        zu_error_clear(&scratch);
        t->err = &scratch;
        t->deadline = zu_deadline_in(2000);   /* a close must not hang */
        SSLClose(t->ctx);
    }
    if (t->inner) zu_stream_close(t->inner);
}

static void st_stream_destroy(zu_stream *s) {
    st_impl *t;
    if (!s) return;
    t = (st_impl *)s->impl;
    if (t) {
        st_stream_close(s);
        if (t->ctx) CFRelease(t->ctx);
        if (t->inner) zu_stream_free(t->inner);
        zu_free(t);
    }
    zu_free(s);
}

/* §26.2: decrypted plaintext Secure Transport is already holding would not
 * show up on the socket, so check that before delegating. */
static int st_stream_readable(zu_stream *s, int timeout_ms) {
    st_impl *t;
    size_t pending = 0;
    if (!s || !s->impl) return -1;
    t = (st_impl *)s->impl;
    if (t->ctx && SSLGetBufferedReadSize(t->ctx, &pending) == noErr && pending > 0)
        return 1;
    return zu_stream_readable(t->inner, timeout_ms);
}

static const zu_stream_vtable k_st_vt = {
    "tls", st_stream_read, st_stream_write, st_stream_close,
    st_stream_destroy, st_stream_readable
};

/* --- connect -------------------------------------------------------------- */

int zu_tls_available(void) { return 1; }

const char *zu_tls_backend_name(void) { return "securetransport"; }

zu_code zu_tls_connect(zu_stream **out, zu_stream *inner, const char *hostname,
                       const zu_tls_config *cfg, zu_deadline deadline,
                       zu_error *err) {
    static zu_fork_guard g_trust_guard;
    static int g_armed = 0;
    st_impl *t = NULL;
    zu_stream *s = NULL;
    SecTrustRef trust = NULL;
    OSStatus os;
    zu_code rc;

    if (!out || !inner || !hostname || !cfg) return ZU_ERR_TLS;
    *out = NULL;

    /* §26.4 hazard 2 / D-32 / R-12. Security.framework opens an XPC connection
     * to trustd on first use, and that connection does not survive fork(): the
     * child SIGSEGVs rather than failing. Turning that into a named condition
     * is the entire mitigation — it does not make forked HTTPS work, it makes
     * the limitation diagnosable. Measured in S0 as finding F-5. */
    if (!g_armed) { zu_fork_guard_arm(&g_trust_guard); g_armed = 1; }
    else if (zu_fork_guard_tripped(&g_trust_guard)) {
        zu_error_set(err, ZU_ERR_FORK, ZU_PHASE_TLS, "%s", zu_fork_message());
        return ZU_ERR_FORK;
    }

    t = (st_impl *)zu_calloc(1, sizeof *t);
    s = (zu_stream *)zu_calloc(1, sizeof *s);
    if (!t || !s) { zu_free(t); zu_free(s); return ZU_ERR_NOMEM; }
    t->inner = inner;
    t->deadline = deadline;
    t->err = err;

    t->ctx = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
    if (!t->ctx) {
        zu_error_set(err, ZU_ERR_TLS, ZU_PHASE_TLS, "SSLCreateContext failed");
        goto fail_detach;
    }
    SSLSetIOFuncs(t->ctx, st_read, st_write);
    SSLSetConnection(t->ctx, (SSLConnectionRef)(uintptr_t)(void *)t);
    SSLSetPeerDomainName(t->ctx, hostname, strlen(hostname));   /* SNI */
    /* A caller asking for TLS 1.3 must be told no, not quietly given 1.2.
     * Silently weakening a security setting is worse than failing. */
    if (cfg->min_version >= 13) {
        zu_error_set(err, ZU_ERR_TLS, ZU_PHASE_TLS,
                     "min_version = TLS 1.3 cannot be satisfied on macOS: the "
                     "system TLS API tops out at 1.2 (see ?zuhttp_tls)");
        goto fail_detach;
    }
    SSLSetProtocolVersionMin(t->ctx, kTLSProtocol12);
    /* §14.1: trust is evaluated by US, not by Secure Transport, so the
     * handshake is broken at the server-auth step and resumed after
     * SecTrustEvaluateWithError. This is the §13.1 split in one call. */
    SSLSetSessionOption(t->ctx, kSSLSessionOptionBreakOnServerAuth, true);

    for (;;) {
        os = SSLHandshake(t->ctx);
        if (os == errSSLServerAuthCompleted) {
            os = SSLCopyPeerTrust(t->ctx, &trust);
            if (os != noErr || !trust) {
                zu_error_set(err, ZU_ERR_TLS, ZU_PHASE_TLS,
                             "cannot obtain the peer trust object (OSStatus %d)", (int)os);
                goto fail_detach;
            }
            rc = check_trust(trust, hostname, cfg, err);
            CFRelease(trust);
            trust = NULL;
            if (rc != ZU_OK) goto fail_rc;
            continue;                     /* resume the handshake */
        }
        if (os == noErr) break;
        if (t->io_failed) { rc = t->io_code; goto fail_rc; }
        zu_error_set(err, ZU_ERR_TLS_HANDSHAKE, ZU_PHASE_TLS,
                     "TLS handshake failed (OSStatus %d)", (int)os);
        zu_error_set_backend(err, "securetransport", (int)os);
        rc = ZU_ERR_TLS_HANDSHAKE;
        goto fail_rc;
    }

    /* §14.4 pinning needs the SubjectPublicKeyInfo hash, and Security.framework
     * exposes the key but not the SPKI wrapper, so computing it means parsing
     * the certificate DER by hand. Refusing is correct: a pin that silently
     * checks the wrong bytes is worse than no pin at all. */
    if (cfg->n_pins > 0) {
        zu_error_set(err, ZU_ERR_TLS_PIN, ZU_PHASE_TLS,
                     "public-key pinning is not implemented in the Secure Transport "
                     "backend; it is available on Linux (see ?zu_tls)");
        rc = ZU_ERR_TLS_PIN;
        goto fail_rc;
    }

    {
        SSLProtocol proto = kSSLProtocolUnknown;
        SSLCipherSuite cs = 0;
        SSLGetNegotiatedProtocolVersion(t->ctx, &proto);
        SSLGetNegotiatedCipher(t->ctx, &cs);
        snprintf(t->protocol, sizeof t->protocol, "%s",
                 proto == kTLSProtocol12 ? "TLSv1.2" :
                 proto == kTLSProtocol11 ? "TLSv1.1" :
                 proto == kTLSProtocol1  ? "TLSv1.0" : "unknown");
        snprintf(t->cipher, sizeof t->cipher, "0x%04x", (unsigned)cs);
    }

    s->vt = &k_st_vt;
    s->impl = t;
    *out = s;
    return ZU_OK;

fail_detach:
    rc = ZU_ERR_TLS;
fail_rc:
    /* §S7 contract: `inner` is NOT ours on failure — the caller still holds it
     * and will close it, so a handshake failure cannot double-free a socket. */
    if (trust) CFRelease(trust);
    if (t->ctx) CFRelease(t->ctx);
    t->inner = NULL;
    zu_free(t);
    zu_free(s);
    return rc;
}

void zu_tls_stream_free(zu_stream *s) { st_stream_destroy(s); }

int zu_tls_get_info(const zu_stream *s, zu_tls_info *out) {
    const st_impl *t;
    if (!s || !s->impl || !out) return 0;
    t = (const st_impl *)s->impl;
    memset(out, 0, sizeof *out);
    snprintf(out->protocol, sizeof out->protocol, "%s", t->protocol);
    snprintf(out->cipher, sizeof out->cipher, "%s", t->cipher);
    snprintf(out->trust_backend, sizeof out->trust_backend, "sectrust");
    return 1;
}

#pragma clang diagnostic pop

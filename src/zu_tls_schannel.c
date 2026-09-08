/* zuhttp — Windows TLS: Schannel engine + Windows certificate store (§13.4, D-5).
 *
 * D-5 is not a preference, it is a requirement, and the §63.2 slice measured
 * why: linking OpenSSL on Windows builds and links cleanly under Rtools and
 * then cannot verify a single certificate, because OpenSSL looks for a CA
 * bundle at a compiled-in path that does not exist and never consults the
 * Windows certificate store. There are no trust anchors at all. The
 * alternatives are shipping a certificate bundle, which §2 rejects outright,
 * or reading the Windows store by hand and feeding it to OpenSSL — which is
 * most of this file with none of its benefits.
 *
 * SCOPE: TLS 1.2, via SCHANNEL_CRED. S1 confirmed every symbol on that path is
 * present and links under Rtools' mingw-w64 (FINDINGS F-9). TLS 1.3 needs
 * SCH_CREDENTIALS, which those headers do NOT declare (F-8, risk R-3), so it
 * is deliberately a separate step: declaring a structure whose layout we
 * cannot verify and handing it to AcquireCredentialsHandle is a memory-safety
 * bug, not a compile error.
 *
 * Trust is verified by US (SCH_CRED_MANUAL_CRED_VALIDATION +
 * ISC_REQ_MANUAL_CRED_VALIDATION) rather than by Schannel, which is the §13.1
 * engine/trust split and is what lets §34.1 tell a bad chain from a bad name.
 */
#define SECURITY_WIN32

#include "zu_tls.h"
#include "zu_alloc.h"
#include "zu_buffer.h"
#include "zu_stream.h"

#include <windows.h>
#include <wincrypt.h>
#include <schannel.h>
#include <sspi.h>

#include <string.h>
#include <stdio.h>

/* Declared in wininet.h, which mingw-w64's wincrypt/schannel headers do not
 * pull in — and including wininet.h here would drag in a large unrelated
 * surface for one flag.
 *
 * Note the contrast with R-3: declaring a SCALAR CONSTANT locally is safe,
 * because a wrong value means a wrong flag and nothing more. Declaring a
 * STRUCT locally (SCH_CREDENTIALS, for TLS 1.3) is not, because a wrong
 * layout handed to AcquireCredentialsHandle corrupts memory. That difference
 * is why one is a footnote and the other is a tracked risk. */
#ifndef SECURITY_FLAG_IGNORE_CERT_CN_INVALID
#  define SECURITY_FLAG_IGNORE_CERT_CN_INVALID 0x00001000
#endif

#define ZU_SCH_MAX_TOKEN   (32 * 1024)
#define ZU_SCH_READ_CHUNK  16384

typedef struct {
    CredHandle  cred;
    CtxtHandle  ctx;
    int         have_cred;
    int         have_ctx;
    zu_stream  *inner;             /* owned once the handshake succeeds */
    SecPkgContext_StreamSizes sizes;
    zu_buffer   enc;               /* ciphertext read but not yet decrypted */
    zu_buffer   dec;               /* plaintext decrypted but not yet returned */
    char        protocol[16];
    char        cipher[64];
    int         closed;
} sch_impl;

/* --- diagnostics ---------------------------------------------------------- */

static void sspi_message(SECURITY_STATUS ss, char *out, size_t cap) {
    DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                             NULL, (DWORD)ss, 0, out, (DWORD)cap, NULL);
    if (n == 0) { snprintf(out, cap, "SSPI status 0x%08lx", (unsigned long)ss); return; }
    /* FormatMessage leaves a trailing CRLF that reads badly inside a sentence. */
    while (n > 0 && (out[n - 1] == '\r' || out[n - 1] == '\n' || out[n - 1] == ' '))
        out[--n] = '\0';
}

/* --- trust (§13.1: ours, not Schannel's) ---------------------------------- */

static zu_code verify_peer(sch_impl *t, const char *hostname,
                           const zu_tls_config *cfg, zu_error *err) {
    PCCERT_CONTEXT leaf = NULL;
    PCCERT_CHAIN_CONTEXT chain = NULL;
    CERT_CHAIN_PARA chain_para;
    CERT_CHAIN_POLICY_PARA policy_para;
    CERT_CHAIN_POLICY_STATUS policy_status;
    SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl_para;
    LPWSTR whost = NULL;
    SECURITY_STATUS ss;
    zu_code rc = ZU_OK;
    int wlen;
    char detail[256];

    ss = QueryContextAttributes(&t->ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &leaf);
    if (ss != SEC_E_OK || !leaf) {
        sspi_message(ss, detail, sizeof detail);
        zu_error_set(err, ZU_ERR_TLS, ZU_PHASE_TLS,
                     "the peer sent no certificate: %s", detail);
        return ZU_ERR_TLS;
    }

    if (!cfg->verify_peer) { CertFreeCertificateContext(leaf); return ZU_OK; }

    memset(&chain_para, 0, sizeof chain_para);
    chain_para.cbSize = sizeof chain_para;
    chain_para.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
    chain_para.RequestedUsage.Usage.cUsageIdentifier = 0;
    chain_para.RequestedUsage.Usage.rgpszUsageIdentifier = NULL;

    /* §14.5 / D-31: revocation is OFF by default. Windows would otherwise make
     * a network call we can neither deadline nor cancel. */
    if (!CertGetCertificateChain(NULL, leaf, NULL, leaf->hCertStore, &chain_para,
                                 cfg->revocation ? CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT : 0,
                                 NULL, &chain)) {
        zu_error_set(err, ZU_ERR_TLS_CERT, ZU_PHASE_TLS,
                     "cannot build a certificate chain (0x%08lx)",
                     (unsigned long)GetLastError());
        CertFreeCertificateContext(leaf);
        return ZU_ERR_TLS_CERT;
    }

    /* The hostname must reach CertVerifyCertificateChainPolicy as UTF-16. */
    if (cfg->verify_hostname && hostname) {
        wlen = MultiByteToWideChar(CP_UTF8, 0, hostname, -1, NULL, 0);
        if (wlen > 0) {
            whost = (LPWSTR)zu_alloc((size_t)wlen * sizeof(WCHAR));
            if (whost) MultiByteToWideChar(CP_UTF8, 0, hostname, -1, whost, wlen);
        }
    }

    memset(&ssl_para, 0, sizeof ssl_para);
    ssl_para.cbSize = sizeof ssl_para;
    ssl_para.dwAuthType = AUTHTYPE_SERVER;
    ssl_para.pwszServerName = whost;
    if (!cfg->verify_hostname)
        ssl_para.fdwChecks = SECURITY_FLAG_IGNORE_CERT_CN_INVALID;

    memset(&policy_para, 0, sizeof policy_para);
    policy_para.cbSize = sizeof policy_para;
    policy_para.pvExtraPolicyPara = &ssl_para;

    memset(&policy_status, 0, sizeof policy_status);
    policy_status.cbSize = sizeof policy_status;

    if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain,
                                          &policy_para, &policy_status)) {
        zu_error_set(err, ZU_ERR_TLS_CERT, ZU_PHASE_TLS,
                     "certificate policy check failed (0x%08lx)",
                     (unsigned long)GetLastError());
        rc = ZU_ERR_TLS_CERT;
    } else if (policy_status.dwError != 0) {
        sspi_message((SECURITY_STATUS)policy_status.dwError, detail, sizeof detail);
        /* Windows reports a precise reason, so unlike macOS this needs no
         * second evaluation to separate a bad name from a bad chain (§34.1). */
        if (policy_status.dwError == (DWORD)CERT_E_CN_NO_MATCH) {
            zu_error_set(err, ZU_ERR_TLS_HOSTNAME, ZU_PHASE_TLS,
                         "certificate is valid but not for '%s': %s",
                         hostname ? hostname : "(unknown)", detail);
            rc = ZU_ERR_TLS_HOSTNAME;
        } else {
            zu_error_set(err, ZU_ERR_TLS_CERT, ZU_PHASE_TLS,
                         "certificate verification failed for '%s': %s",
                         hostname ? hostname : "(unknown)", detail);
            rc = ZU_ERR_TLS_CERT;
        }
        zu_error_set_backend(err, "schannel", (int)policy_status.dwError);
    }

    zu_free(whost);
    CertFreeCertificateChain(chain);
    CertFreeCertificateContext(leaf);
    return rc;
}

/* --- handshake ------------------------------------------------------------ */

/* Keep the trailing `extra` bytes of t->enc and drop everything before them.
 *
 * SECBUFFER_EXTRA reports a COUNT, and the bytes it refers to are the tail of
 * the buffer we handed in. Computing the source as (len - extra) without
 * checking that extra <= len underflows size_t into a huge offset and reads
 * wild memory — which is a segfault, not a wrong answer. */
static void keep_trailing(sch_impl *t, size_t extra) {
    if (extra == 0 || extra > t->enc.len) { zu_buf_reset(&t->enc); return; }
    memmove(t->enc.data, t->enc.data + (t->enc.len - extra), extra);
    t->enc.len = extra;
}

static zu_code do_handshake(sch_impl *t, const char *hostname,
                            zu_deadline d, zu_error *err) {
    SecBuffer  outb[1], inb[2];
    SecBufferDesc outd, ind;
    DWORD req = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT
              | ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR
              | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM
              /* §13.1: WE evaluate trust, not Schannel. */
              | ISC_REQ_MANUAL_CRED_VALIDATION;
    DWORD attrs = 0;
    SECURITY_STATUS ss;
    char detail[256];
    int first = 1;
    int used_input;      /* was `inb` populated on THIS iteration? */

    for (;;) {
        used_input = 0;
        outb[0].pvBuffer = NULL;
        outb[0].BufferType = SECBUFFER_TOKEN;
        outb[0].cbBuffer = 0;
        outd.ulVersion = SECBUFFER_VERSION;
        outd.cBuffers = 1;
        outd.pBuffers = outb;

        if (first) {
            ss = InitializeSecurityContextA(&t->cred, NULL, (SEC_CHAR *)hostname,
                                            req, 0, 0, NULL, 0,
                                            &t->ctx, &outd, &attrs, NULL);
            first = 0;
            /* Claim the handle only if Schannel actually produced one. On a
             * hard failure it may not have, and DeleteSecurityContext on an
             * unset handle in the cleanup path is its own crash. */
            if (ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED) t->have_ctx = 1;
            /* `inb` is deliberately NOT touched on this path, which is why the
             * SECBUFFER_EXTRA checks below key off used_input rather than
             * !first. Keying off `first` read uninitialised stack memory on
             * exactly this iteration — undefined behaviour that would usually
             * appear to work, because the garbage rarely equals
             * SECBUFFER_EXTRA. Found by review; a test would not have. */
        } else {
            inb[0].pvBuffer   = t->enc.data;
            inb[0].cbBuffer   = (unsigned long)t->enc.len;
            inb[0].BufferType = SECBUFFER_TOKEN;
            inb[1].pvBuffer   = NULL;
            inb[1].cbBuffer   = 0;
            inb[1].BufferType = SECBUFFER_EMPTY;
            ind.ulVersion = SECBUFFER_VERSION;
            ind.cBuffers  = 2;
            ind.pBuffers  = inb;

            used_input = 1;
            ss = InitializeSecurityContextA(&t->cred, &t->ctx, (SEC_CHAR *)hostname,
                                            req, 0, 0, &ind, 0,
                                            NULL, &outd, &attrs, NULL);
        }

        /* Anything Schannel produced goes to the peer, even on failure paths:
         * a TLS alert is how the server learns why we hung up. */
        if (outb[0].cbBuffer > 0 && outb[0].pvBuffer) {
            int ok = zu_stream_write_all(t->inner, outb[0].pvBuffer,
                                         outb[0].cbBuffer, d, err);
            FreeContextBuffer(outb[0].pvBuffer);
            if (!ok) return err->code ? err->code : ZU_ERR_IO;
        }

        if (ss == SEC_E_OK) {
            /* Keep whatever arrived past the end of the handshake. */
            if (used_input && inb[1].BufferType == SECBUFFER_EXTRA)
                keep_trailing(t, inb[1].cbBuffer);
            else
                zu_buf_reset(&t->enc);
            return ZU_OK;
        }

        if (ss == SEC_I_CONTINUE_NEEDED || ss == SEC_E_INCOMPLETE_MESSAGE) {
            char chunk[ZU_SCH_READ_CHUNK];
            zu_ssize n;

            if (ss == SEC_I_CONTINUE_NEEDED) {
                if (used_input && inb[1].BufferType == SECBUFFER_EXTRA)
                    keep_trailing(t, inb[1].cbBuffer);
                else
                    zu_buf_reset(&t->enc);
            }
            n = zu_stream_read(t->inner, chunk, sizeof chunk, d, err);
            if (n < 0) return err->code ? err->code : ZU_ERR_IO;
            if (n == 0) {
                zu_error_set(err, ZU_ERR_TLS_HANDSHAKE, ZU_PHASE_TLS,
                             "peer closed during the TLS handshake");
                return ZU_ERR_TLS_HANDSHAKE;
            }
            if (!zu_buf_append(&t->enc, chunk, (size_t)n)) return ZU_ERR_NOMEM;
            continue;
        }

        sspi_message(ss, detail, sizeof detail);
        zu_error_set(err, ZU_ERR_TLS_HANDSHAKE, ZU_PHASE_TLS,
                     "TLS handshake failed: %s", detail);
        zu_error_set_backend(err, "schannel", (int)ss);
        return ZU_ERR_TLS_HANDSHAKE;
    }
}

/* --- record layer --------------------------------------------------------- */

/* Decrypt whatever complete records are sitting in t->enc, appending plaintext
 * to t->dec. Returns ZU_ERR_WOULDBLOCK when more ciphertext is needed. */
static zu_code decrypt_available(sch_impl *t, zu_error *err) {
    for (;;) {
        SecBuffer b[4];
        SecBufferDesc d;
        SECURITY_STATUS ss;
        size_t extra_len = 0;
        int i;

        if (t->enc.len == 0) return ZU_ERR_WOULDBLOCK;

        b[0].pvBuffer   = t->enc.data;
        b[0].cbBuffer   = (unsigned long)t->enc.len;
        b[0].BufferType = SECBUFFER_DATA;
        for (i = 1; i < 4; i++) {
            b[i].pvBuffer = NULL; b[i].cbBuffer = 0; b[i].BufferType = SECBUFFER_EMPTY;
        }
        d.ulVersion = SECBUFFER_VERSION;
        d.cBuffers  = 4;
        d.pBuffers  = b;

        ss = DecryptMessage(&t->ctx, &d, 0, NULL);

        if (ss == SEC_E_INCOMPLETE_MESSAGE) return ZU_ERR_WOULDBLOCK;

        if (ss == SEC_I_CONTEXT_EXPIRED) {   /* the peer sent close_notify */
            zu_buf_reset(&t->enc);
            return ZU_ERR_CLOSED;
        }
        if (ss != SEC_E_OK) {
            char detail[256];
            sspi_message(ss, detail, sizeof detail);
            zu_error_set(err, ZU_ERR_TLS, ZU_PHASE_READ, "TLS decrypt failed: %s", detail);
            zu_error_set_backend(err, "schannel", (int)ss);
            return ZU_ERR_TLS;
        }

        for (i = 0; i < 4; i++) {
            if (b[i].BufferType == SECBUFFER_DATA && b[i].cbBuffer > 0) {
                if (!zu_buf_append(&t->dec, b[i].pvBuffer, b[i].cbBuffer))
                    return ZU_ERR_NOMEM;
            } else if (b[i].BufferType == SECBUFFER_EXTRA && b[i].cbBuffer > 0) {
                extra_len = b[i].cbBuffer;
            }
        }

        /* SECBUFFER_EXTRA points INTO t->enc, so the leftover is moved to the
         * front rather than copied out; anything else aliases freed storage. */
        if (extra_len > 0 && extra_len <= t->enc.len) {
            keep_trailing(t, extra_len);
            continue;                       /* another whole record may follow */
        }
        zu_buf_reset(&t->enc);
        return ZU_OK;
    }
}

static zu_ssize sch_read(zu_stream *s, void *buf, size_t n, zu_deadline d, zu_error *err) {
    sch_impl *t = (sch_impl *)s->impl;

    for (;;) {
        if (t->dec.len > 0) {
            size_t take = t->dec.len < n ? t->dec.len : n;
            memcpy(buf, t->dec.data, take);
            zu_buf_consume(&t->dec, take);
            return (zu_ssize)take;
        }
        {
            zu_code rc = decrypt_available(t, err);
            if (rc == ZU_OK) continue;
            if (rc == ZU_ERR_CLOSED) return 0;
            if (rc != ZU_ERR_WOULDBLOCK) return -1;
        }
        {
            char chunk[ZU_SCH_READ_CHUNK];
            zu_ssize got = zu_stream_read(t->inner, chunk, sizeof chunk, d, err);
            if (got < 0) return -1;
            if (got == 0) return 0;         /* connection-close framing (§18.1) */
            if (!zu_buf_append(&t->enc, chunk, (size_t)got)) {
                zu_error_set(err, ZU_ERR_NOMEM, ZU_PHASE_READ, "out of memory");
                return -1;
            }
        }
    }
}

static zu_ssize sch_write(zu_stream *s, const void *buf, size_t n,
                          zu_deadline d, zu_error *err) {
    sch_impl *t = (sch_impl *)s->impl;
    const unsigned char *p = (const unsigned char *)buf;
    size_t sent = 0;

    while (sent < n) {
        size_t take = n - sent;
        SecBuffer b[4];
        SecBufferDesc desc;
        SECURITY_STATUS ss;
        unsigned char *rec;
        size_t reclen;

        if (take > t->sizes.cbMaximumMessage) take = t->sizes.cbMaximumMessage;

        reclen = (size_t)t->sizes.cbHeader + take + (size_t)t->sizes.cbTrailer;
        rec = (unsigned char *)zu_alloc(reclen);
        if (!rec) { zu_error_set(err, ZU_ERR_NOMEM, ZU_PHASE_WRITE, "out of memory"); return -1; }
        memcpy(rec + t->sizes.cbHeader, p + sent, take);

        b[0].pvBuffer = rec;                            b[0].cbBuffer = t->sizes.cbHeader;  b[0].BufferType = SECBUFFER_STREAM_HEADER;
        b[1].pvBuffer = rec + t->sizes.cbHeader;        b[1].cbBuffer = (unsigned long)take; b[1].BufferType = SECBUFFER_DATA;
        b[2].pvBuffer = rec + t->sizes.cbHeader + take; b[2].cbBuffer = t->sizes.cbTrailer;  b[2].BufferType = SECBUFFER_STREAM_TRAILER;
        b[3].pvBuffer = NULL;                           b[3].cbBuffer = 0;                   b[3].BufferType = SECBUFFER_EMPTY;
        desc.ulVersion = SECBUFFER_VERSION;
        desc.cBuffers  = 4;
        desc.pBuffers  = b;

        ss = EncryptMessage(&t->ctx, 0, &desc, 0);
        if (ss != SEC_E_OK) {
            char detail[256];
            sspi_message(ss, detail, sizeof detail);
            zu_error_set(err, ZU_ERR_TLS, ZU_PHASE_WRITE, "TLS encrypt failed: %s", detail);
            zu_error_set_backend(err, "schannel", (int)ss);
            zu_free(rec);
            return -1;
        }
        /* EncryptMessage may shorten the trailer, so the wire length is the
         * sum of what it reports, not the buffer we allocated. */
        reclen = (size_t)b[0].cbBuffer + (size_t)b[1].cbBuffer + (size_t)b[2].cbBuffer;
        if (!zu_stream_write_all(t->inner, rec, reclen, d, err)) {
            zu_free(rec);
            return -1;
        }
        zu_free(rec);
        sent += take;
    }
    return (zu_ssize)sent;
}

static void sch_close(zu_stream *s) {
    sch_impl *t = (sch_impl *)s->impl;
    if (!t || t->closed) return;
    t->closed = 1;
    if (t->inner) zu_stream_close(t->inner);
}

static void sch_destroy(zu_stream *s) {
    sch_impl *t;
    if (!s) return;
    t = (sch_impl *)s->impl;
    if (t) {
        sch_close(s);
        if (t->have_ctx)  DeleteSecurityContext(&t->ctx);
        if (t->have_cred) FreeCredentialsHandle(&t->cred);
        zu_buf_free(&t->enc);
        zu_buf_free(&t->dec);
        if (t->inner) zu_stream_free(t->inner);
        zu_free(t);
    }
    zu_free(s);
}

/* §26.2: plaintext we have already decrypted is invisible to the socket. */
static int sch_readable(zu_stream *s, int timeout_ms) {
    sch_impl *t;
    if (!s || !s->impl) return -1;
    t = (sch_impl *)s->impl;
    if (t->dec.len > 0 || t->enc.len > 0) return 1;
    return zu_stream_readable(t->inner, timeout_ms);
}

static const zu_stream_vtable k_sch_vt = {
    "tls", sch_read, sch_write, sch_close, sch_destroy, sch_readable
};

/* --- connect -------------------------------------------------------------- */

int zu_tls_available(void) { return 1; }
const char *zu_tls_backend_name(void) { return "schannel"; }

zu_code zu_tls_connect(zu_stream **out, zu_stream *inner, const char *hostname,
                       const zu_tls_config *cfg, zu_deadline deadline,
                       zu_error *err) {
    sch_impl *t = NULL;
    zu_stream *s = NULL;
    SCHANNEL_CRED sc;
    SECURITY_STATUS ss;
    TimeStamp expiry;
    zu_code rc;
    char detail[256];

    if (!out || !inner || !hostname || !cfg) return ZU_ERR_TLS;
    *out = NULL;

    /* §14.4 pinning would need the leaf SubjectPublicKeyInfo; CryptoAPI can
     * supply it, but it is not implemented yet and a pin that checks the wrong
     * bytes is worse than no pin. Refuse rather than pretend. */
    if (cfg->n_pins > 0) {
        zu_error_set(err, ZU_ERR_TLS_PIN, ZU_PHASE_TLS,
                     "public-key pinning is not implemented in the Schannel "
                     "backend; it is available on Linux (see ?zu_tls)");
        return ZU_ERR_TLS_PIN;
    }
    if (cfg->source == ZU_TRUST_FILE || cfg->source == ZU_TRUST_DATA ||
        cfg->ca_extra_file) {
        /* §14.3 additive/replacement trust needs a CERT_STORE_PROV_MEMORY
         * store wired into CertGetCertificateChain. S1 confirmed the API is
         * available; the wiring is not written yet. */
        zu_error_set(err, ZU_ERR_TLS, ZU_PHASE_TLS,
                     "custom CA sources are not implemented in the Schannel "
                     "backend yet; the Windows certificate store is used");
        return ZU_ERR_TLS;
    }

    t = (sch_impl *)zu_calloc(1, sizeof *t);
    s = (zu_stream *)zu_calloc(1, sizeof *s);
    if (!t || !s) { zu_free(t); zu_free(s); return ZU_ERR_NOMEM; }
    t->inner = inner;
    if (!zu_buf_init(&t->enc, ZU_SCH_MAX_TOKEN, 4u * 1024u * 1024u) ||
        !zu_buf_init(&t->dec, ZU_SCH_READ_CHUNK, 4u * 1024u * 1024u)) {
        rc = ZU_ERR_NOMEM;
        goto fail;
    }

    memset(&sc, 0, sizeof sc);
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    /* TLS 1.2 only. See the file header: TLS 1.3 needs SCH_CREDENTIALS, which
     * Rtools' headers do not declare (R-3). */
    sc.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
    sc.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION   /* §13.1: we verify */
               | SCH_CRED_NO_DEFAULT_CREDS
               | SCH_USE_STRONG_CRYPTO;

    ss = AcquireCredentialsHandleA(NULL, (SEC_CHAR *)UNISP_NAME_A,
                                   SECPKG_CRED_OUTBOUND, NULL, &sc,
                                   NULL, NULL, &t->cred, &expiry);
    if (ss != SEC_E_OK) {
        sspi_message(ss, detail, sizeof detail);
        zu_error_set(err, ZU_ERR_TLS, ZU_PHASE_TLS,
                     "cannot acquire Schannel credentials: %s", detail);
        zu_error_set_backend(err, "schannel", (int)ss);
        rc = ZU_ERR_TLS;
        goto fail;
    }
    t->have_cred = 1;

    rc = do_handshake(t, hostname, deadline, err);
    if (rc != ZU_OK) goto fail;

    rc = verify_peer(t, hostname, cfg, err);
    if (rc != ZU_OK) goto fail;

    ss = QueryContextAttributes(&t->ctx, SECPKG_ATTR_STREAM_SIZES, &t->sizes);
    if (ss != SEC_E_OK) {
        sspi_message(ss, detail, sizeof detail);
        zu_error_set(err, ZU_ERR_TLS, ZU_PHASE_TLS, "cannot query stream sizes: %s", detail);
        rc = ZU_ERR_TLS;
        goto fail;
    }

    {
        SecPkgContext_ConnectionInfo info;
        memset(&info, 0, sizeof info);
        if (QueryContextAttributes(&t->ctx, SECPKG_ATTR_CONNECTION_INFO, &info) == SEC_E_OK) {
            snprintf(t->protocol, sizeof t->protocol, "%s",
                     (info.dwProtocol & SP_PROT_TLS1_2_CLIENT) ? "TLSv1.2" :
                     (info.dwProtocol & SP_PROT_TLS1_1_CLIENT) ? "TLSv1.1" : "unknown");
            snprintf(t->cipher, sizeof t->cipher, "alg 0x%08lx/%lu bit",
                     (unsigned long)info.aiCipher, (unsigned long)info.dwCipherStrength);
        } else {
            snprintf(t->protocol, sizeof t->protocol, "TLSv1.2");
            snprintf(t->cipher, sizeof t->cipher, "unknown");
        }
    }

    s->vt = &k_sch_vt;
    s->impl = t;
    *out = s;
    return ZU_OK;

fail:
    /* S7 contract: `inner` is NOT ours on failure; the caller still holds it
     * and will close it, so a handshake failure cannot double-free a socket. */
    if (t) {
        if (t->have_ctx)  DeleteSecurityContext(&t->ctx);
        if (t->have_cred) FreeCredentialsHandle(&t->cred);
        zu_buf_free(&t->enc);
        zu_buf_free(&t->dec);
        t->inner = NULL;
        zu_free(t);
    }
    zu_free(s);
    return rc;
}

void zu_tls_stream_free(zu_stream *s) { sch_destroy(s); }

int zu_tls_get_info(const zu_stream *s, zu_tls_info *out) {
    const sch_impl *t;
    if (!s || !s->impl || !out) return 0;
    t = (const sch_impl *)s->impl;
    memset(out, 0, sizeof *out);
    snprintf(out->protocol, sizeof out->protocol, "%s", t->protocol);
    snprintf(out->cipher, sizeof out->cipher, "%s", t->cipher);
    snprintf(out->trust_backend, sizeof out->trust_backend, "wincertstore");
    return 1;
}

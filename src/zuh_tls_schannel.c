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

#include "zuh_tls.h"
#include "zuh_alloc.h"
#include "zuh_buffer.h"
#include "zuh_stream.h"

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

#define ZUH_SCH_MAX_TOKEN   (32 * 1024)
#define ZUH_SCH_READ_CHUNK  16384

typedef struct {
    CredHandle  cred;
    CtxtHandle  ctx;
    int         have_cred;
    int         have_ctx;
    zuh_stream  *inner;             /* owned once the handshake succeeds */
    SecPkgContext_StreamSizes sizes;
    zuh_buffer   enc;               /* ciphertext read but not yet decrypted */
    zuh_buffer   dec;               /* plaintext decrypted but not yet returned */
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

static zuh_code verify_peer(sch_impl *t, const char *hostname,
                           const zuh_tls_config *cfg, zuh_error *err) {
    PCCERT_CONTEXT leaf = NULL;
    PCCERT_CHAIN_CONTEXT chain = NULL;
    CERT_CHAIN_PARA chain_para;
    CERT_CHAIN_POLICY_PARA policy_para;
    CERT_CHAIN_POLICY_STATUS policy_status;
    SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl_para;
    LPWSTR whost = NULL;
    SECURITY_STATUS ss;
    zuh_code rc = ZUH_OK;
    int wlen;
    char detail[256];

    ss = QueryContextAttributes(&t->ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &leaf);
    if (ss != SEC_E_OK || !leaf) {
        sspi_message(ss, detail, sizeof detail);
        zuh_error_set(err, ZUH_ERR_TLS, ZUH_PHASE_TLS,
                     "the peer sent no certificate: %s", detail);
        return ZUH_ERR_TLS;
    }

    if (!cfg->verify_peer) { CertFreeCertificateContext(leaf); return ZUH_OK; }

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
        zuh_error_set(err, ZUH_ERR_TLS_CERT, ZUH_PHASE_TLS,
                     "cannot build a certificate chain (0x%08lx)",
                     (unsigned long)GetLastError());
        CertFreeCertificateContext(leaf);
        return ZUH_ERR_TLS_CERT;
    }

    /* The hostname must reach CertVerifyCertificateChainPolicy as UTF-16. */
    if (cfg->verify_hostname && hostname) {
        wlen = MultiByteToWideChar(CP_UTF8, 0, hostname, -1, NULL, 0);
        if (wlen > 0) {
            whost = (LPWSTR)zuh_alloc((size_t)wlen * sizeof(WCHAR));
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
        zuh_error_set(err, ZUH_ERR_TLS_CERT, ZUH_PHASE_TLS,
                     "certificate policy check failed (0x%08lx)",
                     (unsigned long)GetLastError());
        rc = ZUH_ERR_TLS_CERT;
    } else if (policy_status.dwError != 0) {
        sspi_message((SECURITY_STATUS)policy_status.dwError, detail, sizeof detail);
        /* Windows reports a precise reason, so unlike macOS this needs no
         * second evaluation to separate a bad name from a bad chain (§34.1). */
        if (policy_status.dwError == (DWORD)CERT_E_CN_NO_MATCH) {
            zuh_error_set(err, ZUH_ERR_TLS_HOSTNAME, ZUH_PHASE_TLS,
                         "certificate is valid but not for '%s': %s",
                         hostname ? hostname : "(unknown)", detail);
            rc = ZUH_ERR_TLS_HOSTNAME;
        } else {
            zuh_error_set(err, ZUH_ERR_TLS_CERT, ZUH_PHASE_TLS,
                         "certificate verification failed for '%s': %s",
                         hostname ? hostname : "(unknown)", detail);
            rc = ZUH_ERR_TLS_CERT;
        }
        zuh_error_set_backend(err, "schannel", (int)policy_status.dwError);
    }

    zuh_free(whost);
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
    if (extra == 0 || extra > t->enc.len) { zuh_buf_reset(&t->enc); return; }
    memmove(t->enc.data, t->enc.data + (t->enc.len - extra), extra);
    t->enc.len = extra;
}

static zuh_code do_handshake(sch_impl *t, const char *hostname,
                            zuh_deadline d, zuh_error *err) {
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
            int ok = zuh_stream_write_all(t->inner, outb[0].pvBuffer,
                                         outb[0].cbBuffer, d, err);
            FreeContextBuffer(outb[0].pvBuffer);
            if (!ok) return err->code ? err->code : ZUH_ERR_IO;
        }

        if (ss == SEC_E_OK) {
            /* Keep whatever arrived past the end of the handshake. */
            if (used_input && inb[1].BufferType == SECBUFFER_EXTRA)
                keep_trailing(t, inb[1].cbBuffer);
            else
                zuh_buf_reset(&t->enc);
            return ZUH_OK;
        }

        if (ss == SEC_I_CONTINUE_NEEDED || ss == SEC_E_INCOMPLETE_MESSAGE) {
            char chunk[ZUH_SCH_READ_CHUNK];
            zuh_ssize n;

            if (ss == SEC_I_CONTINUE_NEEDED) {
                if (used_input && inb[1].BufferType == SECBUFFER_EXTRA)
                    keep_trailing(t, inb[1].cbBuffer);
                else
                    zuh_buf_reset(&t->enc);
            }
            n = zuh_stream_read(t->inner, chunk, sizeof chunk, d, err);
            if (n < 0) return err->code ? err->code : ZUH_ERR_IO;
            if (n == 0) {
                zuh_error_set(err, ZUH_ERR_TLS_HANDSHAKE, ZUH_PHASE_TLS,
                             "peer closed during the TLS handshake");
                return ZUH_ERR_TLS_HANDSHAKE;
            }
            if (!zuh_buf_append(&t->enc, chunk, (size_t)n)) return ZUH_ERR_NOMEM;
            continue;
        }

        sspi_message(ss, detail, sizeof detail);
        zuh_error_set(err, ZUH_ERR_TLS_HANDSHAKE, ZUH_PHASE_TLS,
                     "TLS handshake failed: %s", detail);
        zuh_error_set_backend(err, "schannel", (int)ss);
        return ZUH_ERR_TLS_HANDSHAKE;
    }
}

/* --- record layer --------------------------------------------------------- */

/* Decrypt whatever complete records are sitting in t->enc, appending plaintext
 * to t->dec. Returns ZUH_ERR_WOULDBLOCK when more ciphertext is needed. */
static zuh_code decrypt_available(sch_impl *t, zuh_error *err) {
    for (;;) {
        SecBuffer b[4];
        SecBufferDesc d;
        SECURITY_STATUS ss;
        size_t extra_len = 0;
        int i;

        if (t->enc.len == 0) return ZUH_ERR_WOULDBLOCK;

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

        if (ss == SEC_E_INCOMPLETE_MESSAGE) return ZUH_ERR_WOULDBLOCK;

        if (ss == SEC_I_CONTEXT_EXPIRED) {   /* the peer sent close_notify */
            zuh_buf_reset(&t->enc);
            return ZUH_ERR_CLOSED;
        }
        if (ss != SEC_E_OK) {
            char detail[256];
            sspi_message(ss, detail, sizeof detail);
            zuh_error_set(err, ZUH_ERR_TLS, ZUH_PHASE_READ, "TLS decrypt failed: %s", detail);
            zuh_error_set_backend(err, "schannel", (int)ss);
            return ZUH_ERR_TLS;
        }

        for (i = 0; i < 4; i++) {
            if (b[i].BufferType == SECBUFFER_DATA && b[i].cbBuffer > 0) {
                if (!zuh_buf_append(&t->dec, b[i].pvBuffer, b[i].cbBuffer))
                    return ZUH_ERR_NOMEM;
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
        zuh_buf_reset(&t->enc);
        return ZUH_OK;
    }
}

static zuh_ssize sch_read(zuh_stream *s, void *buf, size_t n, zuh_deadline d, zuh_error *err) {
    sch_impl *t = (sch_impl *)s->impl;

    for (;;) {
        if (t->dec.len > 0) {
            size_t take = t->dec.len < n ? t->dec.len : n;
            memcpy(buf, t->dec.data, take);
            zuh_buf_consume(&t->dec, take);
            return (zuh_ssize)take;
        }
        {
            zuh_code rc = decrypt_available(t, err);
            if (rc == ZUH_OK) continue;
            if (rc == ZUH_ERR_CLOSED) return 0;
            if (rc != ZUH_ERR_WOULDBLOCK) return -1;
        }
        {
            char chunk[ZUH_SCH_READ_CHUNK];
            zuh_ssize got = zuh_stream_read(t->inner, chunk, sizeof chunk, d, err);
            if (got < 0) return -1;
            if (got == 0) return 0;         /* connection-close framing (§18.1) */
            if (!zuh_buf_append(&t->enc, chunk, (size_t)got)) {
                zuh_error_set(err, ZUH_ERR_NOMEM, ZUH_PHASE_READ, "out of memory");
                return -1;
            }
        }
    }
}

static zuh_ssize sch_write(zuh_stream *s, const void *buf, size_t n,
                          zuh_deadline d, zuh_error *err) {
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
        rec = (unsigned char *)zuh_alloc(reclen);
        if (!rec) { zuh_error_set(err, ZUH_ERR_NOMEM, ZUH_PHASE_WRITE, "out of memory"); return -1; }
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
            zuh_error_set(err, ZUH_ERR_TLS, ZUH_PHASE_WRITE, "TLS encrypt failed: %s", detail);
            zuh_error_set_backend(err, "schannel", (int)ss);
            zuh_free(rec);
            return -1;
        }
        /* EncryptMessage may shorten the trailer, so the wire length is the
         * sum of what it reports, not the buffer we allocated. */
        reclen = (size_t)b[0].cbBuffer + (size_t)b[1].cbBuffer + (size_t)b[2].cbBuffer;
        if (!zuh_stream_write_all(t->inner, rec, reclen, d, err)) {
            zuh_free(rec);
            return -1;
        }
        zuh_free(rec);
        sent += take;
    }
    return (zuh_ssize)sent;
}

static void sch_close(zuh_stream *s) {
    sch_impl *t = (sch_impl *)s->impl;
    if (!t || t->closed) return;
    t->closed = 1;
    if (t->inner) zuh_stream_close(t->inner);
}

static void sch_destroy(zuh_stream *s) {
    sch_impl *t;
    if (!s) return;
    t = (sch_impl *)s->impl;
    if (t) {
        sch_close(s);
        if (t->have_ctx)  DeleteSecurityContext(&t->ctx);
        if (t->have_cred) FreeCredentialsHandle(&t->cred);
        zuh_buf_free(&t->enc);
        zuh_buf_free(&t->dec);
        if (t->inner) zuh_stream_free(t->inner);
        zuh_free(t);
    }
    zuh_free(s);
}

/* §26.2: plaintext we have already decrypted is invisible to the socket. */
static int sch_readable(zuh_stream *s, int timeout_ms) {
    sch_impl *t;
    if (!s || !s->impl) return -1;
    t = (sch_impl *)s->impl;
    if (t->dec.len > 0 || t->enc.len > 0) return 1;
    return zuh_stream_readable(t->inner, timeout_ms);
}

static const zuh_stream_vtable k_sch_vt = {
    "tls", sch_read, sch_write, sch_close, sch_destroy, sch_readable
};

/* --- connect -------------------------------------------------------------- */

int zuh_tls_available(void) { return 1; }
const char *zuh_tls_backend_name(void) { return "schannel"; }

/* Revocation only. Pins need the leaf SubjectPublicKeyInfo, which CryptoAPI
 * can supply but which is not wired yet (#12). ca_file and ca_extra need a
 * CERT_STORE_PROV_MEMORY store passed to CertGetCertificateChain (§14.3,
 * #5). TLS 1.3 needs SCH_CREDENTIALS (R-3, #17). All four are refused by
 * zuh_tls_config_check() before the handshake (D-56). */
unsigned zuh_tls_backend_caps(void) {
    return ZUH_TLS_CAP_REVOCATION;
}

zuh_code zuh_tls_connect(zuh_stream **out, zuh_stream *inner, const char *hostname,
                       const zuh_tls_config *cfg, zuh_deadline deadline,
                       zuh_error *err) {
    sch_impl *t = NULL;
    zuh_stream *s = NULL;
    SCHANNEL_CRED sc;
    SECURITY_STATUS ss;
    TimeStamp expiry;
    zuh_code rc;
    char detail[256];

    if (!out || !inner || !hostname || !cfg) return ZUH_ERR_TLS;
    *out = NULL;

    rc = zuh_tls_config_check(cfg, zuh_tls_backend_caps(), zuh_tls_backend_name(), err);
    if (rc != ZUH_OK) return rc;

    t = (sch_impl *)zuh_calloc(1, sizeof *t);
    s = (zuh_stream *)zuh_calloc(1, sizeof *s);
    if (!t || !s) { zuh_free(t); zuh_free(s); return ZUH_ERR_NOMEM; }
    t->inner = inner;
    if (!zuh_buf_init(&t->enc, ZUH_SCH_MAX_TOKEN, 4u * 1024u * 1024u) ||
        !zuh_buf_init(&t->dec, ZUH_SCH_READ_CHUNK, 4u * 1024u * 1024u)) {
        rc = ZUH_ERR_NOMEM;
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
        zuh_error_set(err, ZUH_ERR_TLS, ZUH_PHASE_TLS,
                     "cannot acquire Schannel credentials: %s", detail);
        zuh_error_set_backend(err, "schannel", (int)ss);
        rc = ZUH_ERR_TLS;
        goto fail;
    }
    t->have_cred = 1;

    rc = do_handshake(t, hostname, deadline, err);
    if (rc != ZUH_OK) goto fail;

    rc = verify_peer(t, hostname, cfg, err);
    if (rc != ZUH_OK) goto fail;

    ss = QueryContextAttributes(&t->ctx, SECPKG_ATTR_STREAM_SIZES, &t->sizes);
    if (ss != SEC_E_OK) {
        sspi_message(ss, detail, sizeof detail);
        zuh_error_set(err, ZUH_ERR_TLS, ZUH_PHASE_TLS, "cannot query stream sizes: %s", detail);
        rc = ZUH_ERR_TLS;
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
    return ZUH_OK;

fail:
    /* S7 contract: `inner` is NOT ours on failure; the caller still holds it
     * and will close it, so a handshake failure cannot double-free a socket. */
    if (t) {
        if (t->have_ctx)  DeleteSecurityContext(&t->ctx);
        if (t->have_cred) FreeCredentialsHandle(&t->cred);
        zuh_buf_free(&t->enc);
        zuh_buf_free(&t->dec);
        t->inner = NULL;
        zuh_free(t);
    }
    zuh_free(s);
    return rc;
}

void zuh_tls_stream_free(zuh_stream *s) { sch_destroy(s); }

int zuh_tls_get_info(const zuh_stream *s, zuh_tls_info *out) {
    const sch_impl *t;
    if (!s || !s->impl || !out) return 0;
    t = (const sch_impl *)s->impl;
    memset(out, 0, sizeof *out);
    snprintf(out->protocol, sizeof out->protocol, "%s", t->protocol);
    snprintf(out->cipher, sizeof out->cipher, "%s", t->cipher);
    snprintf(out->trust_backend, sizeof out->trust_backend, "wincertstore");
    return 1;
}

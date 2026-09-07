/* zuhttp — OpenSSL TLS engine (design §13.5, roadmap S7).
 *
 * Reference implementation of the §13.1 engine/trust split. The engine drives
 * OpenSSL through MEMORY BIOs rather than handing it a socket, so every byte
 * still moves through the caller's zu_stream and therefore through the
 * caller's poll loop, deadlines and interrupt checkpoints (§24, §25). Giving
 * OpenSSL the file descriptor would put the blocking back inside the library
 * and break both.
 *
 * S0 finding F-3 is the single most important line in this file — see
 * SSL_CTX_set_verify below.
 */
#include "zu_tls.h"
#include "zu_alloc.h"
#include "zu_buffer.h"
#include <string.h>
#include <stdio.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

void zu_tls_config_init(zu_tls_config *c) {
    memset(c, 0, sizeof *c);
    c->source = ZU_TRUST_SYSTEM;
    c->verify_peer = 1;       /* §14.1: never default to off */
    c->verify_hostname = 1;
    c->revocation = 0;        /* §14.5 / S0 F-4 */
    c->min_version = 12;      /* TLS 1.2 */
    c->alpn = "http/1.1";
}

const char *zu_tls_backend_name(void) { return "openssl"; }
int         zu_tls_available(void)    { return 1; }

typedef struct {
    SSL_CTX   *ctx;
    SSL       *ssl;
    BIO       *rbio;          /* network -> SSL */
    BIO       *wbio;          /* SSL -> network */
    zu_stream *inner;         /* owned once the handshake succeeds */
    zu_tls_info info;
    const zu_tls_config *cfg;
    char       hostname[256];
    int        pin_ok;
} tls_impl;

static void ssl_err_string(char *out, size_t cap) {
    unsigned long e = ERR_peek_last_error();
    if (e == 0) { snprintf(out, cap, "no OpenSSL error recorded"); return; }
    ERR_error_string_n(e, out, cap);
}

/* Move whatever SSL produced out to the network. */
static zu_code flush_out(tls_impl *t, zu_deadline d, zu_error *err) {
    char buf[16384];
    int n;
    while ((n = BIO_read(t->wbio, buf, (int)sizeof buf)) > 0) {
        if (!zu_stream_write_all(t->inner, buf, (size_t)n, d, err))
            return err && err->code ? err->code : ZU_ERR_IO;
    }
    return ZU_OK;
}

/* Pull from the network into SSL. */
static zu_code fill_in(tls_impl *t, zu_deadline d, zu_error *err) {
    char buf[16384];
    zu_ssize n = zu_stream_read(t->inner, buf, sizeof buf, d, err);
    if (n > 0) {
        BIO_write(t->rbio, buf, (int)n);
        return ZU_OK;
    }
    if (n == 0) {
        zu_error_set(err, ZU_ERR_CLOSED, ZU_PHASE_TLS, "peer closed during TLS");
        return ZU_ERR_CLOSED;
    }
    if (err && err->code == ZU_ERR_WOULDBLOCK) { zu_error_clear(err); return ZU_OK; }
    return err && err->code ? err->code : ZU_ERR_IO;
}

/* §14.4 pinning: SHA-256 over the leaf SubjectPublicKeyInfo, base64, compared
 * against "sha256//..." entries. Additive to chain and hostname checks. */
static int pin_matches(X509 *leaf, const char *const *pins, size_t n_pins) {
    unsigned char *spki = NULL;
    int spki_len;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    char b64[128];
    size_t i;
    int ok = 0;

    spki_len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(leaf), &spki);
    if (spki_len <= 0 || !spki) return 0;

    if (EVP_Digest(spki, (size_t)spki_len, digest, &dlen, EVP_sha256(), NULL) == 1) {
        int b64len = EVP_EncodeBlock((unsigned char *)b64, digest, (int)dlen);
        if (b64len > 0) {
            b64[b64len] = '\0';
            for (i = 0; i < n_pins; i++) {
                const char *p = pins[i];
                if (!p) continue;
                if (strncmp(p, "sha256//", 8) == 0) p += 8;
                if (strcmp(p, b64) == 0) { ok = 1; break; }
            }
        }
    }
    OPENSSL_free(spki);
    return ok;
}

static int verify_cb(X509_STORE_CTX *sctx, void *arg) {
    tls_impl *t = (tls_impl *)arg;
    int ok;

    /* Chain + hostname, using OpenSSL's own verification. Hostname matching is
     * configured through X509_VERIFY_PARAM below and is never hand-rolled. */
    ok = X509_verify_cert(sctx);
    if (ok != 1) return 0;

    if (t->cfg && t->cfg->n_pins > 0) {
        X509 *leaf = X509_STORE_CTX_get0_cert(sctx);
        if (!leaf || !pin_matches(leaf, t->cfg->pins, t->cfg->n_pins)) {
            t->pin_ok = 0;
            return 0;                 /* §14.4: in addition to, not instead of */
        }
        t->pin_ok = 1;
    }
    return 1;
}

static zu_code configure_trust(tls_impl *t, const zu_tls_config *cfg, zu_error *err) {
    switch (cfg->source) {
        case ZU_TRUST_SYSTEM:
            if (SSL_CTX_set_default_verify_paths(t->ctx) != 1) {
                zu_error_set(err, ZU_ERR_TLS, ZU_PHASE_TLS,
                             "cannot load the system trust store");
                return ZU_ERR_TLS;
            }
            break;
        case ZU_TRUST_FILE:
            /* §14.2: REPLACES system trust. Deliberately not combined with
             * set_default_verify_paths. */
            if (!cfg->ca_file ||
                SSL_CTX_load_verify_locations(t->ctx, cfg->ca_file, NULL) != 1) {
                zu_error_set(err, ZU_ERR_TLS, ZU_PHASE_TLS,
                             "cannot load CA file '%s'",
                             cfg->ca_file ? cfg->ca_file : "(null)");
                return ZU_ERR_TLS;
            }
            break;
        case ZU_TRUST_DATA: {
            BIO *b;
            X509_STORE *store;
            X509 *x;
            int added = 0;
            if (!cfg->ca_data || cfg->ca_data_len == 0) {
                zu_error_set(err, ZU_ERR_TLS, ZU_PHASE_TLS, "ca_data is empty");
                return ZU_ERR_TLS;
            }
            b = BIO_new_mem_buf(cfg->ca_data, (int)cfg->ca_data_len);
            if (!b) return ZU_ERR_NOMEM;
            store = SSL_CTX_get_cert_store(t->ctx);
            while ((x = PEM_read_bio_X509(b, NULL, NULL, NULL)) != NULL) {
                X509_STORE_add_cert(store, x);
                X509_free(x);
                added++;
            }
            BIO_free(b);
            if (!added) {
                zu_error_set(err, ZU_ERR_TLS, ZU_PHASE_TLS,
                             "ca_data contained no PEM certificates");
                return ZU_ERR_TLS;
            }
            break;
        }
    }

    /* §14.2 ca_extra ADDS to whatever was selected above. */
    if (cfg->ca_extra_file) {
        if (SSL_CTX_load_verify_locations(t->ctx, cfg->ca_extra_file, NULL) != 1) {
            zu_error_set(err, ZU_ERR_TLS, ZU_PHASE_TLS,
                         "cannot load ca_extra file '%s'", cfg->ca_extra_file);
            return ZU_ERR_TLS;
        }
    }

    if (cfg->revocation) {
        /* §14.5: opt-in only. OpenSSL checks nothing by default. */
        X509_VERIFY_PARAM *p = SSL_CTX_get0_param(t->ctx);
        X509_VERIFY_PARAM_set_flags(p, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
    }
    return ZU_OK;
}

static zu_ssize tls_read(zu_stream *s, void *buf, size_t n, zu_deadline d, zu_error *err) {
    tls_impl *t = (tls_impl *)s->impl;
    for (;;) {
        int r = SSL_read(t->ssl, buf, (int)(n > INT_MAX ? INT_MAX : n));
        int e;
        if (r > 0) return (zu_ssize)r;
        e = SSL_get_error(t->ssl, r);
        if (e == SSL_ERROR_ZERO_RETURN) return 0;          /* clean close_notify */
        if (e == SSL_ERROR_WANT_READ) {
            if (flush_out(t, d, err) != ZU_OK) return -1;
            if (fill_in(t, d, err) != ZU_OK) return -1;
            continue;
        }
        if (e == SSL_ERROR_WANT_WRITE) {
            if (flush_out(t, d, err) != ZU_OK) return -1;
            continue;
        }
        if (e == SSL_ERROR_SYSCALL && r == 0) return 0;    /* truncated, treat as EOF */
        {
            char eb[192];
            ssl_err_string(eb, sizeof eb);
            zu_error_set(err, ZU_ERR_TLS, ZU_PHASE_READ, "TLS read failed: %s", eb);
            zu_error_set_backend(err, "openssl", (int)ERR_peek_last_error());
        }
        return -1;
    }
}

static zu_ssize tls_write(zu_stream *s, const void *buf, size_t n, zu_deadline d, zu_error *err) {
    tls_impl *t = (tls_impl *)s->impl;
    for (;;) {
        int w = SSL_write(t->ssl, buf, (int)(n > INT_MAX ? INT_MAX : n));
        int e;
        if (w > 0) {
            if (flush_out(t, d, err) != ZU_OK) return -1;
            return (zu_ssize)w;
        }
        e = SSL_get_error(t->ssl, w);
        if (e == SSL_ERROR_WANT_READ) {
            if (flush_out(t, d, err) != ZU_OK) return -1;
            if (fill_in(t, d, err) != ZU_OK) return -1;
            continue;
        }
        if (e == SSL_ERROR_WANT_WRITE) {
            if (flush_out(t, d, err) != ZU_OK) return -1;
            continue;
        }
        {
            char eb[192];
            ssl_err_string(eb, sizeof eb);
            zu_error_set(err, ZU_ERR_TLS, ZU_PHASE_WRITE, "TLS write failed: %s", eb);
        }
        return -1;
    }
}

static void tls_close(zu_stream *s) {
    tls_impl *t = (tls_impl *)s->impl;
    if (!t) return;
    if (t->ssl) {
        SSL_shutdown(t->ssl);          /* best effort; peer may already be gone */
        SSL_free(t->ssl);              /* frees rbio/wbio too */
        t->ssl = NULL; t->rbio = t->wbio = NULL;
    }
    if (t->ctx) { SSL_CTX_free(t->ctx); t->ctx = NULL; }
    if (t->inner) zu_stream_close(t->inner);
}

static void tls_destroy(zu_stream *s);

/* §26.2 through a TLS wrapper. Buffered plaintext that OpenSSL has already
 * decrypted would not show up on the socket, so check that first; otherwise
 * delegate to the transport underneath. */
static int tls_readable(zu_stream *s, int timeout_ms) {
    tls_impl *t;
    if (!s || !s->impl) return -1;
    t = (tls_impl *)s->impl;
    if (t->ssl && SSL_pending(t->ssl) > 0) return 1;
    return zu_stream_readable(t->inner, timeout_ms);
}

static const zu_stream_vtable k_tls_vt = {
    "tls", tls_read, tls_write, tls_close, tls_destroy, tls_readable
};

static void tls_destroy(zu_stream *s) {
    tls_impl *t;
    if (!s) return;
    t = (tls_impl *)s->impl;
    tls_close(s);
    /* The TLS stream owns the inner stream once the handshake succeeded, and
     * cannot know its concrete type — hence the generic hook (§9). */
    if (t && t->inner) zu_stream_free(t->inner);
    zu_free(t);
    zu_free(s);
}

zu_code zu_tls_connect(zu_stream **out, zu_stream *inner, const char *hostname,
                       const zu_tls_config *cfg, zu_deadline deadline,
                       zu_error *err) {
    zu_tls_config def;
    zu_stream *s = NULL;
    tls_impl *t = NULL;
    zu_code rc = ZU_ERR_TLS;

    if (!out || !inner || !hostname) return ZU_ERR_PARSE;
    *out = NULL;
    if (!cfg) { zu_tls_config_init(&def); cfg = &def; }

    s = (zu_stream *)zu_calloc(1, sizeof *s);
    t = (tls_impl *)zu_calloc(1, sizeof *t);
    if (!s || !t) { zu_free(s); zu_free(t); return ZU_ERR_NOMEM; }
    t->cfg = cfg;
    strncpy(t->hostname, hostname, sizeof t->hostname - 1);

    t->ctx = SSL_CTX_new(TLS_client_method());
    if (!t->ctx) {
        zu_error_set(err, ZU_ERR_TLS, ZU_PHASE_TLS, "cannot create an SSL context");
        goto fail;
    }

    SSL_CTX_set_min_proto_version(t->ctx,
        cfg->min_version >= 13 ? TLS1_3_VERSION : TLS1_2_VERSION);

    if (cfg->verify_peer) {
        rc = configure_trust(t, cfg, err);
        if (rc != ZU_OK) goto fail;

        /* ---------------------------------------------------------------
         * S0 FINDING F-3. Without SSL_VERIFY_PEER the client default is
         * SSL_VERIFY_NONE, under which a cert_verify_callback returning 0
         * RECORDS the failure but does NOT abort the handshake. The result is
         * a working connection to an untrusted peer — a silent verification
         * bypass that every happy-path test passes.
         * --------------------------------------------------------------- */
        SSL_CTX_set_verify(t->ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_cert_verify_callback(t->ctx, verify_cb, t);
    } else {
        SSL_CTX_set_verify(t->ctx, SSL_VERIFY_NONE, NULL);
    }

    t->ssl = SSL_new(t->ctx);
    if (!t->ssl) { zu_error_set(err, ZU_ERR_TLS, ZU_PHASE_TLS, "SSL_new failed"); goto fail; }

    t->rbio = BIO_new(BIO_s_mem());
    t->wbio = BIO_new(BIO_s_mem());
    if (!t->rbio || !t->wbio) { rc = ZU_ERR_NOMEM; goto fail; }
    BIO_set_mem_eof_return(t->rbio, -1);
    BIO_set_mem_eof_return(t->wbio, -1);
    SSL_set_bio(t->ssl, t->rbio, t->wbio);   /* SSL owns them from here */
    SSL_set_connect_state(t->ssl);

    /* SNI, and hostname verification driven by the name WE asked for — never
     * a name taken from the certificate. */
    SSL_set_tlsext_host_name(t->ssl, t->hostname);
    if (cfg->verify_peer && cfg->verify_hostname) {
        X509_VERIFY_PARAM *p = SSL_get0_param(t->ssl);
        X509_VERIFY_PARAM_set_hostflags(p, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        if (X509_VERIFY_PARAM_set1_host(p, t->hostname, 0) != 1) {
            zu_error_set(err, ZU_ERR_TLS, ZU_PHASE_TLS, "cannot set the verification host");
            goto fail;
        }
    }

    if (cfg->alpn && *cfg->alpn) {
        unsigned char proto[64];
        size_t len = strlen(cfg->alpn);
        if (len < sizeof proto - 1) {
            proto[0] = (unsigned char)len;
            memcpy(proto + 1, cfg->alpn, len);
            SSL_set_alpn_protos(t->ssl, proto, (unsigned)(len + 1));
        }
    }

    t->inner = inner;

    for (;;) {
        int r, e;
        if (zu_deadline_expired(deadline)) {
            zu_error_set(err, ZU_ERR_TIMEOUT, ZU_PHASE_TLS, "TLS handshake deadline exceeded");
            rc = ZU_ERR_TIMEOUT; goto fail_detach;
        }
        ERR_clear_error();
        r = SSL_do_handshake(t->ssl);
        if (r == 1) break;
        e = SSL_get_error(t->ssl, r);
        if (e == SSL_ERROR_WANT_READ) {
            if (flush_out(t, deadline, err) != ZU_OK) { rc = err->code; goto fail_detach; }
            if (fill_in(t, deadline, err) != ZU_OK)   { rc = err->code; goto fail_detach; }
            continue;
        }
        if (e == SSL_ERROR_WANT_WRITE) {
            if (flush_out(t, deadline, err) != ZU_OK) { rc = err->code; goto fail_detach; }
            continue;
        }
        {
            /* Translate to the §34.1 class the user actually needs. */
            long v = SSL_get_verify_result(t->ssl);
            char eb[192];
            ssl_err_string(eb, sizeof eb);
            if (cfg->n_pins > 0 && !t->pin_ok) {
                zu_error_set(err, ZU_ERR_TLS_PIN, ZU_PHASE_TLS,
                             "certificate public key does not match any configured pin");
                rc = ZU_ERR_TLS_PIN;
            } else if (v == X509_V_ERR_HOSTNAME_MISMATCH) {
                zu_error_set(err, ZU_ERR_TLS_HOSTNAME, ZU_PHASE_TLS,
                             "certificate is not valid for '%s'", t->hostname);
                rc = ZU_ERR_TLS_HOSTNAME;
            } else if (v == X509_V_ERR_CERT_HAS_EXPIRED ||
                       v == X509_V_ERR_CERT_NOT_YET_VALID ||
                       v == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
                       v == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN ||
                       v == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ||
                       v == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE) {
                zu_error_set(err, ZU_ERR_TLS_CERT, ZU_PHASE_TLS,
                             "certificate verification failed for '%s': %s",
                             t->hostname, X509_verify_cert_error_string(v));
                rc = ZU_ERR_TLS_CERT;
            } else {
                zu_error_set(err, ZU_ERR_TLS_HANDSHAKE, ZU_PHASE_TLS,
                             "TLS handshake failed: %s", eb);
                rc = ZU_ERR_TLS_HANDSHAKE;
            }
            zu_error_set_backend(err, "openssl", (int)v);
            goto fail_detach;
        }
    }

    if (flush_out(t, deadline, err) != ZU_OK) { rc = err->code; goto fail_detach; }

    snprintf(t->info.protocol, sizeof t->info.protocol, "%s", SSL_get_version(t->ssl));
    snprintf(t->info.cipher, sizeof t->info.cipher, "%s", SSL_get_cipher(t->ssl));
    snprintf(t->info.trust_backend, sizeof t->info.trust_backend, "openssl");
    t->info.reused_session = SSL_session_reused(t->ssl);

    s->vt = &k_tls_vt;
    s->impl = t;
    *out = s;
    return ZU_OK;

fail_detach:
    /* The caller still owns `inner` on failure and will close it; do not close
     * it here or it would be closed twice. */
    t->inner = NULL;
fail:
    if (t->ssl) SSL_free(t->ssl);              /* frees the BIOs */
    else { if (t->rbio) BIO_free(t->rbio); if (t->wbio) BIO_free(t->wbio); }
    if (t->ctx) SSL_CTX_free(t->ctx);
    zu_free(t);
    zu_free(s);
    return rc;
}

void zu_tls_stream_free(zu_stream *s) { tls_destroy(s); }

int zu_tls_get_info(const zu_stream *s, zu_tls_info *out) {
    const tls_impl *t;
    if (!s || !s->impl || !out) return 0;
    t = (const tls_impl *)s->impl;
    *out = t->info;
    return 1;
}

/* zuhttp — TLS backend interface (design §13, §15, §38).
 *
 * §13.1 splits two questions that have different answers per platform:
 *
 *   1. who speaks the protocol?   -> the ENGINE
 *   2. who decides the chain is trusted?  -> the TRUST EVALUATOR
 *
 * Only (2) must be native for zuhttp to deliver on "system trust". Keeping
 * them separate is what makes macOS tractable: S0 proved an OpenSSL engine can
 * hand its chain to SecTrustEvaluateWithError and get Keychain trust while the
 * caller keeps its own poll loop.
 *
 *   Windows  Schannel        + Windows cert store
 *   macOS    portable engine + Keychain via SecTrust      (S0: validated)
 *   Unix     OpenSSL         + OpenSSL default verify paths
 *
 * A TLS stream WRAPS a zu_stream rather than owning a socket, so the same
 * engine serves a direct connection and a CONNECT tunnel (§20.3) unchanged.
 */
#ifndef ZUHTTP_TLS_H
#define ZUHTTP_TLS_H

#include "zu_platform.h"
#include "zu_stream.h"
#include "zu_error.h"
#include "zu_time.h"

/* --- trust configuration (§14) --- */

typedef enum {
    ZU_TRUST_SYSTEM = 0,  /* platform store: the default, never bundled CAs */
    ZU_TRUST_FILE,        /* ca_file REPLACES system trust (§14.2)          */
    ZU_TRUST_DATA         /* ca_data REPLACES system trust                  */
} zu_trust_source;

typedef struct {
    zu_trust_source source;
    const char     *ca_file;      /* ZU_TRUST_FILE */
    const void     *ca_data;      /* ZU_TRUST_DATA */
    size_t          ca_data_len;

    /* ADDS to system trust rather than replacing it. The distinction is
     * security-relevant and surprises people, so the two are separate fields
     * and never one overloaded argument (§14.2). */
    const char     *ca_extra_file;

    int             verify_peer;      /* default 1; never 0 by default */
    int             verify_hostname;  /* default 1 */

    /* §14.4 public-key pinning: "sha256//<base64>" entries. Checked IN
     * ADDITION to chain and hostname verification, never instead of. */
    const char *const *pins;
    size_t             n_pins;

    /* §14.5 revocation is OFF by default. S0 finding F-4 measured the cost at
     * 7-15x, and it makes an uninterruptible network call inside the platform
     * trust evaluator that zuhttp can neither deadline nor cancel. */
    int             revocation;

    int             min_version;      /* 12 => TLS 1.2, 13 => TLS 1.3 */
    const char     *alpn;             /* e.g. "http/1.1"; NULL to omit */
} zu_tls_config;

void zu_tls_config_init(zu_tls_config *c);

/* --- connection --- */

typedef struct {
    char protocol[16];   /* "TLSv1.3" */
    char cipher[64];
    char trust_backend[24];  /* "openssl", "sectrust", "schannel" (§35.2) */
    int  reused_session;
} zu_tls_info;

/* Wrap `inner` in TLS. On success the returned stream owns `inner` and closing
 * it closes both. On failure `inner` is left untouched for the caller to close,
 * so a handshake failure never double-frees a socket the caller still holds.
 *
 * `hostname` is used for SNI AND for verification; it is never taken from the
 * certificate. */
zu_code zu_tls_connect(zu_stream **out, zu_stream *inner, const char *hostname,
                       const zu_tls_config *cfg, zu_deadline deadline,
                       zu_error *err);

void zu_tls_stream_free(zu_stream *s);
int  zu_tls_get_info(const zu_stream *s, zu_tls_info *out);

/* Which engine was compiled in, for zu_info() (§39). */
const char *zu_tls_backend_name(void);
int         zu_tls_available(void);

#endif /* ZUHTTP_TLS_H */

/* zuhttp — the backend-neutral part of the TLS interface (§14.1).
 *
 * The defaults belong here rather than in a backend, because they are policy,
 * not implementation: every backend must start from verify-on, revocation-off
 * and TLS 1.2 minimum, and duplicating that per backend is how one of them
 * eventually drifts to a weaker default.
 */
#include "zu_tls.h"
#include <string.h>

void zu_tls_config_init(zu_tls_config *c) {
    if (!c) return;
    memset(c, 0, sizeof *c);
    c->source          = ZU_TRUST_SYSTEM;
    c->verify_peer     = 1;    /* §14.1: never default to off */
    c->verify_hostname = 1;
    c->revocation      = 0;    /* §14.5, S0 finding F-4 */
    c->min_version     = 12;   /* TLS 1.2 */
    c->alpn            = "http/1.1";
}

/* --- D-56: refuse, never downgrade -----------------------------------------
 *
 * Every setting below is a security request. A backend that cannot honour one
 * must say so rather than connect without it: min_version = 13 answered with
 * 1.2, a pin nobody checks, or a CA file quietly replaced by the system store
 * are each a weaker connection than the caller asked for, and the caller would
 * never find out. The refusal used to be written out per backend, with
 * different codes (a pin refusal was ZU_ERR_TLS_PIN, the same code as a pin
 * MISMATCH, which let a test pass on a backend that never pinned — #12) and at
 * different points (Secure Transport refused a pin only after the handshake).
 * One function, one code, before the handshake. */
zu_code zu_tls_config_check(const zu_tls_config *cfg, unsigned caps,
                            const char *backend, zu_error *err) {
    const char *what = NULL, *why = "";
    if (!cfg) return ZU_OK;
    if (!backend) backend = "this";

    if (cfg->n_pins > 0 && !(caps & ZU_TLS_CAP_PINS)) {
        what = "public-key pinning (`pins`)";
        why  = "; pinning needs the leaf SubjectPublicKeyInfo, which this "
               "backend does not extract yet";
    } else if (cfg->min_version >= 13 && !(caps & ZU_TLS_CAP_TLS13)) {
        what = "min_version = 13";
        why  = "; this backend tops out at TLS 1.2 and will not silently "
               "give you 1.2 instead";
    } else if ((cfg->source == ZU_TRUST_FILE || cfg->source == ZU_TRUST_DATA) &&
               !(caps & ZU_TLS_CAP_CA_FILE)) {
        what = "`ca_file` (replace the trust store)";
        why  = "; the request is refused rather than verified against the "
               "system store instead";
    } else if (cfg->ca_extra_file && !(caps & ZU_TLS_CAP_CA_EXTRA)) {
        what = "`ca_extra` (add to the trust store)";
        why  = "; the request is refused rather than verified against the "
               "system store alone";
    } else if (cfg->revocation && !(caps & ZU_TLS_CAP_REVOCATION)) {
        what = "revocation = TRUE";
        why  = "; this backend has no CRL or OCSP source, so the check would "
               "fail every chain rather than test revocation";
    }
    if (!what) return ZU_OK;
    zu_error_set(err, ZU_ERR_TLS_UNSUPPORTED, ZU_PHASE_TLS,
                 "%s is not supported by the %s TLS backend%s (see ?zuhttp_tls)",
                 what, backend, why);
    return ZU_ERR_TLS_UNSUPPORTED;
}

/* --- §35.2 cipher-suite names --------------------------------------------
 *
 * The suites a modern server actually negotiates, not the full IANA registry:
 * a table of 300 entries mostly listing things zuhttp will never see is a
 * maintenance burden that buys nothing. Unknown codes fall through to the
 * hex, which is still better than an empty field.
 *
 * Ordered as TLS 1.3, then the ECDHE AEAD suites, then the older ones — which
 * is roughly the order of preference any sane server has, and makes it easy
 * to see at a glance where a connection sits.
 */
const char *zu_tls_cipher_name(unsigned code) {
    switch (code) {
        /* TLS 1.3 */
        case 0x1301: return "TLS_AES_128_GCM_SHA256";
        case 0x1302: return "TLS_AES_256_GCM_SHA384";
        case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
        case 0x1304: return "TLS_AES_128_CCM_SHA256";
        case 0x1305: return "TLS_AES_128_CCM_8_SHA256";
        /* TLS 1.2 ECDHE + AEAD: forward secrecy, no CBC. What a healthy 1.2
         * connection looks like. */
        case 0xC02B: return "ECDHE-ECDSA-AES128-GCM-SHA256";
        case 0xC02C: return "ECDHE-ECDSA-AES256-GCM-SHA384";
        case 0xC02F: return "ECDHE-RSA-AES128-GCM-SHA256";
        case 0xC030: return "ECDHE-RSA-AES256-GCM-SHA384";
        case 0xCCA8: return "ECDHE-RSA-CHACHA20-POLY1305";
        case 0xCCA9: return "ECDHE-ECDSA-CHACHA20-POLY1305";
        case 0xCCAA: return "DHE-RSA-CHACHA20-POLY1305";
        case 0x009E: return "DHE-RSA-AES128-GCM-SHA256";
        case 0x009F: return "DHE-RSA-AES256-GCM-SHA384";
        /* ECDHE + CBC: forward secrecy, but the CBC construction TLS 1.3
         * removed. Named so a user can SEE they are on one. */
        case 0xC023: return "ECDHE-ECDSA-AES128-SHA256";
        case 0xC024: return "ECDHE-ECDSA-AES256-SHA384";
        case 0xC027: return "ECDHE-RSA-AES128-SHA256";
        case 0xC028: return "ECDHE-RSA-AES256-SHA384";
        case 0xC009: return "ECDHE-ECDSA-AES128-SHA";
        case 0xC00A: return "ECDHE-ECDSA-AES256-SHA";
        case 0xC013: return "ECDHE-RSA-AES128-SHA";
        case 0xC014: return "ECDHE-RSA-AES256-SHA";
        /* Static RSA key exchange: NO forward secrecy. Present because
         * seeing the name is the point — a user who finds one of these has
         * learned something a hex code would have hidden. */
        case 0x009C: return "AES128-GCM-SHA256";
        case 0x009D: return "AES256-GCM-SHA384";
        case 0x002F: return "AES128-SHA";
        case 0x0035: return "AES256-SHA";
        case 0x003C: return "AES128-SHA256";
        case 0x003D: return "AES256-SHA256";
        default:     return NULL;
    }
}

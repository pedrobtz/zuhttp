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

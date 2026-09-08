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

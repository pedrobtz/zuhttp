/* A "no TLS" backend, for binaries that link the engine without a TLS
 * library: the offline suite (test_engine_mock.c) and the engine fuzz target.
 * https:// fails cleanly with ZUH_ERR_TLS, which is itself a path worth
 * testing. Test-only: the package always links a real backend (configure). */
#include "zuh_tls.h"

const char *zuh_tls_backend_name(void) { return "none"; }
int         zuh_tls_available(void)    { return 0; }
unsigned    zuh_tls_backend_caps(void) { return 0u; }

zuh_code zuh_tls_connect(zuh_stream **out, zuh_stream *inner, const char *hostname,
                       const zuh_tls_config *cfg, zuh_deadline deadline,
                       zuh_error *err) {
    (void)inner; (void)hostname; (void)cfg; (void)deadline;
    if (out) *out = NULL;
    zuh_error_set(err, ZUH_ERR_TLS, ZUH_PHASE_TLS, "no TLS backend in this build");
    return ZUH_ERR_TLS;
}

void zuh_tls_stream_free(zuh_stream *s) { zuh_stream_free(s); }

int zuh_tls_get_info(const zuh_stream *s, zuh_tls_info *out) {
    (void)s; (void)out;
    return 0;
}

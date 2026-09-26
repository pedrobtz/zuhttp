/* A "no TLS" backend, for binaries that link the engine without a TLS
 * library: the offline suite (test_engine_mock.c) and the engine fuzz target.
 * https:// fails cleanly with ZU_ERR_TLS, which is itself a path worth
 * testing. Test-only: the package always links a real backend (configure). */
#include "zu_tls.h"

const char *zu_tls_backend_name(void) { return "none"; }
int         zu_tls_available(void)    { return 0; }
unsigned    zu_tls_backend_caps(void) { return 0u; }

zu_code zu_tls_connect(zu_stream **out, zu_stream *inner, const char *hostname,
                       const zu_tls_config *cfg, zu_deadline deadline,
                       zu_error *err) {
    (void)inner; (void)hostname; (void)cfg; (void)deadline;
    if (out) *out = NULL;
    zu_error_set(err, ZU_ERR_TLS, ZU_PHASE_TLS, "no TLS backend in this build");
    return ZU_ERR_TLS;
}

void zu_tls_stream_free(zu_stream *s) { zu_stream_free(s); }

int zu_tls_get_info(const zu_stream *s, zu_tls_info *out) {
    (void)s; (void)out;
    return 0;
}

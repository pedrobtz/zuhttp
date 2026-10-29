#include "zuh_error.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

void zuh_error_clear(zuh_error *e) {
    if (!e) return;
    memset(e, 0, sizeof *e);
}

void zuh_error_set(zuh_error *e, zuh_code code, zuh_phase phase, const char *fmt, ...) {
    va_list ap;
    if (!e) return;
    e->code = code;
    e->phase = phase;
    e->backend_code = 0;
    e->backend[0] = '\0';
    va_start(ap, fmt);
    vsnprintf(e->message, sizeof e->message, fmt, ap);
    va_end(ap);
}

void zuh_error_set_backend(zuh_error *e, const char *backend, int backend_code) {
    if (!e) return;
    if (backend) {
        strncpy(e->backend, backend, sizeof e->backend - 1);
        e->backend[sizeof e->backend - 1] = '\0';
    }
    e->backend_code = backend_code;
}

/* The R-visible class names of design §34.1. Order must match zuh_code. */
static const char *const k_class[ZUH_CODE_COUNT] = {
    "zu_ok",
    "zu_memory_error",
    "zu_overflow_error",
    "zu_dns_error",
    "zu_connect_error",
    "zu_timeout_error",
    "zu_tls_error",
    "zu_tls_certificate_error",
    "zu_tls_hostname_error",
    "zu_tls_handshake_error",
    "zu_tls_pin_error",
    "zu_tls_unsupported_error",
    "zu_http_parse_error",
    "zu_url_error",
    "zu_proxy_error",
    "zu_proxy_auth_error",
    "zu_redirect_error",
    "zu_too_many_redirects",
    "zu_body_limit_error",
    "zu_body_decode_error",
    "zu_body_not_replayable",
    "zu_http_status_error",
    "zu_http_client_error",
    "zu_http_server_error",
    "zu_cancelled_error",
    "zu_interrupted_error",
    "zu_fork_error",
    "zu_io_error",
    "zu_closed",
    "zu_wouldblock"
};

/* Parent of each class in the §34.1 tree, or ZUH_CODE_COUNT for a direct child
 * of zu_error. Kept adjacent to k_class[] so the two are read together. */
static zuh_code class_parent(zuh_code code) {
    switch (code) {
        case ZUH_ERR_TLS_CERT:
        case ZUH_ERR_TLS_HOSTNAME:
        case ZUH_ERR_TLS_HANDSHAKE:
        case ZUH_ERR_TLS_PIN:
        case ZUH_ERR_TLS_UNSUPPORTED:    return ZUH_ERR_TLS;
        case ZUH_ERR_PROXY_AUTH:         return ZUH_ERR_PROXY;
        case ZUH_ERR_TOO_MANY_REDIRECTS: return ZUH_ERR_REDIRECT;
        case ZUH_ERR_INTERRUPTED:        return ZUH_ERR_CANCELLED;
        case ZUH_ERR_HTTP_CLIENT:
        case ZUH_ERR_HTTP_SERVER:        return ZUH_ERR_HTTP_STATUS;
        default:                        return ZUH_CODE_COUNT;
    }
}

int zuh_code_class_chain(zuh_code code, const char **out, int max) {
    int n = 0;
    zuh_code c = code;
    if (!out || max <= 0) return 0;
    if (code <= ZUH_OK || code >= ZUH_CODE_COUNT) return 0;
    for (;;) {
        if (n >= max) return n;
        out[n++] = k_class[c];
        c = class_parent(c);
        if (c == ZUH_CODE_COUNT) break;
    }
    /* Every §34.1 class inherits zu_error, including the direct children, and
     * zu_error inherits zuhttp_error, directly above R's `error` (D-65): one
     * handler for everything zuhttp raises. */
    if (n < max) out[n++] = "zu_error";
    if (n < max) out[n++] = "zuhttp_error";
    return n;
}

const char *zuh_code_class(zuh_code code) {
    if (code < 0 || code >= ZUH_CODE_COUNT) return "zu_error";
    return k_class[code];
}

const char *zuh_phase_name(zuh_phase phase) {
    switch (phase) {
        case ZUH_PHASE_DNS:     return "dns";
        case ZUH_PHASE_CONNECT: return "connect";
        case ZUH_PHASE_TLS:     return "tls";
        case ZUH_PHASE_WRITE:   return "write";
        case ZUH_PHASE_TTFB:    return "ttfb";
        case ZUH_PHASE_READ:    return "read";
        case ZUH_PHASE_DECODE:  return "decode";
        case ZUH_PHASE_NONE:    break;
    }
    return "none";
}

int zuh_code_retryable(zuh_code code) {
    switch (code) {
        /* §33.2: transport failures before a response are retryable. */
        case ZUH_ERR_DNS:
        case ZUH_ERR_CONNECT:
        case ZUH_ERR_IO:
            return 1;
        /* A trust failure will not fix itself; nor will a parse error. */
        case ZUH_ERR_TLS:
        case ZUH_ERR_TLS_CERT:
        case ZUH_ERR_TLS_HOSTNAME:
        case ZUH_ERR_TLS_HANDSHAKE:
        case ZUH_ERR_TLS_PIN:
        /* A backend that cannot do something will not learn to on retry. */
        case ZUH_ERR_TLS_UNSUPPORTED:
        case ZUH_ERR_PARSE:
        case ZUH_ERR_URL:
        case ZUH_ERR_CANCELLED:
        case ZUH_ERR_INTERRUPTED:
        case ZUH_ERR_FORK:
        case ZUH_ERR_BODY_NOT_REPLAYABLE:
        /* Whether a 5xx or a 429 is worth another attempt depends on the
         * method's idempotency and on Retry-After, neither of which is visible
         * from a bare code. That is the retry layer's call (§33.2), not ours. */
        case ZUH_ERR_HTTP_STATUS:
        case ZUH_ERR_HTTP_CLIENT:
        case ZUH_ERR_HTTP_SERVER:
            return 0;
        /* Timeouts are retryable only if budget remains; that is the retry
         * layer's call (§24.3), not ours. Report the possibility. */
        case ZUH_ERR_TIMEOUT:
            return 1;
        default:
            return 0;
    }
}

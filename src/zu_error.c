#include "zu_error.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

void zu_error_clear(zu_error *e) {
    if (!e) return;
    memset(e, 0, sizeof *e);
}

void zu_error_set(zu_error *e, zu_code code, zu_phase phase, const char *fmt, ...) {
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

void zu_error_set_backend(zu_error *e, const char *backend, int backend_code) {
    if (!e) return;
    if (backend) {
        strncpy(e->backend, backend, sizeof e->backend - 1);
        e->backend[sizeof e->backend - 1] = '\0';
    }
    e->backend_code = backend_code;
}

/* The R-visible class names of design §34.1. Order must match zu_code. */
static const char *const k_class[ZU_CODE_COUNT] = {
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

/* Parent of each class in the §34.1 tree, or ZU_CODE_COUNT for a direct child
 * of zu_error. Kept adjacent to k_class[] so the two are read together. */
static zu_code class_parent(zu_code code) {
    switch (code) {
        case ZU_ERR_TLS_CERT:
        case ZU_ERR_TLS_HOSTNAME:
        case ZU_ERR_TLS_HANDSHAKE:
        case ZU_ERR_TLS_PIN:            return ZU_ERR_TLS;
        case ZU_ERR_PROXY_AUTH:         return ZU_ERR_PROXY;
        case ZU_ERR_TOO_MANY_REDIRECTS: return ZU_ERR_REDIRECT;
        case ZU_ERR_INTERRUPTED:        return ZU_ERR_CANCELLED;
        case ZU_ERR_HTTP_CLIENT:
        case ZU_ERR_HTTP_SERVER:        return ZU_ERR_HTTP_STATUS;
        default:                        return ZU_CODE_COUNT;
    }
}

int zu_code_class_chain(zu_code code, const char **out, int max) {
    int n = 0;
    zu_code c = code;
    if (!out || max <= 0) return 0;
    if (code <= ZU_OK || code >= ZU_CODE_COUNT) return 0;
    for (;;) {
        if (n >= max) return n;
        out[n++] = k_class[c];
        c = class_parent(c);
        if (c == ZU_CODE_COUNT) break;
    }
    /* Every §34.1 class inherits zu_error, including the direct children. */
    if (n < max) out[n++] = "zu_error";
    return n;
}

const char *zu_code_class(zu_code code) {
    if (code < 0 || code >= ZU_CODE_COUNT) return "zu_error";
    return k_class[code];
}

const char *zu_phase_name(zu_phase phase) {
    switch (phase) {
        case ZU_PHASE_DNS:     return "dns";
        case ZU_PHASE_CONNECT: return "connect";
        case ZU_PHASE_TLS:     return "tls";
        case ZU_PHASE_WRITE:   return "write";
        case ZU_PHASE_TTFB:    return "ttfb";
        case ZU_PHASE_READ:    return "read";
        case ZU_PHASE_DECODE:  return "decode";
        case ZU_PHASE_NONE:    break;
    }
    return "none";
}

int zu_code_retryable(zu_code code) {
    switch (code) {
        /* §33.2: transport failures before a response are retryable. */
        case ZU_ERR_DNS:
        case ZU_ERR_CONNECT:
        case ZU_ERR_IO:
            return 1;
        /* A trust failure will not fix itself; nor will a parse error. */
        case ZU_ERR_TLS:
        case ZU_ERR_TLS_CERT:
        case ZU_ERR_TLS_HOSTNAME:
        case ZU_ERR_TLS_HANDSHAKE:
        case ZU_ERR_TLS_PIN:
        case ZU_ERR_PARSE:
        case ZU_ERR_URL:
        case ZU_ERR_CANCELLED:
        case ZU_ERR_INTERRUPTED:
        case ZU_ERR_FORK:
        case ZU_ERR_BODY_NOT_REPLAYABLE:
        /* Whether a 5xx or a 429 is worth another attempt depends on the
         * method's idempotency and on Retry-After, neither of which is visible
         * from a bare code. That is the retry layer's call (§33.2), not ours. */
        case ZU_ERR_HTTP_STATUS:
        case ZU_ERR_HTTP_CLIENT:
        case ZU_ERR_HTTP_SERVER:
            return 0;
        /* Timeouts are retryable only if budget remains; that is the retry
         * layer's call (§24.3), not ours. Report the possibility. */
        case ZU_ERR_TIMEOUT:
            return 1;
        default:
            return 0;
    }
}

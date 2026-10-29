/* zuhttp — structured errors.
 *
 * Design §34. The C layer carries a stable code, a phase, an optional
 * backend-native code, and a human message; src/init.c maps the code to the
 * R condition class in §34.1. The code is the stable contract — message
 * wording may change, `zuh_code` may not.
 */
#ifndef ZUHTTP_ERROR_H
#define ZUHTTP_ERROR_H

#include "zuh_platform.h"

/* Keep in sync with the class hierarchy in design §34.1 and with
 * zuh_code_class() in zuh_error.c. Values are NOT stable across 0.x. */
typedef enum {
    ZUH_OK = 0,
    ZUH_ERR_NOMEM,
    ZUH_ERR_OVERFLOW,
    ZUH_ERR_DNS,
    ZUH_ERR_CONNECT,
    ZUH_ERR_TIMEOUT,
    ZUH_ERR_TLS,
    ZUH_ERR_TLS_CERT,
    ZUH_ERR_TLS_HOSTNAME,
    ZUH_ERR_TLS_HANDSHAKE,
    ZUH_ERR_TLS_PIN,
    /* The linked backend cannot honour a setting the caller asked for (pins,
     * TLS 1.3, a custom CA, revocation). Distinct from ZUH_ERR_TLS_PIN so that
     * "this backend cannot pin" and "the pin did not match" are never the
     * same condition (#12): a test that accepts either passes vacuously. */
    ZUH_ERR_TLS_UNSUPPORTED,
    ZUH_ERR_PARSE,
    ZUH_ERR_URL,           /* §8.2: the URL itself does not parse or is unusable */
    ZUH_ERR_PROXY,
    ZUH_ERR_PROXY_AUTH,
    ZUH_ERR_REDIRECT,
    ZUH_ERR_TOO_MANY_REDIRECTS,
    ZUH_ERR_BODY_LIMIT,
    ZUH_ERR_BODY_DECODE,
    ZUH_ERR_BODY_NOT_REPLAYABLE,
    /* A valid response that carries an error status. Not a transport failure:
     * the request succeeded, the server said no. Raised only by the R layer's
     * zu_resp_check() (§31.14), never by the engine — which is why the C core
     * never sets these, but defines them, so §34.1 has one definition. */
    ZUH_ERR_HTTP_STATUS,
    ZUH_ERR_HTTP_CLIENT,   /* 4xx */
    ZUH_ERR_HTTP_SERVER,   /* 5xx */
    ZUH_ERR_CANCELLED,
    ZUH_ERR_INTERRUPTED,
    ZUH_ERR_FORK,          /* §26.4 hazard 2, macOS */
    ZUH_ERR_IO,
    ZUH_ERR_CLOSED,        /* orderly peer close */
    ZUH_ERR_WOULDBLOCK,    /* not an error: retry when the stream is ready */
    ZUH_CODE_COUNT
} zuh_code;

typedef enum {
    ZUH_PHASE_NONE = 0,
    ZUH_PHASE_DNS,
    ZUH_PHASE_CONNECT,
    ZUH_PHASE_TLS,
    ZUH_PHASE_WRITE,
    ZUH_PHASE_TTFB,
    ZUH_PHASE_READ,
    ZUH_PHASE_DECODE
} zuh_phase;

#define ZUH_ERR_MSG_MAX 256

typedef struct {
    zuh_code  code;
    zuh_phase phase;
    int      backend_code;              /* native errno / OSStatus / OpenSSL code */
    char     backend[24];               /* "openssl", "schannel", "sectrust", ... */
    char     message[ZUH_ERR_MSG_MAX];
} zuh_error;

void zuh_error_clear(zuh_error *e);
void zuh_error_set(zuh_error *e, zuh_code code, zuh_phase phase, const char *fmt, ...) ZUH_PRINTF(4, 5);
void zuh_error_set_backend(zuh_error *e, const char *backend, int backend_code);

/* Stable identifiers. zuh_code_class() returns the R condition class from
 * design §34.1, e.g. "zu_tls_certificate_error". Never NULL. */
const char *zuh_code_class(zuh_code code);

/* The full §34.1 class chain, most specific first, ending with "zu_error".
 * "error" and "condition" are appended by the R layer, which is where those
 * names mean something.
 *
 * This exists so the hierarchy has ONE definition. Catching zu_tls_error must
 * also catch zu_tls_certificate_error, and a parent map maintained separately
 * in R would drift from k_class[] the first time a code was added.
 *
 * Writes at most `max` pointers into `out` and returns how many; 0 for ZUH_OK
 * or an out-of-range code. */
#define ZUH_CLASS_CHAIN_MAX 4
int zuh_code_class_chain(zuh_code code, const char **out, int max);
const char *zuh_phase_name(zuh_phase phase);

/* Retryability hint (§33.2, §34.2). */
int zuh_code_retryable(zuh_code code);

#endif /* ZUHTTP_ERROR_H */

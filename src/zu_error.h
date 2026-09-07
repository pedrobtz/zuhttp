/* zuhttp — structured errors.
 *
 * Design §34. The C layer carries a stable code, a phase, an optional
 * backend-native code, and a human message; src/init.c maps the code to the
 * R condition class in §34.1. The code is the stable contract — message
 * wording may change, `zu_code` may not.
 */
#ifndef ZUHTTP_ERROR_H
#define ZUHTTP_ERROR_H

#include "zu_platform.h"

/* Keep in sync with the class hierarchy in design §34.1 and with
 * zu_code_class() in zu_error.c. Values are NOT stable across 0.x. */
typedef enum {
    ZU_OK = 0,
    ZU_ERR_NOMEM,
    ZU_ERR_OVERFLOW,
    ZU_ERR_DNS,
    ZU_ERR_CONNECT,
    ZU_ERR_TIMEOUT,
    ZU_ERR_TLS,
    ZU_ERR_TLS_CERT,
    ZU_ERR_TLS_HOSTNAME,
    ZU_ERR_TLS_HANDSHAKE,
    ZU_ERR_TLS_PIN,
    ZU_ERR_PARSE,
    ZU_ERR_URL,           /* §8.2: the URL itself does not parse or is unusable */
    ZU_ERR_PROXY,
    ZU_ERR_PROXY_AUTH,
    ZU_ERR_REDIRECT,
    ZU_ERR_TOO_MANY_REDIRECTS,
    ZU_ERR_BODY_LIMIT,
    ZU_ERR_BODY_DECODE,
    ZU_ERR_BODY_NOT_REPLAYABLE,
    ZU_ERR_CANCELLED,
    ZU_ERR_INTERRUPTED,
    ZU_ERR_FORK,          /* §26.4 hazard 2, macOS */
    ZU_ERR_IO,
    ZU_ERR_CLOSED,        /* orderly peer close */
    ZU_ERR_WOULDBLOCK,    /* not an error: retry when the stream is ready */
    ZU_CODE_COUNT
} zu_code;

typedef enum {
    ZU_PHASE_NONE = 0,
    ZU_PHASE_DNS,
    ZU_PHASE_CONNECT,
    ZU_PHASE_TLS,
    ZU_PHASE_WRITE,
    ZU_PHASE_TTFB,
    ZU_PHASE_READ,
    ZU_PHASE_DECODE
} zu_phase;

#define ZU_ERR_MSG_MAX 256

typedef struct {
    zu_code  code;
    zu_phase phase;
    int      backend_code;              /* native errno / OSStatus / OpenSSL code */
    char     backend[24];               /* "openssl", "schannel", "sectrust", ... */
    char     message[ZU_ERR_MSG_MAX];
} zu_error;

void zu_error_clear(zu_error *e);
void zu_error_set(zu_error *e, zu_code code, zu_phase phase, const char *fmt, ...) ZU_PRINTF(4, 5);
void zu_error_set_backend(zu_error *e, const char *backend, int backend_code);

/* Stable identifiers. zu_code_class() returns the R condition class from
 * design §34.1, e.g. "zu_tls_certificate_error". Never NULL. */
const char *zu_code_class(zu_code code);
const char *zu_phase_name(zu_phase phase);

/* Retryability hint (§33.2, §34.2). */
int zu_code_retryable(zu_code code);

#endif /* ZUHTTP_ERROR_H */

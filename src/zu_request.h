/* zuhttp — request construction (design §17).
 *
 * Builds an HTTP/1.1 request into a checked buffer. Refuses to serialise
 * anything that would let a caller inject a second request.
 */
#ifndef ZUHTTP_REQUEST_H
#define ZUHTTP_REQUEST_H

#include "zu_platform.h"
#include "zu_headers.h"
#include "zu_buffer.h"

typedef enum {
    ZU_TARGET_ORIGIN = 0,   /* GET /path?q=1 HTTP/1.1        (direct) */
    ZU_TARGET_ABSOLUTE,     /* GET http://h/path HTTP/1.1    (via proxy, §20.3) */
    ZU_TARGET_AUTHORITY     /* CONNECT host:443 HTTP/1.1     (§20.3) */
} zu_target_form;

typedef enum {
    ZU_BODY_NONE = 0,
    ZU_BODY_LENGTH,         /* Content-Length: n */
    ZU_BODY_CHUNKED         /* Transfer-Encoding: chunked (§28.1) */
} zu_body_framing;

typedef struct {
    const char     *method;      /* borrowed; must be an RFC 7230 token */
    const char     *target;      /* borrowed; already encoded */
    const char     *host;        /* borrowed; authority for the Host header */
    zu_target_form  form;
    zu_headers      headers;
    zu_body_framing body;
    uint64_t        content_length;
} zu_request;

void    zu_request_init(zu_request *r);
void    zu_request_free(zu_request *r);

/* A method must be a token: no spaces, no control characters. "GET /x HTTP/1.1"
 * as a method is a request-splitting attempt, not a method. */
int zu_method_valid(const char *method);
/* A target may not contain CTLs, space, CR or LF. */
int zu_target_valid(const char *target);

/* Apply the §17.2 defaults, each only if absent so a caller override wins. */
zu_code zu_request_add_defaults(zu_request *r, const char *user_agent);

/* Serialise request line + headers + CRLF. The body is written separately by
 * the caller, so a large or streamed body never has to be buffered. */
zu_code zu_request_write(const zu_request *r, zu_buffer *out);

#endif /* ZUHTTP_REQUEST_H */

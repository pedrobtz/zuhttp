/* zuhttp — request construction (design §17).
 *
 * Builds an HTTP/1.1 request into a checked buffer. Refuses to serialise
 * anything that would let a caller inject a second request.
 */
#ifndef ZUHTTP_REQUEST_H
#define ZUHTTP_REQUEST_H

#include "zuh_platform.h"
#include "zuh_headers.h"
#include "zuh_buffer.h"

typedef enum {
    ZUH_TARGET_ORIGIN = 0,   /* GET /path?q=1 HTTP/1.1        (direct) */
    ZUH_TARGET_ABSOLUTE,     /* GET http://h/path HTTP/1.1    (via proxy, §20.3) */
    ZUH_TARGET_AUTHORITY     /* CONNECT host:443 HTTP/1.1     (§20.3) */
} zuh_target_form;

typedef enum {
    ZUH_BODY_NONE = 0,
    ZUH_BODY_LENGTH,         /* Content-Length: n */
    ZUH_BODY_CHUNKED         /* Transfer-Encoding: chunked (§28.1) */
} zuh_body_framing;

typedef struct {
    const char     *method;      /* borrowed; must be an RFC 7230 token */
    const char     *target;      /* borrowed; already encoded */
    const char     *host;        /* borrowed; authority for the Host header */
    zuh_target_form  form;
    zuh_headers      headers;
    zuh_body_framing body;
    uint64_t        content_length;
} zuh_request;

void    zuh_request_init(zuh_request *r);
void    zuh_request_free(zuh_request *r);

/* A method must be a token: no spaces, no control characters. "GET /x HTTP/1.1"
 * as a method is a request-splitting attempt, not a method. */
int zuh_method_valid(const char *method);
/* A target may not contain CTLs, space, CR or LF. */
int zuh_target_valid(const char *target);

/* Apply the §17.2 defaults, each only if absent so a caller override wins. */
zuh_code zuh_request_add_defaults(zuh_request *r, const char *user_agent);

/* Serialise request line + headers + CRLF. The body is written separately by
 * the caller, so a large or streamed body never has to be buffered. */
zuh_code zuh_request_write(const zuh_request *r, zuh_buffer *out);

#endif /* ZUHTTP_REQUEST_H */

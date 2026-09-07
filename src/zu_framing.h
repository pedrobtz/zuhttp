/* zuhttp — response body framing (design §18.1).
 *
 * THIS IS THE REQUEST-SMUGGLING DEFENCE. It is deliberately project-owned and
 * not delegated to the vendored parser (§8.1), it is strict rather than
 * permissive, and it is the primary fuzz target (§43).
 *
 * Ambiguity is always resolved by rejecting, never by picking an
 * interpretation. Every "prefer X over Y" rule in an HTTP client is a
 * disagreement waiting to happen with some intermediary that prefers Y.
 */
#ifndef ZUHTTP_FRAMING_H
#define ZUHTTP_FRAMING_H

#include "zu_platform.h"
#include "zu_headers.h"
#include "zu_error.h"

typedef enum {
    ZU_FRAME_NONE = 0,     /* no body can be present, whatever the headers say */
    ZU_FRAME_LENGTH,       /* exactly `length` bytes */
    ZU_FRAME_CHUNKED,      /* chunked transfer coding */
    ZU_FRAME_UNTIL_CLOSE   /* read to EOF; connection is not reusable */
} zu_frame_kind;

typedef struct {
    zu_frame_kind kind;
    uint64_t      length;    /* meaningful only for ZU_FRAME_LENGTH */
    int           poolable;  /* may the connection be reused after this body? */
} zu_framing;

/* `status` is the response status code; `method_is_head` reflects the request.
 * Returns ZU_OK, or ZU_ERR_PARSE for any ambiguous or malformed framing. */
zu_code zu_framing_decide(const zu_headers *h, int status, int method_is_head,
                          zu_framing *out, zu_error *err);

/* Strict unsigned decimal parse: digits only, no sign, no whitespace, no
 * leading '+', overflow-checked. Returns 1 on success. */
int zu_parse_u64_strict(const char *s, size_t len, uint64_t *out);

/* Trim leading/trailing OWS (SP and HTAB) from a field value. */
void zu_trim_ows(const char **s, size_t *len);

#endif /* ZUHTTP_FRAMING_H */

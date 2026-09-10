/* zuhttp — response parsing (design §18).
 *
 * Wraps picohttpparser (decision D-10) and translates its zero-copy output
 * into project-owned structures. The parser type is never exposed: §8.1
 * requires that the vendored library stay invisible above this file.
 *
 * picohttpparser PARSES. It decides nothing about framing. Every §18.1 rule
 * lives in zu_framing.c and is applied here explicitly.
 */
#ifndef ZUHTTP_RESPONSE_H
#define ZUHTTP_RESPONSE_H

#include "zu_platform.h"
#include "zu_headers.h"
#include "zu_framing.h"
#include "zu_error.h"

#define ZU_REASON_MAX 128

typedef struct {
    int         status;
    int         minor_version;      /* 0 or 1 for HTTP/1.x */
    char        reason[ZU_REASON_MAX];
    zu_headers  headers;
    zu_framing  framing;
} zu_response;

void zu_response_init(zu_response *r);
void zu_response_free(zu_response *r);

/* Incremental header-block parse.
 *
 *   ZU_OK              a complete header block; *consumed is set
 *   ZU_ERR_WOULDBLOCK  need more bytes; call again with a longer buffer
 *   ZU_ERR_PARSE       malformed — the connection must be closed
 *   ZU_ERR_BODY_LIMIT  a §40 limit was exceeded
 *
 * `last_len` is the length passed on the previous call (0 first time). It is
 * picohttpparser's incremental-parse hint and bounds the repeated scan.
 *
 * Framing is NOT decided here: call zu_response_decide_framing() once the
 * request method is known.
 */
zu_code zu_response_parse(zu_response *r, const char *buf, size_t len,
                          size_t last_len, size_t *consumed, zu_error *err);

/* Apply §18.1 given the request method. Fills r->framing. */
zu_code zu_response_decide_framing(zu_response *r, int method_is_head, zu_error *err);

/* Is this an interim 1xx that must be skipped and re-parsed (§18)? */
int zu_response_is_informational(const zu_response *r);

/* --- chunked decoding (§18.2) --- */

typedef struct {
    void   *state;          /* opaque; picohttpparser's decoder */
    int     started;
    uint64_t max_chunk;     /* §40 max_chunk_size; 0 disables */
    uint64_t total;         /* running decoded total */
    uint64_t max_total;     /* §40 max_body_bytes; 0 disables */
} zu_chunked;

zu_code zu_chunked_init(zu_chunked *c, uint64_t max_chunk, uint64_t max_total);
void    zu_chunked_free(zu_chunked *c);

/* Decode in place. On entry *len is the byte count in buf; on return it is the
 * number of DECODED bytes at the front of buf.
 *
 *   ZU_OK              the final chunk was seen; decoding is complete
 *   ZU_ERR_WOULDBLOCK  more input needed
 *   ZU_ERR_PARSE       malformed chunk framing
 *   ZU_ERR_BODY_LIMIT  a §40 limit was exceeded
 */
zu_code zu_chunked_decode(zu_chunked *c, char *buf, size_t *len, zu_error *err);

#endif /* ZUHTTP_RESPONSE_H */

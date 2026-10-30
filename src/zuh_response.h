/* zuhttp — response parsing (design §18).
 *
 * Wraps picohttpparser (decision D-10) and translates its zero-copy output
 * into project-owned structures. The parser type is never exposed: §8.1
 * requires that the vendored library stay invisible above this file.
 *
 * picohttpparser PARSES. It decides nothing about framing. Every §18.1 rule
 * lives in zuh_framing.c and is applied here explicitly.
 */
#ifndef ZUHTTP_RESPONSE_H
#define ZUHTTP_RESPONSE_H

#include "zuh_platform.h"
#include "zuh_headers.h"
#include "zuh_framing.h"
#include "zuh_error.h"

#define ZUH_REASON_MAX 128

typedef struct {
    int         status;
    int         minor_version;      /* 0 or 1 for HTTP/1.x */
    char        reason[ZUH_REASON_MAX];
    zuh_headers  headers;
    zuh_framing  framing;
} zuh_response;

void zuh_response_init(zuh_response *r);
void zuh_response_free(zuh_response *r);

/* Incremental header-block parse.
 *
 *   ZUH_OK              a complete header block; *consumed is set
 *   ZUH_ERR_WOULDBLOCK  need more bytes; call again with a longer buffer
 *   ZUH_ERR_PARSE       malformed — the connection must be closed
 *   ZUH_ERR_BODY_LIMIT  a §40 limit was exceeded
 *
 * `last_len` is the length passed on the previous call (0 first time). It is
 * picohttpparser's incremental-parse hint and bounds the repeated scan.
 *
 * Framing is NOT decided here: call zuh_response_decide_framing() once the
 * request method is known.
 */
zuh_code zuh_response_parse(zuh_response *r, const char *buf, size_t len,
                          size_t last_len, size_t *consumed, zuh_error *err);

/* Apply §18.1 given the request method. Fills r->framing. */
zuh_code zuh_response_decide_framing(zuh_response *r, int method_is_head, zuh_error *err);

/* Is this an interim 1xx that must be skipped and re-parsed (§18)? */
int zuh_response_is_informational(const zuh_response *r);

/* --- chunked decoding (§18.2) --- */

typedef struct {
    void   *state;          /* opaque; picohttpparser's decoder */
    int     started;
    uint64_t max_chunk;     /* §18.1 max_chunk_size; 0 disables. Checked
                             * against the unread rest of the current chunk
                             * when a feed ends inside it, so it is exact to
                             * within one feed: a whole chunk delivered in one
                             * call is not measured. */
    uint64_t total;         /* running decoded total */
    uint64_t max_total;     /* §40 max_body_bytes; 0 disables */
    size_t   surplus;       /* bytes after the final chunk and trailers, once
                             * decoding is complete: data the server sent
                             * beyond this response (§26.3) */
} zuh_chunked;

zuh_code zuh_chunked_init(zuh_chunked *c, uint64_t max_chunk, uint64_t max_total);
void    zuh_chunked_free(zuh_chunked *c);

/* Decode in place. On entry *len is the byte count in buf; on return it is the
 * number of DECODED bytes at the front of buf.
 *
 *   ZUH_OK              the final chunk was seen; decoding is complete
 *   ZUH_ERR_WOULDBLOCK  more input needed
 *   ZUH_ERR_PARSE       malformed chunk framing
 *   ZUH_ERR_BODY_LIMIT  a §40 limit was exceeded
 */
zuh_code zuh_chunked_decode(zuh_chunked *c, char *buf, size_t *len, zuh_error *err);

#endif /* ZUHTTP_RESPONSE_H */

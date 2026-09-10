/* zuhttp — checked growable buffer.
 *
 * Design §17 ("checked growable buffer", "all integer-to-string conversions
 * must be overflow-safe"), §40 (explicit limits), §18.4 (header limits
 * enforced as the buffer grows, not after).
 *
 * Every buffer carries a hard cap. Growth past it fails rather than
 * allocating, which is how §40's limits become real rather than advisory.
 */
#ifndef ZUHTTP_BUFFER_H
#define ZUHTTP_BUFFER_H

#include "zu_platform.h"
#include "zu_error.h"

typedef struct {
    unsigned char *data;
    size_t         len;
    size_t         cap;
    size_t         max;       /* hard limit; 0 means "no limit" */
    int            hit_limit; /* last failure was the cap, not the allocator */
} zu_buffer;

/* Return 1 on success, 0 on failure (out of memory, overflow, or cap). */
int  zu_buf_init(zu_buffer *b, size_t initial_cap, size_t max);
void zu_buf_free(zu_buffer *b);
void zu_buf_reset(zu_buffer *b);              /* keeps the allocation */

int  zu_buf_reserve(zu_buffer *b, size_t extra);
int  zu_buf_append(zu_buffer *b, const void *src, size_t n);
int  zu_buf_append_str(zu_buffer *b, const char *s);
int  zu_buf_append_byte(zu_buffer *b, unsigned char c);

/* Overflow-safe unsigned decimal conversion — no snprintf, no temp sizing
 * guesswork. Used for Content-Length and chunk sizes. */
int  zu_buf_append_u64(zu_buffer *b, uint64_t v);

/* Consume n bytes from the front, shifting the remainder down. Used by the
 * read path, where a parser has consumed a prefix of the buffer. */
void zu_buf_consume(zu_buffer *b, size_t n);

/* NUL-terminate without counting the NUL in len. Returns 1 on success.
 * The pointer is invalidated by any subsequent append. */
int  zu_buf_cstr(zu_buffer *b, const char **out);

/* Did the last failure hit the cap rather than the allocator? Lets callers
 * raise zu_body_limit_error instead of zu_memory_error (§21.4, §40). */
int  zu_buf_hit_limit(const zu_buffer *b);

#endif /* ZUHTTP_BUFFER_H */

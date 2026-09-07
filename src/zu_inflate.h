/* zuhttp — response decompression (design §21).
 *
 * Links SYSTEM zlib (D-7): it is present everywhere R runs, Rtools ships it,
 * and using it deletes ~10k vendored lines, one fuzz target and one
 * security-tracking obligation at no portability cost.
 *
 * Decompression is the cheapest denial-of-service vector in an HTTP client,
 * so both §21.4 limits are enforced DURING inflation, not after: a bomb must
 * fail early rather than after the allocation it was designed to provoke.
 */
#ifndef ZUHTTP_INFLATE_H
#define ZUHTTP_INFLATE_H

#include "zu_platform.h"
#include "zu_error.h"
#include "zu_buffer.h"

typedef enum {
    ZU_ENC_IDENTITY = 0,
    ZU_ENC_GZIP,
    ZU_ENC_DEFLATE,
    ZU_ENC_UNSUPPORTED
} zu_encoding;

/* Map a Content-Encoding field value. Unknown codings are UNSUPPORTED rather
 * than silently treated as identity, which would hand the caller compressed
 * bytes labelled as plain text. */
zu_encoding zu_encoding_parse(const char *content_encoding);

typedef struct {
    void       *strm;         /* z_stream, opaque here so zlib stays internal */
    zu_encoding enc;
    int         started;
    int         finished;
    int         wrap_decided; /* deflate: zlib vs raw has been chosen */
    unsigned char hdr[2];     /* first bytes, held back until wrap is decided */
    size_t      hdr_len;
    uint64_t    in_total;
    uint64_t    out_total;
    uint64_t    max_out;      /* §40 max_decompressed_bytes; 0 disables */
    unsigned    max_ratio;    /* §40 max_decompression_ratio; 0 disables */
} zu_inflate;

zu_code zu_inflate_init(zu_inflate *z, zu_encoding enc,
                        uint64_t max_out, unsigned max_ratio);
void    zu_inflate_free(zu_inflate *z);

/* Inflate `in` into `out` (appending).
 *   ZU_OK              stream finished
 *   ZU_ERR_WOULDBLOCK  more input needed
 *   ZU_ERR_BODY_DECODE malformed compressed data
 *   ZU_ERR_BODY_LIMIT  a §21.4 limit was hit
 */
zu_code zu_inflate_run(zu_inflate *z, const void *in, size_t in_len,
                       zu_buffer *out, zu_error *err);

#endif /* ZUHTTP_INFLATE_H */

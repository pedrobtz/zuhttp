/* zuhttp — the response body path: wire bytes to sink (design §27, §21).
 *
 * Split out of zu_engine.c at S17 for the reason every other read loop here
 * is its own translation unit: the engine opens sockets, so a test of the
 * engine needs a network, while a test of THIS needs only a mock stream. The
 * §27 streaming guarantee — that memory does not grow with the body — is a
 * property of this file, so it is the file the RSS test has to be able to
 * drive directly (§50.1).
 */
#ifndef ZUHTTP_BODY_H
#define ZUHTTP_BODY_H

#include "zu_platform.h"
#include "zu_error.h"
#include "zu_stream.h"
#include "zu_headers.h"
#include "zu_framing.h"
#include "zu_response.h"   /* the chunked decoder */
#include "zu_inflate.h"
#include "zu_sink.h"
#include "zu_time.h"

/* Decompression and delivery for one response. Opaque only by convention —
 * the engine allocates one on the stack per hop. */
typedef struct {
    zu_sink   *sink;
    zu_inflate inflate;
    int        inflating;
    zu_buffer  staging;     /* decoded bytes, drained to the sink each pass */
    uint64_t   raw_seen;    /* pre-decode, so LENGTH framing can find its end */
    uint64_t   max_body;    /* §40; checked BEFORE the sink sees a byte */
} zu_body_pipe;

/* Reads Content-Encoding from `h` and, when it decodes, REMOVES that header
 * and Content-Length: once the body leaves here it is not encoded any more,
 * so those headers would describe something the caller never received. */
zu_code zu_body_pipe_init(zu_body_pipe *p, zu_sink *sink, zu_headers *h,
                          int no_decode, uint64_t max_body, zu_error *err);
void    zu_body_pipe_free(zu_body_pipe *p);

/* Hand one run of wire bytes onward, inflating first when compressed. */
zu_code zu_body_pipe_feed(zu_body_pipe *p, const void *data, size_t n,
                          zu_error *err);

/* Read one body from `s` according to the §18.1 framing decision. `seed` is
 * whatever already arrived alongside the headers. */
zu_code zu_body_read(zu_stream *s, const zu_framing *fr, zu_body_pipe *p,
                     const char *seed, size_t seed_len,
                     uint64_t max_body, zu_deadline dl, zu_error *err);

#endif /* ZUHTTP_BODY_H */

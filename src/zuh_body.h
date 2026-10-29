/* zuhttp — the response body path: wire bytes to sink (design §27, §21).
 *
 * Split out of zuh_engine.c at S17 for the reason every other read loop here
 * is its own translation unit: the engine opens sockets, so a test of the
 * engine needs a network, while a test of THIS needs only a mock stream. The
 * §27 streaming guarantee — that memory does not grow with the body — is a
 * property of this file, so it is the file the RSS test has to be able to
 * drive directly (§50.1).
 */
#ifndef ZUHTTP_BODY_H
#define ZUHTTP_BODY_H

#include "zuh_platform.h"
#include "zuh_error.h"
#include "zuh_stream.h"
#include "zuh_headers.h"
#include "zuh_framing.h"
#include "zuh_response.h"   /* the chunked decoder */
#include "zuh_inflate.h"
#include "zuh_sink.h"
#include "zuh_time.h"

/* Decompression and delivery for one response. Opaque only by convention —
 * the engine allocates one on the stack per hop. */
typedef struct {
    zuh_sink   *sink;
    zuh_inflate inflate;
    int        inflating;
    zuh_buffer  staging;     /* decoded bytes, drained to the sink each pass */
    uint64_t   raw_seen;    /* pre-decode, so LENGTH framing can find its end */
    /* Bytes received beyond the end of this response's framing. A server
     * does not send what was not asked for, so any surplus means the stream
     * is out of step with its responses; the engine then refuses to pool the
     * connection (§26.3), since the next response on it could not be trusted
     * to be the answer to the next request. */
    uint64_t   surplus;
    uint64_t   max_body;    /* §40; checked BEFORE the sink sees a byte */
} zuh_body_pipe;

/* Reads Content-Encoding from `h` and, when it decodes, REMOVES that header
 * and Content-Length: once the body leaves here it is not encoded any more,
 * so those headers would describe something the caller never received. */
zuh_code zuh_body_pipe_init(zuh_body_pipe *p, zuh_sink *sink, zuh_headers *h,
                          int no_decode, uint64_t max_body, zuh_error *err);
void    zuh_body_pipe_free(zuh_body_pipe *p);

/* Hand one run of wire bytes onward, inflating first when compressed. */
zuh_code zuh_body_pipe_feed(zuh_body_pipe *p, const void *data, size_t n,
                          zuh_error *err);

/* Read one body from `s` according to the §18.1 framing decision. `seed` is
 * whatever already arrived alongside the headers. */
zuh_code zuh_body_read(zuh_stream *s, const zuh_framing *fr, zuh_body_pipe *p,
                     const char *seed, size_t seed_len,
                     uint64_t max_body, zuh_deadline dl, zuh_error *err);

#endif /* ZUHTTP_BODY_H */

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
    /* §65.3, D-91: the trailer fields, from a chunked body's trailer section
     * or an HTTP/2 stream's trailing HEADERS. Empty when there were none. */
    zuh_headers trailers;
} zuh_body_pipe;

/* §21.4, D-69: decoded output may be at most this many times the compressed
 * input, once 32 input bytes have been seen. max_body bounds a bomb in
 * megabytes; this makes it fail after kilobytes. 1000 sits just under
 * deflate's ceiling of about 1030:1, so only a pathological body -- a run of
 * one byte -- can reach it, and legitimate text compresses tens of times. */
#define ZUH_MAX_DECOMPRESSION_RATIO 1000u

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
/* The end of a body: flush what the decoder holds and check that it ended
 * where the coding says it ends. zuh_body_read() calls it; the HTTP/2 driver
 * (§65.2), which feeds the pipe itself, calls it at END_STREAM. */
zuh_code zuh_body_pipe_finish(zuh_body_pipe *p, zuh_error *err);

/* §28, §65.7, D-95: a request body produced a piece at a time, by a
 * function the caller supplies (R's zu_body_stream()). `next` sets *data and
 * *len to the next piece, which stays valid until the following call, and
 * *len to 0 at the end; anything but ZUH_OK stops the request. `release`
 * frees `ctx`, and is called exactly once, by whoever owns the source last:
 * the engine, or the pulled body it was handed to (§65.4). A source is not
 * rewindable, so it is never replayed (§28.2). */
/* `dl` is the deadline of the wait `next` is called under: the attempt's
 * over HTTP/1.1, the send's over HTTP/2. Empty pieces write nothing, so a
 * source that loops past them is the only thing that can see time pass, and
 * it stops at `dl` with ZUH_ERR_TIMEOUT (#217). */
typedef struct {
    zuh_code (*next)(void *ctx, const void **data, size_t *len, zuh_deadline dl,
                     zuh_error *err);
    void     (*release)(void *ctx);
    void      *ctx;
} zuh_body_source;

/* One response body under one framing, read a step at a time (§65.4).
 * zuh_body_read() loops over the steps; a pulled body takes them one by one.
 * `seed` is copied, so the caller's buffer need not outlive the reader.
 * There is no byte cap here: max_body counts DECODED bytes (§21.4, §40), so
 * it belongs to the pipe, after inflation; a cap on the de-chunked payload
 * bound compressed bytes under chunked framing alone (#212). */
typedef struct {
    zuh_framing fr;
    zuh_chunked dec;
    int         chunked;
    zuh_buffer  seed;       /* bytes that arrived with the headers */
    char       *work;       /* one read */
    int         done;       /* the body ended and the pipe was finished */
} zuh_body_reader;

zuh_code zuh_body_reader_init(zuh_body_reader *r, const zuh_framing *fr,
                              const char *seed, size_t seed_len, zuh_error *err);
/* One read's worth: feeds the pipe, sets r->done (after finishing the pipe)
 * when the framing says the body is over. */
zuh_code zuh_body_reader_step(zuh_body_reader *r, zuh_stream *s, zuh_body_pipe *p,
                              zuh_deadline dl, zuh_error *err);
void     zuh_body_reader_free(zuh_body_reader *r);

zuh_code zuh_body_read(zuh_stream *s, const zuh_framing *fr, zuh_body_pipe *p,
                     const char *seed, size_t seed_len,
                     zuh_deadline dl, zuh_error *err);

#endif /* ZUHTTP_BODY_H */

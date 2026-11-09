#include "zuh_body.h"
#include "zuh_alloc.h"
#include <string.h>

/* Kept local: the engine's own chunk size is an engine concern, and this file
 * must not depend on it. 16 KiB is one comfortable TCP read and, with the
 * staging buffer below, is the entire steady-state cost of a download. */
#define ZUH_READ_CHUNK 16384

/* Everything between the wire and the sink, for one response (§27, §21).
 *
 * Before S17 the body was accumulated whole and then decompressed whole, so a
 * 100 MB gzip response cost the compressed size plus the decoded size in
 * resident memory. Both stages are incremental now, and the only memory held
 * is one read chunk plus one staging buffer regardless of the body's size.
 * That is what makes S17's RSS criterion a property of the design rather than
 * a thing that happens to be true for small responses.
 */
zuh_code zuh_body_pipe_init(zuh_body_pipe *p, zuh_sink *sink, zuh_headers *h,
                         int no_decode, uint64_t max_body, zuh_error *err) {
    zuh_encoding kind;
    memset(p, 0, sizeof *p);
    p->sink = sink;
    p->max_body = max_body;
    zuh_headers_init(&p->trailers);

    /* Two fields are a stacked encoding (RFC 9110 §8.4), refused as a
     * "gzip, br" value is (§21.4): decoding the first and dropping both
     * would hand back still-encoded bytes with the evidence gone (#211). */
    if (!no_decode && zuh_headers_count(h, "Content-Encoding") > 1) {
        zuh_error_set(err, ZUH_ERR_BODY_DECODE, ZUH_PHASE_DECODE,
                     "repeated Content-Encoding fields (a stacked encoding) are not supported");
        return ZUH_ERR_BODY_DECODE;
    }
    kind = no_decode ? ZUH_ENC_IDENTITY
                     : zuh_encoding_parse(zuh_headers_get(h, "Content-Encoding"));
    if (kind == ZUH_ENC_IDENTITY) return ZUH_OK;
    if (kind == ZUH_ENC_UNSUPPORTED) {
        zuh_error_set(err, ZUH_ERR_BODY_DECODE, ZUH_PHASE_DECODE,
                     "unsupported Content-Encoding: %s",
                     zuh_headers_get(h, "Content-Encoding"));
        return ZUH_ERR_BODY_DECODE;
    }
    if (zuh_inflate_init(&p->inflate, kind, max_body, ZUH_MAX_DECOMPRESSION_RATIO) != ZUH_OK)
        return ZUH_ERR_NOMEM;
    if (!zuh_buf_init(&p->staging, ZUH_READ_CHUNK * 4, (size_t)-1)) {
        zuh_inflate_free(&p->inflate);
        return ZUH_ERR_NOMEM;
    }
    p->inflating = 1;
    /* Once the body leaves here it is not encoded any more, so these headers
     * would describe something the caller never received. */
    (void)zuh_headers_remove(h, "Content-Encoding");
    (void)zuh_headers_remove(h, "Content-Length");
    return ZUH_OK;
}

void zuh_body_pipe_free(zuh_body_pipe *p) {
    zuh_headers_free(&p->trailers);
    if (!p->inflating) return;
    zuh_inflate_free(&p->inflate);
    zuh_buf_free(&p->staging);
    p->inflating = 0;
}

/* §40's cap, enforced BEFORE the sink sees anything.
 *
 * That placement is the whole point. Checking afterwards — "did we go over?"
 * — is how a 1 KB max_body handed 1593 bytes to a user's callback: the check
 * fired correctly, but a byte a caller has already received cannot be
 * un-received. A bound someone sizes a buffer or a disk quota from has to
 * hold before the write, not after it. Found by fuzz_body on its first seed;
 * the identical mistake was found in zuh_inflate by fuzzing at S18, which is
 * why the compressed path below is already exact. */
static zuh_code cap_check(const zuh_body_pipe *p, size_t n, zuh_error *err) {
    uint64_t written = p->sink ? p->sink->written : 0;
    if (p->max_body == 0) return ZUH_OK;              /* 0 = no cap */
    if (written + (uint64_t)n <= p->max_body) return ZUH_OK;
    zuh_error_set(err, ZUH_ERR_BODY_LIMIT, ZUH_PHASE_READ,
                 "response body exceeds the configured limit");
    return ZUH_ERR_BODY_LIMIT;
}

/* Hand one run of wire bytes onward, inflating first when the response was
 * compressed. The staging buffer is truncated rather than freed each pass, so
 * it settles at the size of the largest single expansion and stops growing. */
zuh_code zuh_body_pipe_feed(zuh_body_pipe *p, const void *data, size_t n, zuh_error *err) {
    zuh_code rc;
    if (n == 0) return ZUH_OK;
    if (!p->inflating) {
        /* Identity: output length equals input length, so one check up front
         * makes the cap exact. The compressed branch does not need it —
         * zuh_inflate bounds its own output window to the remaining allowance
         * and never emits past it (§21.4). */
        rc = cap_check(p, n, err);
        if (rc != ZUH_OK) return rc;
        return zuh_sink_write(p->sink, data, n, err);
    }

    p->staging.len = 0;
    rc = zuh_inflate_run(&p->inflate, data, n, &p->staging, err);
    if (rc != ZUH_OK && rc != ZUH_ERR_WOULDBLOCK) return rc;
    return zuh_sink_write(p->sink, p->staging.data, p->staging.len, err);
}

/* D-76: the framing says the body is over; the decoder has to agree. Every
 * framing mode ends here, because each of them used to report success on a
 * compressed stream that stopped short — the byte count was right and the
 * body was not. Whatever the decoder still holds is delivered first. */
zuh_code zuh_body_pipe_finish(zuh_body_pipe *p, zuh_error *err) {
    zuh_code rc;
    if (!p->inflating) return ZUH_OK;
    p->staging.len = 0;
    rc = zuh_inflate_run(&p->inflate, NULL, 0, &p->staging, err);
    if (rc != ZUH_OK) return rc;
    return p->staging.len
        ? zuh_sink_write(p->sink, p->staging.data, p->staging.len, err) : ZUH_OK;
}

/* --- the reader: one framing, stepped one read at a time ---------------
 *
 * §65.4 needs a body that is read when the caller asks rather than all at
 * once, so the framing loop that used to live here is a state machine whose
 * step does one read's worth of work. zuh_body_read() is the loop over it;
 * zuh_resp_read() takes one step at a time. Either way the same framing code
 * runs, so a pulled body cannot be framed differently from a buffered one. */

zuh_code zuh_body_reader_init(zuh_body_reader *r, const zuh_framing *fr,
                              const char *seed, size_t seed_len, zuh_error *err) {
    memset(r, 0, sizeof *r);
    r->fr = *fr;
    r->work = (char *)zuh_alloc(ZUH_READ_CHUNK);
    if (!r->work || !zuh_buf_init(&r->seed, seed_len ? seed_len : 1, (size_t)-1) ||
        (seed_len && !zuh_buf_append(&r->seed, seed, seed_len))) {
        zuh_body_reader_free(r);
        zuh_error_set(err, ZUH_ERR_NOMEM, ZUH_PHASE_READ, "out of memory");
        return ZUH_ERR_NOMEM;
    }
    if (fr->kind == ZUH_FRAME_CHUNKED) {
        zuh_code rc = zuh_chunked_init(&r->dec);
        if (rc != ZUH_OK) {
            zuh_body_reader_free(r);
            zuh_error_set(err, rc, ZUH_PHASE_READ, "out of memory");
            return rc;
        }
        r->chunked = 1;
    }
    return ZUH_OK;
}

void zuh_body_reader_free(zuh_body_reader *r) {
    if (r->chunked) zuh_chunked_free(&r->dec);
    r->chunked = 0;
    zuh_free(r->work);
    r->work = NULL;
    zuh_buf_free(&r->seed);
}

/* The next run of wire bytes: what arrived with the headers first, then the
 * stream. 0 is end of stream. */
static zuh_ssize next_bytes(zuh_body_reader *r, zuh_stream *s, zuh_deadline dl,
                            zuh_error *err) {
    if (r->seed.len) {
        size_t n = r->seed.len < ZUH_READ_CHUNK ? r->seed.len : ZUH_READ_CHUNK;
        memcpy(r->work, r->seed.data, n);
        zuh_buf_consume(&r->seed, n);
        return (zuh_ssize)n;
    }
    return zuh_stream_read(s, r->work, ZUH_READ_CHUNK, dl, err);
}

static zuh_code step_framed(zuh_body_reader *r, zuh_stream *s, zuh_body_pipe *p,
                            zuh_deadline dl, zuh_error *err) {
    const zuh_framing *fr = &r->fr;
    zuh_ssize n;
    size_t take;

    if (fr->kind == ZUH_FRAME_NONE) {
        /* HEAD, 204, 304: no body, so anything already read is surplus. */
        p->surplus += (uint64_t)r->seed.len;
        zuh_buf_reset(&r->seed);
        r->done = 1;
        return ZUH_OK;
    }
    if (fr->kind == ZUH_FRAME_LENGTH && p->raw_seen >= fr->length) {
        p->surplus += (uint64_t)r->seed.len;
        zuh_buf_reset(&r->seed);
        r->done = 1;
        return ZUH_OK;
    }

    n = next_bytes(r, s, dl, err);
    if (n < 0) return err->code;
    if (n == 0) {
        if (fr->kind == ZUH_FRAME_UNTIL_CLOSE) { r->done = 1; return ZUH_OK; }
        if (fr->kind == ZUH_FRAME_CHUNKED) {
            zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_READ,
                         "connection closed inside a chunked body");
            return ZUH_ERR_PARSE;
        }
        zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_READ,
                     "connection closed with %lu of %lu body bytes read",
                     (unsigned long)p->raw_seen, (unsigned long)fr->length);
        return ZUH_ERR_PARSE;
    }

    if (fr->kind == ZUH_FRAME_CHUNKED) {
        size_t len = (size_t)n;
        zuh_code rc, w;
        /* WIRE bytes, before de-chunking: `len` comes back as the decoded
         * length, so counting that would report the body and call it the
         * wire. The difference is the chunk framing, which is exactly what
         * someone comparing the two numbers wants to see. */
        p->raw_seen += (uint64_t)n;
        rc = zuh_chunked_decode(&r->dec, r->work, &len, err);
        /* The result first: a failed decode delivers nothing (#210). */
        if (rc != ZUH_OK && rc != ZUH_ERR_WOULDBLOCK) return rc;
        if (len) {
            w = zuh_body_pipe_feed(p, r->work, len, err);
            if (w != ZUH_OK) return w;
        }
        if (rc == ZUH_ERR_WOULDBLOCK) return ZUH_OK;
        /* The last chunk and its trailers are in, and with them the end of
         * the message: whatever followed it, in this read or still held from
         * the headers, belongs to no response we asked for. */
        p->surplus += (uint64_t)r->dec.surplus + (uint64_t)r->seed.len;
        zuh_buf_reset(&r->seed);
        zuh_headers_free(&p->trailers);
        p->trailers = r->dec.trailers;           /* ownership moves */
        zuh_headers_init(&r->dec.trailers);
        r->done = 1;
        return ZUH_OK;
    }

    /* LENGTH and UNTIL_CLOSE differ only in when they stop. Anything past
     * Content-Length is the next response on this connection, not this body;
     * trimming here rather than truncating a buffer afterwards is what lets
     * the body go straight to a sink. No cap check here: zuh_body_pipe_feed()
     * refuses before writing, so §27.1's rule that the cap covers every sink
     * holds where every sink's bytes pass. */
    take = (size_t)n;
    if (fr->kind == ZUH_FRAME_LENGTH && p->raw_seen + take > fr->length)
        take = (size_t)(fr->length - p->raw_seen);
    p->surplus += (uint64_t)((size_t)n - take);
    {
        zuh_code w = zuh_body_pipe_feed(p, r->work, take, err);
        if (w != ZUH_OK) return w;
    }
    p->raw_seen += take;
    if (fr->kind == ZUH_FRAME_LENGTH && p->raw_seen >= fr->length) {
        p->surplus += (uint64_t)r->seed.len;
        zuh_buf_reset(&r->seed);
        r->done = 1;
    }
    return ZUH_OK;
}

zuh_code zuh_body_reader_step(zuh_body_reader *r, zuh_stream *s, zuh_body_pipe *p,
                              zuh_deadline dl, zuh_error *err) {
    zuh_code rc;
    if (r->done) return ZUH_OK;
    rc = step_framed(r, s, p, dl, err);
    if (rc == ZUH_OK && r->done) rc = zuh_body_pipe_finish(p, err);
    return rc;
}

zuh_code zuh_body_read(zuh_stream *s, const zuh_framing *fr, zuh_body_pipe *p,
                         const char *seed, size_t seed_len,
                         zuh_deadline dl, zuh_error *err) {
    zuh_body_reader r;
    zuh_code rc = zuh_body_reader_init(&r, fr, seed, seed_len, err);
    while (rc == ZUH_OK && !r.done) rc = zuh_body_reader_step(&r, s, p, dl, err);
    zuh_body_reader_free(&r);
    return rc;
}

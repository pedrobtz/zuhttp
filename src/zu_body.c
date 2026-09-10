#include "zu_body.h"
#include "zu_alloc.h"
#include <string.h>

/* Kept local: the engine's own chunk size is an engine concern, and this file
 * must not depend on it. 16 KiB is one comfortable TCP read and, with the
 * staging buffer below, is the entire steady-state cost of a download. */
#define ZU_READ_CHUNK 16384

/* Everything between the wire and the sink, for one response (§27, §21).
 *
 * Before S17 the body was accumulated whole and then decompressed whole, so a
 * 100 MB gzip response cost the compressed size plus the decoded size in
 * resident memory. Both stages are incremental now, and the only memory held
 * is one read chunk plus one staging buffer regardless of the body's size.
 * That is what makes S17's RSS criterion a property of the design rather than
 * a thing that happens to be true for small responses.
 */
zu_code zu_body_pipe_init(zu_body_pipe *p, zu_sink *sink, zu_headers *h,
                         int no_decode, uint64_t max_body, zu_error *err) {
    zu_encoding kind;
    memset(p, 0, sizeof *p);
    p->sink = sink;
    p->max_body = max_body;

    kind = no_decode ? ZU_ENC_IDENTITY
                     : zu_encoding_parse(zu_headers_get(h, "Content-Encoding"));
    if (kind == ZU_ENC_IDENTITY) return ZU_OK;
    if (kind == ZU_ENC_UNSUPPORTED) {
        zu_error_set(err, ZU_ERR_BODY_DECODE, ZU_PHASE_DECODE,
                     "unsupported Content-Encoding: %s",
                     zu_headers_get(h, "Content-Encoding"));
        return ZU_ERR_BODY_DECODE;
    }
    if (zu_inflate_init(&p->inflate, kind, max_body, 0) != ZU_OK)
        return ZU_ERR_NOMEM;
    if (!zu_buf_init(&p->staging, ZU_READ_CHUNK * 4, (size_t)-1)) {
        zu_inflate_free(&p->inflate);
        return ZU_ERR_NOMEM;
    }
    p->inflating = 1;
    /* Once the body leaves here it is not encoded any more, so these headers
     * would describe something the caller never received. */
    (void)zu_headers_remove(h, "Content-Encoding");
    (void)zu_headers_remove(h, "Content-Length");
    return ZU_OK;
}

void zu_body_pipe_free(zu_body_pipe *p) {
    if (!p->inflating) return;
    zu_inflate_free(&p->inflate);
    zu_buf_free(&p->staging);
    p->inflating = 0;
}

/* §40's cap, enforced BEFORE the sink sees anything.
 *
 * That placement is the whole point. Checking afterwards — "did we go over?"
 * — is how a 1 KB max_body handed 1593 bytes to a user's callback: the check
 * fired correctly, but a byte a caller has already received cannot be
 * un-received. A bound someone sizes a buffer or a disk quota from has to
 * hold before the write, not after it. Found by fuzz_body on its first seed;
 * the identical mistake was found in zu_inflate by fuzzing at S18, which is
 * why the compressed path below is already exact. */
static zu_code cap_check(const zu_body_pipe *p, size_t n, zu_error *err) {
    uint64_t written = p->sink ? p->sink->written : 0;
    if (p->max_body == 0) return ZU_OK;              /* 0 = no cap */
    if (written + (uint64_t)n <= p->max_body) return ZU_OK;
    zu_error_set(err, ZU_ERR_BODY_LIMIT, ZU_PHASE_READ,
                 "response body exceeds the configured limit");
    return ZU_ERR_BODY_LIMIT;
}

/* Hand one run of wire bytes onward, inflating first when the response was
 * compressed. The staging buffer is truncated rather than freed each pass, so
 * it settles at the size of the largest single expansion and stops growing. */
zu_code zu_body_pipe_feed(zu_body_pipe *p, const void *data, size_t n, zu_error *err) {
    zu_code rc;
    if (n == 0) return ZU_OK;
    if (!p->inflating) {
        /* Identity: output length equals input length, so one check up front
         * makes the cap exact. The compressed branch does not need it —
         * zu_inflate bounds its own output window to the remaining allowance
         * and never emits past it (§21.4). */
        rc = cap_check(p, n, err);
        if (rc != ZU_OK) return rc;
        return zu_sink_write(p->sink, data, n, err);
    }

    p->staging.len = 0;
    rc = zu_inflate_run(&p->inflate, data, n, &p->staging, err);
    if (rc != ZU_OK && rc != ZU_ERR_WOULDBLOCK) return rc;
    return zu_sink_write(p->sink, p->staging.data, p->staging.len, err);
}

zu_code zu_body_read(zu_stream *s, const zu_framing *fr, zu_body_pipe *p,
                         const char *seed, size_t seed_len,
                         uint64_t max_body, zu_deadline dl, zu_error *err) {
    if (fr->kind == ZU_FRAME_NONE) return ZU_OK;

    if (fr->kind == ZU_FRAME_CHUNKED) {
        zu_chunked dec;
        char *work;
        zu_code rc = zu_chunked_init(&dec, 0, max_body);
        if (rc != ZU_OK) return rc;

        work = (char *)zu_alloc(ZU_READ_CHUNK);
        if (!work) { zu_chunked_free(&dec); return ZU_ERR_NOMEM; }

        if (seed_len) {
            size_t len = seed_len;
            memcpy(work, seed, seed_len);
            /* WIRE bytes, before de-chunking: `len` comes back as the decoded
             * length, so counting that would report the body and call it the
             * wire. The difference is the chunk framing, which is exactly what
             * someone comparing the two numbers wants to see. */
            p->raw_seen += seed_len;
            rc = zu_chunked_decode(&dec, work, &len, err);
            if (len) {
                zu_code w = zu_body_pipe_feed(p, work, len, err);
                if (w != ZU_OK) rc = w;
            }
        } else {
            rc = ZU_ERR_WOULDBLOCK;
        }
        while (rc == ZU_ERR_WOULDBLOCK) {
            size_t len;
            zu_ssize n = zu_stream_read(s, work, ZU_READ_CHUNK, dl, err);
            if (n < 0) { rc = err->code; break; }
            if (n == 0) {
                zu_error_set(err, ZU_ERR_PARSE, ZU_PHASE_READ,
                             "connection closed inside a chunked body");
                rc = ZU_ERR_PARSE;
                break;
            }
            len = (size_t)n;
            p->raw_seen += (uint64_t)n;
            rc = zu_chunked_decode(&dec, work, &len, err);
            if (len) {
                zu_code w = zu_body_pipe_feed(p, work, len, err);
                if (w != ZU_OK) { rc = w; break; }
            }
        }
        zu_free(work);
        zu_chunked_free(&dec);
        return rc == ZU_OK ? ZU_OK : rc;
    }

    /* LENGTH and UNTIL_CLOSE differ only in when they stop. */
    if (seed_len) {
        size_t take = seed_len;
        /* Anything past Content-Length is the next response on this
         * connection, not this body. Trimming here rather than truncating a
         * buffer afterwards is what lets the body go straight to a sink. */
        if (fr->kind == ZU_FRAME_LENGTH && take > fr->length)
            take = (size_t)fr->length;
        {
            zu_code w = zu_body_pipe_feed(p, seed, take, err);
            if (w != ZU_OK) return w;
        }
        p->raw_seen += take;
    }
    for (;;) {
        char chunk[ZU_READ_CHUNK];
        zu_ssize n;
        size_t take;

        if (fr->kind == ZU_FRAME_LENGTH && p->raw_seen >= fr->length) break;
        /* No cap check here any more. It used to live at exactly this point,
         * AFTER a chunk had already reached the sink, which made max_body
         * something noticed rather than a bound enforced. zu_body_pipe_feed()
         * refuses before writing, so reaching this line means the cap still
         * holds. §27.1's rule that the cap covers every sink, file included,
         * is satisfied there — where every sink's bytes pass.
         */
        n = zu_stream_read(s, chunk, sizeof chunk, dl, err);
        if (n < 0) return err->code;
        if (n == 0) {
            if (fr->kind == ZU_FRAME_UNTIL_CLOSE) break;
            zu_error_set(err, ZU_ERR_PARSE, ZU_PHASE_READ,
                         "connection closed with %lu of %lu body bytes read",
                         (unsigned long)p->raw_seen, (unsigned long)fr->length);
            return ZU_ERR_PARSE;
        }
        take = (size_t)n;
        if (fr->kind == ZU_FRAME_LENGTH && p->raw_seen + take > fr->length)
            take = (size_t)(fr->length - p->raw_seen);
        {
            zu_code w = zu_body_pipe_feed(p, chunk, take, err);
            if (w != ZU_OK) return w;
        }
        p->raw_seen += take;
    }
    return ZU_OK;
}

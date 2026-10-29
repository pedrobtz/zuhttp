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

    kind = no_decode ? ZUH_ENC_IDENTITY
                     : zuh_encoding_parse(zuh_headers_get(h, "Content-Encoding"));
    if (kind == ZUH_ENC_IDENTITY) return ZUH_OK;
    if (kind == ZUH_ENC_UNSUPPORTED) {
        zuh_error_set(err, ZUH_ERR_BODY_DECODE, ZUH_PHASE_DECODE,
                     "unsupported Content-Encoding: %s",
                     zuh_headers_get(h, "Content-Encoding"));
        return ZUH_ERR_BODY_DECODE;
    }
    if (zuh_inflate_init(&p->inflate, kind, max_body, 0) != ZUH_OK)
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
static zuh_code pipe_finish(zuh_body_pipe *p, zuh_error *err) {
    zuh_code rc;
    if (!p->inflating) return ZUH_OK;
    p->staging.len = 0;
    rc = zuh_inflate_run(&p->inflate, NULL, 0, &p->staging, err);
    if (rc != ZUH_OK) return rc;
    return p->staging.len
        ? zuh_sink_write(p->sink, p->staging.data, p->staging.len, err) : ZUH_OK;
}

static zuh_code body_read_framed(zuh_stream *s, const zuh_framing *fr, zuh_body_pipe *p,
                                const char *seed, size_t seed_len,
                                uint64_t max_body, zuh_deadline dl, zuh_error *err);

zuh_code zuh_body_read(zuh_stream *s, const zuh_framing *fr, zuh_body_pipe *p,
                         const char *seed, size_t seed_len,
                         uint64_t max_body, zuh_deadline dl, zuh_error *err) {
    zuh_code rc = body_read_framed(s, fr, p, seed, seed_len, max_body, dl, err);
    return rc == ZUH_OK ? pipe_finish(p, err) : rc;
}

static zuh_code body_read_framed(zuh_stream *s, const zuh_framing *fr, zuh_body_pipe *p,
                                const char *seed, size_t seed_len,
                                uint64_t max_body, zuh_deadline dl, zuh_error *err) {
    if (fr->kind == ZUH_FRAME_NONE) {
        /* HEAD, 204, 304: no body, so anything already read is surplus. */
        p->surplus += (uint64_t)seed_len;
        return ZUH_OK;
    }

    if (fr->kind == ZUH_FRAME_CHUNKED) {
        zuh_chunked dec;
        char *work;
        zuh_code rc = zuh_chunked_init(&dec, 0, max_body);
        if (rc != ZUH_OK) return rc;

        work = (char *)zuh_alloc(ZUH_READ_CHUNK);
        if (!work) { zuh_chunked_free(&dec); return ZUH_ERR_NOMEM; }

        if (seed_len) {
            size_t len = seed_len;
            memcpy(work, seed, seed_len);
            /* WIRE bytes, before de-chunking: `len` comes back as the decoded
             * length, so counting that would report the body and call it the
             * wire. The difference is the chunk framing, which is exactly what
             * someone comparing the two numbers wants to see. */
            p->raw_seen += seed_len;
            rc = zuh_chunked_decode(&dec, work, &len, err);
            if (len) {
                zuh_code w = zuh_body_pipe_feed(p, work, len, err);
                if (w != ZUH_OK) rc = w;
            }
        } else {
            rc = ZUH_ERR_WOULDBLOCK;
        }
        while (rc == ZUH_ERR_WOULDBLOCK) {
            size_t len;
            zuh_ssize n = zuh_stream_read(s, work, ZUH_READ_CHUNK, dl, err);
            if (n < 0) { rc = err->code; break; }
            if (n == 0) {
                zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_READ,
                             "connection closed inside a chunked body");
                rc = ZUH_ERR_PARSE;
                break;
            }
            len = (size_t)n;
            p->raw_seen += (uint64_t)n;
            rc = zuh_chunked_decode(&dec, work, &len, err);
            if (len) {
                zuh_code w = zuh_body_pipe_feed(p, work, len, err);
                if (w != ZUH_OK) { rc = w; break; }
            }
        }
        if (rc == ZUH_OK) p->surplus += (uint64_t)dec.surplus;
        zuh_free(work);
        zuh_chunked_free(&dec);
        return rc == ZUH_OK ? ZUH_OK : rc;
    }

    /* LENGTH and UNTIL_CLOSE differ only in when they stop. */
    if (seed_len) {
        size_t take = seed_len;
        /* Anything past Content-Length is the next response on this
         * connection, not this body. Trimming here rather than truncating a
         * buffer afterwards is what lets the body go straight to a sink. */
        if (fr->kind == ZUH_FRAME_LENGTH && take > fr->length)
            take = (size_t)fr->length;
        p->surplus += (uint64_t)(seed_len - take);
        {
            zuh_code w = zuh_body_pipe_feed(p, seed, take, err);
            if (w != ZUH_OK) return w;
        }
        p->raw_seen += take;
    }
    for (;;) {
        char chunk[ZUH_READ_CHUNK];
        zuh_ssize n;
        size_t take;

        if (fr->kind == ZUH_FRAME_LENGTH && p->raw_seen >= fr->length) break;
        /* No cap check here any more. It used to live at exactly this point,
         * AFTER a chunk had already reached the sink, which made max_body
         * something noticed rather than a bound enforced. zuh_body_pipe_feed()
         * refuses before writing, so reaching this line means the cap still
         * holds. §27.1's rule that the cap covers every sink, file included,
         * is satisfied there — where every sink's bytes pass.
         */
        n = zuh_stream_read(s, chunk, sizeof chunk, dl, err);
        if (n < 0) return err->code;
        if (n == 0) {
            if (fr->kind == ZUH_FRAME_UNTIL_CLOSE) break;
            zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_READ,
                         "connection closed with %lu of %lu body bytes read",
                         (unsigned long)p->raw_seen, (unsigned long)fr->length);
            return ZUH_ERR_PARSE;
        }
        take = (size_t)n;
        if (fr->kind == ZUH_FRAME_LENGTH && p->raw_seen + take > fr->length)
            take = (size_t)(fr->length - p->raw_seen);
        p->surplus += (uint64_t)((size_t)n - take);
        {
            zuh_code w = zuh_body_pipe_feed(p, chunk, take, err);
            if (w != ZUH_OK) return w;
        }
        p->raw_seen += take;
    }
    return ZUH_OK;
}

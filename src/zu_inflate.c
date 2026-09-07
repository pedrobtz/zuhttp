#include "zu_inflate.h"
#include "zu_alloc.h"
#include "zu_headers.h"    /* zu_ascii_casecmp */
#include "zu_framing.h"    /* zu_trim_ows */
#include <string.h>
#include <zlib.h>

zu_encoding zu_encoding_parse(const char *ce) {
    const char *s;
    size_t len;
    if (!ce || !*ce) return ZU_ENC_IDENTITY;
    s = ce; len = strlen(ce);
    zu_trim_ows(&s, &len);
    if (len == 0) return ZU_ENC_IDENTITY;
    if (zu_ascii_ncasecmp(s, len, "identity", 8) == 0) return ZU_ENC_IDENTITY;
    if (zu_ascii_ncasecmp(s, len, "gzip", 4) == 0)     return ZU_ENC_GZIP;
    if (zu_ascii_ncasecmp(s, len, "x-gzip", 6) == 0)   return ZU_ENC_GZIP;
    if (zu_ascii_ncasecmp(s, len, "deflate", 7) == 0)  return ZU_ENC_DEFLATE;
    /* A list such as "gzip, br" is not something this client unwinds. */
    return ZU_ENC_UNSUPPORTED;
}

zu_code zu_inflate_init(zu_inflate *z, zu_encoding enc,
                        uint64_t max_out, unsigned max_ratio) {
    if (!z) return ZU_ERR_PARSE;
    memset(z, 0, sizeof *z);
    z->enc = enc;
    z->max_out = max_out;
    z->max_ratio = max_ratio;

    if (enc == ZU_ENC_IDENTITY) return ZU_OK;
    if (enc != ZU_ENC_GZIP && enc != ZU_ENC_DEFLATE) return ZU_ERR_BODY_DECODE;

    z->strm = zu_calloc(1, sizeof(z_stream));
    if (!z->strm) return ZU_ERR_NOMEM;

    if (enc == ZU_ENC_GZIP) {
        /* 15 + 16 accepts a gzip wrapper only; the server said gzip. */
        if (inflateInit2((z_stream *)z->strm, 15 + 16) != Z_OK) {
            zu_free(z->strm); z->strm = NULL;
            return ZU_ERR_BODY_DECODE;
        }
        z->started = 1;
        z->wrap_decided = 1;
    }
    /* DEFLATE defers init until two header bytes are seen (§21.3). */
    return ZU_OK;
}

void zu_inflate_free(zu_inflate *z) {
    if (!z) return;
    if (z->strm) {
        if (z->started) inflateEnd((z_stream *)z->strm);
        zu_free(z->strm);
        z->strm = NULL;
    }
    z->started = 0;
}

/* §21.3: servers disagree about `deflate`. Some send a zlib wrapper (RFC 1950,
 * correct), many send raw DEFLATE (RFC 1951). Decide from the first two bytes:
 * a zlib header has CM == 8 and (CMF<<8 | FLG) divisible by 31. */
static int looks_zlib_wrapped(const unsigned char *h) {
    if ((h[0] & 0x0f) != 8) return 0;
    return (((unsigned)h[0] << 8) | h[1]) % 31u == 0;
}

static zu_code start_deflate(zu_inflate *z) {
    int window = looks_zlib_wrapped(z->hdr) ? 15 : -15;
    if (inflateInit2((z_stream *)z->strm, window) != Z_OK)
        return ZU_ERR_BODY_DECODE;
    z->started = 1;
    z->wrap_decided = 1;
    return ZU_OK;
}

static zu_code check_limits(zu_inflate *z, zu_error *err) {
    if (z->max_out && z->out_total > z->max_out) {
        zu_error_set(err, ZU_ERR_BODY_LIMIT, ZU_PHASE_DECODE,
                     "decompressed body exceeds the configured limit");
        return ZU_ERR_BODY_LIMIT;
    }
    /* Ratio is checked incrementally so a bomb fails early. Only meaningful
     * once enough input has been seen for the ratio not to be noise. */
    if (z->max_ratio && z->in_total >= 32) {
        if (z->out_total / z->in_total > (uint64_t)z->max_ratio) {
            zu_error_set(err, ZU_ERR_BODY_LIMIT, ZU_PHASE_DECODE,
                         "decompression ratio %lu:1 exceeds the limit of %u:1",
                         (unsigned long)(z->out_total / z->in_total), z->max_ratio);
            return ZU_ERR_BODY_LIMIT;
        }
    }
    return ZU_OK;
}

zu_code zu_inflate_run(zu_inflate *z, const void *in, size_t in_len,
                       zu_buffer *out, zu_error *err) {
    z_stream *s;
    const unsigned char *p = (const unsigned char *)in;
    unsigned char chunk[16384];

    if (!z || !out) return ZU_ERR_PARSE;

    if (z->enc == ZU_ENC_IDENTITY) {
        if (in_len && !zu_buf_append(out, in, in_len)) return ZU_ERR_NOMEM;
        z->in_total += in_len;
        z->out_total += in_len;
        return check_limits(z, err);
    }
    if (z->finished) return ZU_OK;
    if (!z->strm) return ZU_ERR_BODY_DECODE;

    /* Hold back the first two bytes until the deflate wrapping is known. */
    if (!z->wrap_decided) {
        while (in_len > 0 && z->hdr_len < 2) {
            z->hdr[z->hdr_len++] = *p++;
            in_len--;
            z->in_total++;
        }
        if (z->hdr_len < 2) return ZU_ERR_WOULDBLOCK;   /* need more */
        {
            zu_code rc = start_deflate(z);
            if (rc != ZU_OK) {
                zu_error_set(err, rc, ZU_PHASE_DECODE, "cannot start deflate stream");
                return rc;
            }
        }
        /* Feed the held-back header bytes first. */
        s = (z_stream *)z->strm;
        s->next_in = z->hdr;
        s->avail_in = 2;
        for (;;) {
            int ret;
            s->next_out = chunk;
            s->avail_out = (uInt)sizeof chunk;
            ret = inflate(s, Z_NO_FLUSH);
            if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR) {
                zu_error_set(err, ZU_ERR_BODY_DECODE, ZU_PHASE_DECODE,
                             "malformed compressed data");
                return ZU_ERR_BODY_DECODE;
            }
            {
                size_t produced = sizeof chunk - s->avail_out;
                if (produced) {
                    if (!zu_buf_append(out, chunk, produced)) return ZU_ERR_NOMEM;
                    z->out_total += produced;
                    if (check_limits(z, err) != ZU_OK) return ZU_ERR_BODY_LIMIT;
                }
                if (ret == Z_STREAM_END) { z->finished = 1; return ZU_OK; }
                if (s->avail_in == 0 || produced == 0) break;
            }
        }
    }

    s = (z_stream *)z->strm;
    s->next_in = (Bytef *)(uintptr_t)p;
    s->avail_in = (uInt)in_len;
    z->in_total += in_len;

    for (;;) {
        int ret;
        size_t produced;
        s->next_out = chunk;
        s->avail_out = (uInt)sizeof chunk;
        ret = inflate(s, Z_NO_FLUSH);

        if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR) {
            zu_error_set(err, ZU_ERR_BODY_DECODE, ZU_PHASE_DECODE,
                         "malformed compressed data");
            return ZU_ERR_BODY_DECODE;
        }

        produced = sizeof chunk - s->avail_out;
        if (produced) {
            if (!zu_buf_append(out, chunk, produced)) return ZU_ERR_NOMEM;
            z->out_total += produced;
            if (check_limits(z, err) != ZU_OK) return ZU_ERR_BODY_LIMIT;
        }

        if (ret == Z_STREAM_END) { z->finished = 1; return ZU_OK; }
        if (s->avail_in == 0 && produced == 0) break;
        if (produced == 0 && ret == Z_BUF_ERROR) break;
    }
    return ZU_ERR_WOULDBLOCK;
}

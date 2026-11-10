#include "zuh_response.h"
#include "zuh_alloc.h"
#include "picohttpparser.h"
#include <string.h>

void zuh_response_init(zuh_response *r) {
    memset(r, 0, sizeof *r);
    zuh_headers_init(&r->headers);
}

void zuh_response_free(zuh_response *r) {
    if (!r) return;
    zuh_headers_free(&r->headers);
}

int zuh_response_is_informational(const zuh_response *r) {
    return r && r->status >= 100 && r->status <= 199;
}

zuh_code zuh_response_parse(zuh_response *r, const char *buf, size_t len,
                          size_t last_len, size_t *consumed, zuh_error *err) {
    /* Bounded by §40 max_header_count; picohttpparser needs the array sized
     * up front, which is exactly the limit we want to impose anyway. */
    struct phr_header hdrs[ZUH_DEFAULT_MAX_HEADER_COUNT];
    size_t num = sizeof hdrs / sizeof hdrs[0];
    const char *msg = NULL;
    size_t msg_len = 0;
    int minor = 0, status = 0, rc;
    size_t i;

    if (!r || !buf || !consumed) return ZUH_ERR_PARSE;
    *consumed = 0;

    if (r->headers.max_count && num > r->headers.max_count)
        num = r->headers.max_count;

    rc = phr_parse_response(buf, len, &minor, &status, &msg, &msg_len,
                            hdrs, &num, last_len);

    if (rc == -2) return ZUH_ERR_WOULDBLOCK;          /* incomplete */
    if (rc == -1) {
        /* Also the outcome when the header count exceeds the array, which is
         * the §40 limit doing its job. */
        zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_READ, "malformed response head");
        return ZUH_ERR_PARSE;
    }

    if (minor != 0 && minor != 1) {
        zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_READ,
                     "unsupported HTTP/1.%d response", minor);
        return ZUH_ERR_PARSE;
    }
    if (status < 100 || status > 599) {
        zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_READ,
                     "invalid status code %d", status);
        return ZUH_ERR_PARSE;
    }

    r->status = status;
    r->minor_version = minor;

    if (msg && msg_len) {
        size_t n = msg_len < ZUH_REASON_MAX - 1 ? msg_len : ZUH_REASON_MAX - 1;
        memcpy(r->reason, msg, n);
        r->reason[n] = '\0';
    } else {
        r->reason[0] = '\0';
    }

    /* Re-parsing after an interim 1xx reuses the struct; start clean. */
    zuh_headers_free(&r->headers);
    zuh_headers_init(&r->headers);

    for (i = 0; i < num; i++) {
        zuh_code hc;
        /* picohttpparser signals an obs-fold continuation line with a NULL
         * name. §18.1 rejects obs-fold outright rather than unfolding it. */
        if (hdrs[i].name == NULL) {
            zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_READ,
                         "obsolete line folding in response headers");
            return ZUH_ERR_PARSE;
        }
        /* Validating again here is deliberate defence in depth: the storage
         * layer enforces §17.1/§40 regardless of what the parser accepted. */
        hc = zuh_headers_add(&r->headers, hdrs[i].name, hdrs[i].name_len,
                            hdrs[i].value, hdrs[i].value_len);
        if (hc == ZUH_ERR_NOMEM) {
            zuh_error_set(err, hc, ZUH_PHASE_READ, "out of memory");
            return hc;
        }
        if (hc != ZUH_OK) {
            /* D-101: a header limit is a malformed response, as it is in
             * trailers and over HTTP/2, never zu_body_limit_error. */
            zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_READ,
                         hc == ZUH_ERR_BODY_LIMIT ? "response header limit exceeded"
                                                 : "invalid response header");
            return ZUH_ERR_PARSE;
        }
    }

    *consumed = (size_t)rc;
    return ZUH_OK;
}

zuh_code zuh_response_decide_framing(zuh_response *r, int method_is_head, zuh_error *err) {
    if (!r) return ZUH_ERR_PARSE;
    return zuh_framing_decide(&r->headers, r->status, method_is_head, &r->framing, err);
}

/* ---------------- chunked ---------------- */

zuh_code zuh_chunked_init(zuh_chunked *c) {
    struct phr_chunked_decoder *d;
    if (!c) return ZUH_ERR_PARSE;
    memset(c, 0, sizeof *c);
    d = (struct phr_chunked_decoder *)zuh_calloc(1, sizeof *d);
    if (!d) return ZUH_ERR_NOMEM;
    /* §18.2, D-91: the decoder stops after the last chunk, and the trailer
     * section is parsed here, as a header block of its own. */
    d->consume_trailer = 0;
    c->state = d;
    zuh_headers_init(&c->trailers);
    if (!zuh_buf_init(&c->tbuf, 0, ZUH_DEFAULT_MAX_HEADER_BYTES)) {
        zuh_free(d);
        c->state = NULL;
        return ZUH_ERR_NOMEM;
    }
    return ZUH_OK;
}

void zuh_chunked_free(zuh_chunked *c) {
    if (!c) return;
    zuh_free(c->state);
    c->state = NULL;
    zuh_buf_free(&c->tbuf);
    zuh_headers_free(&c->trailers);
}

/* The trailer section so far: complete, malformed, or still arriving. */
static zuh_code trailer_parse(zuh_chunked *c, zuh_error *err) {
    struct phr_header h[ZUH_DEFAULT_MAX_HEADER_COUNT];
    size_t n = ZUH_DEFAULT_MAX_HEADER_COUNT, i;
    int rc;
    /* Nothing after the last chunk yet: the buffer has not been allocated,
     * and picohttpparser does pointer arithmetic on what it is given (UBSan,
     * fuzz_engine, 2026-11-04). */
    if (c->tbuf.len == 0) return ZUH_ERR_WOULDBLOCK;
    /* tlast spares a 1-byte-a-read section the quadratic re-scan (§8.1).
     * picohttpparser's quick check looks for a blank line after the last
     * call's end, which an empty section ("\r\n" alone) never has, so the
     * first bytes are always parsed in full. */
    rc = phr_parse_headers((const char *)c->tbuf.data, c->tbuf.len, h, &n,
                           c->tlast > 3 ? c->tlast : 0);
    if (rc == -2) {
        /* tbuf holds at most the limit's bytes, so a section incomplete
         * when it is full is over the limit, however the reads split it. */
        if (c->tbuf.len >= ZUH_DEFAULT_MAX_HEADER_BYTES) {
            zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_READ,
                          "chunked trailer section exceeds the header size limit");
            return ZUH_ERR_PARSE;
        }
        c->tlast = c->tbuf.len;
        return ZUH_ERR_WOULDBLOCK;
    }
    if (rc < 0) {
        zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_READ, "malformed chunked trailer section");
        return ZUH_ERR_PARSE;
    }
    for (i = 0; i < n; i++) {
        zuh_code a;
        /* obs-fold continuation lines come back nameless; §18.3 refuses them
         * in headers, and trailers are no different. */
        if (!h[i].name) {
            zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_READ, "obsolete line folding in a trailer");
            return ZUH_ERR_PARSE;
        }
        a = zuh_headers_add(&c->trailers, h[i].name, h[i].name_len, h[i].value, h[i].value_len);
        if (a == ZUH_ERR_NOMEM) {
            zuh_error_set(err, ZUH_ERR_NOMEM, ZUH_PHASE_READ, "out of memory");
            return a;
        }
        if (a != ZUH_OK) {
            zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_READ,
                          "chunked trailer field is invalid or over a limit");
            return ZUH_ERR_PARSE;
        }
    }
    c->surplus = c->tbuf.len - (size_t)rc + c->tover;
    return ZUH_OK;
}

/* §40, D-101: bytes after the last chunk. Only the first max_header_bytes
 * are buffered and parsed, as for a head (#258): the section completes
 * within them or is too large, and what lies past them is only counted, so
 * the outcome never depends on how the bytes arrived. */
static zuh_code trailer_feed(zuh_chunked *c, const char *buf, size_t n, zuh_error *err) {
    size_t room = c->tbuf.len < ZUH_DEFAULT_MAX_HEADER_BYTES
                  ? ZUH_DEFAULT_MAX_HEADER_BYTES - c->tbuf.len : 0;
    size_t take = n < room ? n : room;
    if (take && !zuh_buf_append(&c->tbuf, buf, take)) {
        zuh_error_set(err, ZUH_ERR_NOMEM, ZUH_PHASE_READ, "out of memory");
        return ZUH_ERR_NOMEM;
    }
    c->tover += n - take;
    return trailer_parse(c, err);
}

zuh_code zuh_chunked_decode(zuh_chunked *c, char *buf, size_t *len, zuh_error *err) {
    struct phr_chunked_decoder *d;
    size_t n;
    ssize_t rc;

    if (!c || !c->state || !buf || !len) return ZUH_ERR_PARSE;
    d = (struct phr_chunked_decoder *)c->state;
    n = *len;
    if (c->in_trailer) {
        /* Past the last chunk: everything is trailer section or surplus. */
        *len = 0;
        return trailer_feed(c, buf, n, err);
    }

    rc = phr_decode_chunked(d, buf, &n);

    if (rc == -1) {
        /* #210: `n` was not updated, so leaving *len alone would report the
         * wire length as decoded output. After an error nothing is valid. */
        *len = 0;
        zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_READ, "malformed chunked encoding");
        return ZUH_ERR_PARSE;
    }

    /* Decoded bytes now at the front of buf. They are not bounded here:
     * the body pipe bounds what reaches the sink, after any inflation
     * (§40, #212). */
    *len = n;

    if (rc >= 0) {                      /* final chunk seen */
        /* consume_trailer is off, so the rc bytes after the decoded data
         * are the trailer section and whatever follows the message. */
        c->in_trailer = 1;
        {
            zuh_code t = trailer_feed(c, buf + n, (size_t)rc, err);
            if (t != ZUH_OK && t != ZUH_ERR_WOULDBLOCK) *len = 0;
            return t;
        }
    }
    return ZUH_ERR_WOULDBLOCK;           /* rc == -2: need more input */
}

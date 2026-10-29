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
        if (hc != ZUH_OK) {
            zuh_error_set(err, hc, ZUH_PHASE_READ,
                         hc == ZUH_ERR_BODY_LIMIT ? "response header limit exceeded"
                                                 : "invalid response header");
            return hc;
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

zuh_code zuh_chunked_init(zuh_chunked *c, uint64_t max_chunk, uint64_t max_total) {
    struct phr_chunked_decoder *d;
    if (!c) return ZUH_ERR_PARSE;
    memset(c, 0, sizeof *c);
    d = (struct phr_chunked_decoder *)zuh_calloc(1, sizeof *d);
    if (!d) return ZUH_ERR_NOMEM;
    d->consume_trailer = 1;    /* §18.2: parse trailers, then discard them */
    c->state = d;
    c->max_chunk = max_chunk;
    c->max_total = max_total;
    return ZUH_OK;
}

void zuh_chunked_free(zuh_chunked *c) {
    if (!c) return;
    zuh_free(c->state);
    c->state = NULL;
}

zuh_code zuh_chunked_decode(zuh_chunked *c, char *buf, size_t *len, zuh_error *err) {
    struct phr_chunked_decoder *d;
    size_t n;
    ssize_t rc;

    if (!c || !c->state || !buf || !len) return ZUH_ERR_PARSE;
    d = (struct phr_chunked_decoder *)c->state;
    n = *len;

    rc = phr_decode_chunked(d, buf, &n);

    if (rc == -1) {
        zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_READ, "malformed chunked encoding");
        return ZUH_ERR_PARSE;
    }

    *len = n;   /* decoded bytes now at the front of buf */

    /* §40: bound the decoded total. phr_decode_chunked itself has no limit,
     * so an unbounded chunked body would otherwise grow without end.
     *
     * Compute the remaining budget rather than `total > max_total - n`: that
     * form underflows when n exceeds the budget, wrapping to a huge value and
     * silently DISABLING the limit. This is precisely the unsigned-overflow
     * class §40 exists to prevent, and it shipped here until a test caught it. */
    if (c->max_total) {
        uint64_t remaining = c->max_total >= c->total ? c->max_total - c->total : 0;
        if ((uint64_t)n > remaining) {
            zuh_error_set(err, ZUH_ERR_BODY_LIMIT, ZUH_PHASE_READ,
                         "response body exceeds the configured limit");
            return ZUH_ERR_BODY_LIMIT;
        }
    }
    c->total += (uint64_t)n;

    /* A single chunk larger than max_chunk is rejected. bytes_left_in_chunk
     * is the decoder's view of the current chunk's remaining size. */
    if (c->max_chunk && d->bytes_left_in_chunk > c->max_chunk) {
        zuh_error_set(err, ZUH_ERR_BODY_LIMIT, ZUH_PHASE_READ,
                     "chunk size exceeds the configured limit");
        return ZUH_ERR_BODY_LIMIT;
    }

    if (rc >= 0) {                      /* final chunk seen */
        /* consume_trailer is set, so rc counts only what follows the whole
         * message — never part of this body. */
        c->surplus = (size_t)rc;
        return ZUH_OK;
    }
    return ZUH_ERR_WOULDBLOCK;           /* rc == -2: need more input */
}

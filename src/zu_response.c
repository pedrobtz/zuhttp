#include "zu_response.h"
#include "zu_alloc.h"
#include "picohttpparser.h"
#include <string.h>

void zu_response_init(zu_response *r) {
    memset(r, 0, sizeof *r);
    zu_headers_init(&r->headers);
}

void zu_response_free(zu_response *r) {
    if (!r) return;
    zu_headers_free(&r->headers);
}

int zu_response_is_informational(const zu_response *r) {
    return r && r->status >= 100 && r->status <= 199;
}

zu_code zu_response_parse(zu_response *r, const char *buf, size_t len,
                          size_t last_len, size_t *consumed, zu_error *err) {
    /* Bounded by §40 max_header_count; picohttpparser needs the array sized
     * up front, which is exactly the limit we want to impose anyway. */
    struct phr_header hdrs[ZU_DEFAULT_MAX_HEADER_COUNT];
    size_t num = sizeof hdrs / sizeof hdrs[0];
    const char *msg = NULL;
    size_t msg_len = 0;
    int minor = 0, status = 0, rc;
    size_t i;

    if (!r || !buf || !consumed) return ZU_ERR_PARSE;
    *consumed = 0;

    if (r->headers.max_count && num > r->headers.max_count)
        num = r->headers.max_count;

    rc = phr_parse_response(buf, len, &minor, &status, &msg, &msg_len,
                            hdrs, &num, last_len);

    if (rc == -2) return ZU_ERR_WOULDBLOCK;          /* incomplete */
    if (rc == -1) {
        /* Also the outcome when the header count exceeds the array, which is
         * the §40 limit doing its job. */
        zu_error_set(err, ZU_ERR_PARSE, ZU_PHASE_READ, "malformed response head");
        return ZU_ERR_PARSE;
    }

    if (minor != 0 && minor != 1) {
        zu_error_set(err, ZU_ERR_PARSE, ZU_PHASE_READ,
                     "unsupported HTTP/1.%d response", minor);
        return ZU_ERR_PARSE;
    }
    if (status < 100 || status > 599) {
        zu_error_set(err, ZU_ERR_PARSE, ZU_PHASE_READ,
                     "invalid status code %d", status);
        return ZU_ERR_PARSE;
    }

    r->status = status;
    r->minor_version = minor;

    if (msg && msg_len) {
        size_t n = msg_len < ZU_REASON_MAX - 1 ? msg_len : ZU_REASON_MAX - 1;
        memcpy(r->reason, msg, n);
        r->reason[n] = '\0';
    } else {
        r->reason[0] = '\0';
    }

    /* Re-parsing after an interim 1xx reuses the struct; start clean. */
    zu_headers_free(&r->headers);
    zu_headers_init(&r->headers);

    for (i = 0; i < num; i++) {
        zu_code hc;
        /* picohttpparser signals an obs-fold continuation line with a NULL
         * name. §18.1 rejects obs-fold outright rather than unfolding it. */
        if (hdrs[i].name == NULL) {
            zu_error_set(err, ZU_ERR_PARSE, ZU_PHASE_READ,
                         "obsolete line folding in response headers");
            return ZU_ERR_PARSE;
        }
        /* Validating again here is deliberate defence in depth: the storage
         * layer enforces §17.1/§40 regardless of what the parser accepted. */
        hc = zu_headers_add(&r->headers, hdrs[i].name, hdrs[i].name_len,
                            hdrs[i].value, hdrs[i].value_len);
        if (hc != ZU_OK) {
            zu_error_set(err, hc, ZU_PHASE_READ,
                         hc == ZU_ERR_BODY_LIMIT ? "response header limit exceeded"
                                                 : "invalid response header");
            return hc;
        }
    }

    *consumed = (size_t)rc;
    return ZU_OK;
}

zu_code zu_response_decide_framing(zu_response *r, int method_is_head, zu_error *err) {
    if (!r) return ZU_ERR_PARSE;
    return zu_framing_decide(&r->headers, r->status, method_is_head, &r->framing, err);
}

/* ---------------- chunked ---------------- */

zu_code zu_chunked_init(zu_chunked *c, uint64_t max_chunk, uint64_t max_total) {
    struct phr_chunked_decoder *d;
    if (!c) return ZU_ERR_PARSE;
    memset(c, 0, sizeof *c);
    d = (struct phr_chunked_decoder *)zu_calloc(1, sizeof *d);
    if (!d) return ZU_ERR_NOMEM;
    d->consume_trailer = 1;    /* §18.2: parse trailers, then discard them */
    c->state = d;
    c->max_chunk = max_chunk;
    c->max_total = max_total;
    return ZU_OK;
}

void zu_chunked_free(zu_chunked *c) {
    if (!c) return;
    zu_free(c->state);
    c->state = NULL;
}

zu_code zu_chunked_decode(zu_chunked *c, char *buf, size_t *len, zu_error *err) {
    struct phr_chunked_decoder *d;
    size_t n;
    ssize_t rc;

    if (!c || !c->state || !buf || !len) return ZU_ERR_PARSE;
    d = (struct phr_chunked_decoder *)c->state;
    n = *len;

    rc = phr_decode_chunked(d, buf, &n);

    if (rc == -1) {
        zu_error_set(err, ZU_ERR_PARSE, ZU_PHASE_READ, "malformed chunked encoding");
        return ZU_ERR_PARSE;
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
            zu_error_set(err, ZU_ERR_BODY_LIMIT, ZU_PHASE_READ,
                         "response body exceeds the configured limit");
            return ZU_ERR_BODY_LIMIT;
        }
    }
    c->total += (uint64_t)n;

    /* A single chunk larger than max_chunk is rejected. bytes_left_in_chunk
     * is the decoder's view of the current chunk's remaining size. */
    if (c->max_chunk && d->bytes_left_in_chunk > c->max_chunk) {
        zu_error_set(err, ZU_ERR_BODY_LIMIT, ZU_PHASE_READ,
                     "chunk size exceeds the configured limit");
        return ZU_ERR_BODY_LIMIT;
    }

    if (rc >= 0) return ZU_OK;          /* final chunk seen */
    return ZU_ERR_WOULDBLOCK;           /* rc == -2: need more input */
}

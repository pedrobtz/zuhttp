#include "zuh_framing.h"
#include <string.h>

void zuh_trim_ows(const char **s, size_t *len) {
    const char *p = *s;
    size_t n = *len;
    while (n > 0 && (p[0] == ' ' || p[0] == '\t')) { p++; n--; }
    while (n > 0 && (p[n - 1] == ' ' || p[n - 1] == '\t')) n--;
    *s = p; *len = n;
}

int zuh_parse_u64_strict(const char *s, size_t len, uint64_t *out) {
    uint64_t v = 0;
    size_t i;
    if (!s || len == 0) return 0;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < '0' || c > '9') return 0;          /* no sign, no space, no hex */
        if (v > (UINT64_MAX - (uint64_t)(c - '0')) / 10u) return 0;   /* overflow */
        v = v * 10u + (uint64_t)(c - '0');
    }
    *out = v;
    return 1;
}

/* A status that can never carry a body, whatever the headers claim. */
static int status_bodyless(int status) {
    if (status >= 100 && status <= 199) return 1;   /* informational */
    if (status == 204 || status == 304) return 1;
    return 0;
}

zuh_code zuh_framing_decide(const zuh_headers *h, int status, int method_is_head,
                          zuh_framing *out, zuh_error *err) {
    size_t n_cl, n_te;
    const char *cl, *te;

    if (!h || !out) return ZUH_ERR_PARSE;
    out->kind = ZUH_FRAME_NONE;
    out->length = 0;
    out->poolable = 1;

    if (status < 100 || status > 599) {
        zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_READ,
                     "invalid response status %d", status);
        return ZUH_ERR_PARSE;
    }

    n_cl = zuh_headers_count(h, "Content-Length");
    n_te = zuh_headers_count(h, "Transfer-Encoding");

    /* Rule 1: CL and TE together is the classic smuggling vector. Reject
     * outright; do NOT prefer one over the other (§18.1). */
    if (n_cl > 0 && n_te > 0) {
        zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_READ,
                     "response has both Content-Length and Transfer-Encoding");
        return ZUH_ERR_PARSE;
    }

    /* Rule 2: repeated Content-Length is rejected even when the values agree.
     * Permissiveness here buys a client nothing. */
    if (n_cl > 1) {
        zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_READ,
                     "response has %lu Content-Length headers",
                     (unsigned long)n_cl);
        return ZUH_ERR_PARSE;
    }
    if (n_te > 1) {
        zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_READ,
                     "response has %lu Transfer-Encoding headers",
                     (unsigned long)n_te);
        return ZUH_ERR_PARSE;
    }

    /* Framing headers are still validated on bodyless responses: a 204 that
     * carries "Content-Length: 5, 5" is a broken or hostile peer either way.
     * Only after validating do we conclude there is no body. */
    if (n_te == 1) {
        size_t len;
        te = zuh_headers_get(h, "Transfer-Encoding");
        len = strlen(te);
        zuh_trim_ows(&te, &len);
        /* Rule 3: the only transfer coding this client accepts is `chunked`,
         * alone. A list such as "gzip, chunked" is rejected rather than
         * partially honoured, and "Transfer-Encoding: gzip" is rejected here
         * rather than in the decompressor (§21.4). */
        if (zuh_ascii_ncasecmp(te, len, "chunked", 7) != 0) {
            zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_READ,
                         "unsupported Transfer-Encoding");
            return ZUH_ERR_PARSE;
        }
    }

    if (n_cl == 1) {
        uint64_t v;
        size_t len;
        cl = zuh_headers_get(h, "Content-Length");
        len = strlen(cl);
        zuh_trim_ows(&cl, &len);
        /* Rule 4: a strict decimal only. This rejects "5, 5", "+5", "0x5",
         * " 5 5", the empty value, and anything that overflows uint64. */
        if (!zuh_parse_u64_strict(cl, len, &v)) {
            zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_READ,
                         "malformed Content-Length");
            return ZUH_ERR_PARSE;
        }
        out->length = v;
    }

    /* Only now may we short-circuit on "this response cannot have a body". */
    if (method_is_head || status_bodyless(status)) {
        out->kind = ZUH_FRAME_NONE;
        out->length = 0;
        out->poolable = 1;
        return ZUH_OK;
    }

    if (n_te == 1) {
        out->kind = ZUH_FRAME_CHUNKED;
        out->poolable = 1;
        return ZUH_OK;
    }
    if (n_cl == 1) {
        out->kind = ZUH_FRAME_LENGTH;
        out->poolable = 1;
        return ZUH_OK;
    }

    /* Rule 5: no framing information. The body ends at EOF, so the connection
     * carries no way to find the next response and must not be pooled (§26.3). */
    out->kind = ZUH_FRAME_UNTIL_CLOSE;
    out->poolable = 0;
    return ZUH_OK;
}

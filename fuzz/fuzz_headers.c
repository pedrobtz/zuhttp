/* Target 3 — header normalisation and validation (§17.1, §18.3, §43).
 *
 * Splits NAME\0VALUE so both validators see attacker-controlled bytes,
 * including embedded CR, LF and NUL, the request-splitting alphabet. A
 * validator that lets a CR through crashes nothing; it writes a second
 * header line into the request. So the target compares (#239):
 *
 *   - GRAMMAR. zuh_header_name_valid() against RFC 9110's token, and
 *     zuh_header_value_valid() against the field-value octets, both written
 *     out again in http_grammar.h; zuh_headers_add() against them and the
 *     §40 name and value limits.
 *   - WIRE. An accepted field is stored as given, found by its name in any
 *     case, kept twice when added twice, and written by zuh_headers_write()
 *     as exactly `name: value` CRLF: one line, whatever the value held.
 *   - ROUND TRIP. That line, parsed back as a response header by
 *     zuh_response_parse(), is the same field, its value less the OWS at
 *     either end that every recipient strips (RFC 9112 §5.1).
 */
#include "zuh_headers.h"
#include "zuh_response.h"
#include "zuh_buffer.h"
#include "zuh_alloc.h"
#include "http_grammar.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int same(const char *s, const uint8_t *p, size_t n) {
    return s && strlen(s) == n && (n == 0 || memcmp(s, p, n) == 0);
}

/* What a recipient makes of the line zuh_headers_write() produced. */
static void round_trip(const zuh_buffer *line, const uint8_t *name, size_t nlen,
                       const uint8_t *value, size_t vlen) {
    static const char status[] = "HTTP/1.1 200 OK\r\n";
    zuh_buffer w;
    zuh_response r;
    zuh_error e;
    size_t consumed = 0;
    const char *n, *v;
    zuh_code rc;
    if (!zuh_buf_init(&w, 0, (size_t)-1)) return;
    if (!zuh_buf_append(&w, status, sizeof status - 1) ||
        !zuh_buf_append(&w, line->data, line->len) || !zuh_buf_append(&w, "\r\n", 2)) {
        zuh_buf_free(&w);
        return;
    }
    while (vlen && g_ws(value[0])) { value++; vlen--; }
    while (vlen && g_ws(value[vlen - 1])) vlen--;
    zuh_response_init(&r);
    rc = zuh_response_parse(&r, (const char *)w.data, w.len, 0, &consumed, &e);
    if (rc != ZUH_ERR_NOMEM) {
        G_CHECK(rc == ZUH_OK && consumed == w.len);
        G_CHECK(zuh_headers_total(&r.headers) == 1 && zuh_headers_at(&r.headers, 0, &n, &v));
        G_CHECK(same(n, name, nlen) && same(v, value, vlen));
    }
    zuh_response_free(&r);
    zuh_buf_free(&w);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    zuh_headers h;
    zuh_buffer out;
    const uint8_t *sep, *name = data, *value;
    size_t nlen, vlen, i;
    int name_ok, value_ok;
    zuh_code rc, want;
    char *flip;

    if (size < 1 || size > 16 * 1024) return 0;

    sep = (const uint8_t *)memchr(data, 0, size);
    nlen = sep ? (size_t)(sep - data) : size;
    vlen = sep ? size - nlen - 1 : 0;
    value = sep ? sep + 1 : data;

    /* Grammar. */
    name_ok = zuh_header_name_valid((const char *)name, nlen);
    value_ok = zuh_header_value_valid((const char *)value, vlen);
    G_CHECK(name_ok == g_token(name, nlen));
    G_CHECK(value_ok == g_value_octets(value, vlen));
    want = !name_ok || !value_ok ? ZUH_ERR_PARSE
         : nlen > G_MAX_NAME || vlen > G_MAX_VALUE ? ZUH_ERR_BODY_LIMIT : ZUH_OK;

    zuh_headers_init(&h);
    rc = zuh_headers_add(&h, (const char *)name, nlen, (const char *)value, vlen);
    if (rc == ZUH_ERR_NOMEM) { zuh_headers_free(&h); return 0; }
    G_CHECK(rc == want);
    if (rc != ZUH_OK) {
        G_CHECK(zuh_headers_total(&h) == 0);
        zuh_headers_free(&h);
        return 0;
    }

    /* Wire: stored as given, found in any case, kept when repeated. */
    {
        const char *n, *v;
        G_CHECK(zuh_headers_total(&h) == 1 && zuh_headers_at(&h, 0, &n, &v));
        G_CHECK(same(n, name, nlen) && same(v, value, vlen));
    }
    flip = (char *)malloc(nlen + 1);
    if (flip) {
        for (i = 0; i < nlen; i++) {
            unsigned char c = name[i];
            flip[i] = (char)(c >= 'a' && c <= 'z' ? c - 32 : c >= 'A' && c <= 'Z' ? c + 32 : c);
        }
        flip[nlen] = '\0';
        G_CHECK(zuh_headers_count(&h, flip) == 1 && zuh_headers_has(&h, flip));
        G_CHECK(same(zuh_headers_get(&h, flip), value, vlen));
    }
    (void)zuh_headers_count(&h, "content-length");
    (void)zuh_headers_get(&h, "transfer-encoding");

    if (zuh_buf_init(&out, 64, 1u << 20)) {
        if (zuh_headers_write(&h, &out)) {
            /* `name: value` CRLF, and the CRLF is the only line end. */
            G_CHECK(out.len == nlen + 2 + vlen + 2);
            G_CHECK(memcmp(out.data, name, nlen) == 0 && memcmp(out.data + nlen, ": ", 2) == 0);
            G_CHECK(vlen == 0 || memcmp(out.data + nlen + 2, value, vlen) == 0);
            G_CHECK(memcmp(out.data + out.len - 2, "\r\n", 2) == 0);
            for (i = 0; i + 2 < out.len; i++) {
                unsigned char c = ((const unsigned char *)out.data)[i];
                G_CHECK(c != '\r' && c != '\n' && c != '\0');
            }
            round_trip(&out, name, nlen, value, vlen);
        }
        zuh_buf_free(&out);
    }

    if (flip && zuh_headers_add(&h, flip, nlen, (const char *)value, vlen) == ZUH_OK) {
        G_CHECK(zuh_headers_count(&h, (const char *)flip) == 2);
        G_CHECK(same(zuh_headers_get_at(&h, flip, 1), value, vlen));
        G_CHECK(zuh_headers_remove(&h, flip) == 2 && zuh_headers_total(&h) == 0);
    }
    free(flip);
    zuh_headers_free(&h);
    return 0;
}

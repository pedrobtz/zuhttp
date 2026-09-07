/* Target 3 — header normalisation and validation (§18.3, §43).
 *
 * Splits NAME\0VALUE so both validators see attacker-controlled bytes,
 * including embedded CR, LF and NUL — the request-splitting alphabet. */
#include "zu_headers.h"
#include "zu_buffer.h"
#include "zu_alloc.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    zu_headers h;
    zu_buffer out;
    const uint8_t *sep;
    size_t nlen, vlen;

    if (size < 1 || size > 16 * 1024) return 0;

    sep = (const uint8_t *)memchr(data, 0, size);
    nlen = sep ? (size_t)(sep - data) : size;
    vlen = sep ? size - nlen - 1 : 0;

    (void)zu_header_name_valid((const char *)data, nlen);
    (void)zu_header_value_valid((const char *)(sep ? sep + 1 : data), vlen);

    zu_headers_init(&h);
    if (zu_headers_add(&h, (const char *)data, nlen,
                       (const char *)(sep ? sep + 1 : data), vlen) == ZU_OK) {
        /* Only reached for headers we accepted, which is exactly the set that
         * must survive being counted, fetched and re-serialised. */
        (void)zu_headers_count(&h, "content-length");
        (void)zu_headers_get(&h, "transfer-encoding");
        (void)zu_headers_has(&h, "connection");
        if (zu_buf_init(&out, 64, 1u << 20)) {
            (void)zu_headers_write(&h, &out);
            zu_buf_free(&out);
        }
    }
    zu_headers_free(&h);
    return 0;
}

/* Target 3 — header normalisation and validation (§18.3, §43).
 *
 * Splits NAME\0VALUE so both validators see attacker-controlled bytes,
 * including embedded CR, LF and NUL — the request-splitting alphabet. */
#include "zuh_headers.h"
#include "zuh_buffer.h"
#include "zuh_alloc.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    zuh_headers h;
    zuh_buffer out;
    const uint8_t *sep;
    size_t nlen, vlen;

    if (size < 1 || size > 16 * 1024) return 0;

    sep = (const uint8_t *)memchr(data, 0, size);
    nlen = sep ? (size_t)(sep - data) : size;
    vlen = sep ? size - nlen - 1 : 0;

    (void)zuh_header_name_valid((const char *)data, nlen);
    (void)zuh_header_value_valid((const char *)(sep ? sep + 1 : data), vlen);

    zuh_headers_init(&h);
    if (zuh_headers_add(&h, (const char *)data, nlen,
                       (const char *)(sep ? sep + 1 : data), vlen) == ZUH_OK) {
        /* Only reached for headers we accepted, which is exactly the set that
         * must survive being counted, fetched and re-serialised. */
        (void)zuh_headers_count(&h, "content-length");
        (void)zuh_headers_get(&h, "transfer-encoding");
        (void)zuh_headers_has(&h, "connection");
        if (zuh_buf_init(&out, 64, 1u << 20)) {
            (void)zuh_headers_write(&h, &out);
            zuh_buf_free(&out);
        }
    }
    zuh_headers_free(&h);
    return 0;
}

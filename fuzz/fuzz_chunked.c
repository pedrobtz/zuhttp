/* Target 2 — chunked decoder (§18.2, §43).
 *
 * Splits the input at a byte the fuzzer chooses, so arbitrary chunk-boundary
 * fragmentation is reachable. Decoding is in place, so an overrun shows up as
 * a heap-buffer-overflow rather than as silently wrong output. */
#include "zuh_response.h"
#include "zuh_alloc.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    zuh_chunked c;
    zuh_error e;
    unsigned char *buf;
    size_t split, len;

    if (size < 2 || size > 64 * 1024) return 0;
    split = data[0] % size;          /* first byte picks the fragmentation */
    data++; size--;

    if (zuh_chunked_init(&c, 1u << 20, 1u << 22) != ZUH_OK) return 0;

    buf = (unsigned char *)malloc(size ? size : 1);
    if (!buf) { zuh_chunked_free(&c); return 0; }

    if (split > 0 && split <= size) {
        memcpy(buf, data, split);
        len = split;
        if (zuh_chunked_decode(&c, (char *)buf, &len, &e) == ZUH_ERR_WOULDBLOCK) {
            memcpy(buf, data + split, size - split);
            len = size - split;
            (void)zuh_chunked_decode(&c, (char *)buf, &len, &e);
        }
    } else {
        memcpy(buf, data, size);
        len = size;
        (void)zuh_chunked_decode(&c, (char *)buf, &len, &e);
    }
    free(buf);
    zuh_chunked_free(&c);
    return 0;
}

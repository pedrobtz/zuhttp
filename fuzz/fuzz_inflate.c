/* Target 6 — decompression limits (§21.4, §43).
 *
 * The limits are the point. A decompression bomb must be stopped DURING
 * inflation, not after, so the caps here are small and the assertion is that
 * the output buffer never exceeds them regardless of input. */
#include "zuh_inflate.h"
#include "zuh_buffer.h"
#include "zuh_alloc.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define MAX_OUT   (1u << 20)   /* 1 MB */
#define MAX_RATIO 100u

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void run_one(zuh_encoding enc, const uint8_t *data, size_t size) {
    zuh_inflate z;
    zuh_buffer out;
    zuh_error e;
    if (zuh_inflate_init(&z, enc, MAX_OUT, MAX_RATIO) != ZUH_OK) return;
    if (!zuh_buf_init(&out, 256, 8u << 20)) { zuh_inflate_free(&z); return; }
    (void)zuh_inflate_run(&z, data, size, &out, &e);
    /* §21.4: the cap is enforced during inflation, so it cannot be exceeded
     * even transiently. */
    if (z.out_total > MAX_OUT) abort();
    zuh_buf_free(&out);
    zuh_inflate_free(&z);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 || size > 1u << 20) return 0;
    /* First byte selects the coding, so one corpus covers all three. */
    switch (data[0] % 3) {
        case 0: run_one(ZUH_ENC_GZIP,    data + 1, size - 1); break;
        case 1: run_one(ZUH_ENC_DEFLATE, data + 1, size - 1); break;
        default: {
            /* Also fuzz the Content-Encoding field parser itself. */
            char *s = (char *)malloc(size);
            if (s) { memcpy(s, data + 1, size - 1); s[size - 1] = '\0';
                     (void)zuh_encoding_parse(s); free(s); }
            break;
        }
    }
    return 0;
}

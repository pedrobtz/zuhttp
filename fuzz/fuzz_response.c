/* Target 1 — response parser wrapper (design §43, §50.3).
 *
 * Drives the whole header-block path the way the engine does: incrementally,
 * with the last_len hint, then decide framing. A crash here is reachable from
 * any server on the internet. */
#include "zuh_response.h"
#include "zuh_alloc.h"
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    zuh_response r;
    zuh_error e;
    size_t consumed = 0, last = 0, i;
    if (size > 64 * 1024) return 0;

    zuh_response_init(&r);
    /* Feed it one byte at a time for small inputs so the incremental path and
     * the last_len hint are exercised, not just the one-shot parse. */
    if (size <= 512) {
        for (i = 1; i <= size; i++) {
            zuh_code rc = zuh_response_parse(&r, (const char *)data, i, last, &consumed, &e);
            last = i;
            if (rc != ZUH_ERR_WOULDBLOCK) break;
        }
    } else {
        (void)zuh_response_parse(&r, (const char *)data, size, 0, &consumed, &e);
    }
    (void)zuh_response_decide_framing(&r, 0, &e);
    (void)zuh_response_decide_framing(&r, 1, &e);   /* HEAD path too */
    (void)zuh_response_is_informational(&r);
    zuh_response_free(&r);
    return 0;
}

/* Target 4 — URL handling (§8.2, §43).
 *
 * This target is why §48 says vendored code must be fuzzed as project
 * surface: it drives the vendored uriparser subset AND the zuhttp policy
 * layer over it. Input is a byte range, never NUL-terminated, so a scan past
 * the end is a heap-buffer-overflow under ASan rather than a silent overread.
 */
#include "zu_uri.h"
#include "zu_alloc.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    zu_uri u;
    char origin[512];
    unsigned char *exact;

    if (size > 16 * 1024) return 0;

    /* An exact-size heap allocation: any read at data+size is caught. */
    exact = (unsigned char *)malloc(size ? size : 1);
    if (!exact) return 0;
    if (size) memcpy(exact, data, size);

    if (zu_uri_parse(&u, (const char *)exact, (const char *)exact + size) == ZU_OK) {
        zu_uri copy;
        /* Invariants the rest of the engine relies on (§8.2). */
        if (!u.scheme || !u.host || !u.path_query) abort();
        if (u.path_query[0] != '/') abort();
        if (u.port == 0) abort();
        if (strchr(u.host, '\0') != u.host + strlen(u.host)) abort();

        /* §42: an origin string must never carry credentials. Testing for
         * the userinfo as a SUBSTRING is wrong and libFuzzer proved it in
         * seconds with "http://h@oocd.com:/" — userinfo "h" occurs in
         * "http://oocd.com" inside the scheme. The precise invariant is that
         * scheme://host[:port] can never legitimately contain '@'. */
        if (zu_uri_origin_string(&u, origin, sizeof origin)) {
            if (strchr(origin, '@')) abort();
        }

        (void)zu_uri_same_origin(&u, &u);
        if (zu_uri_copy(&copy, &u)) {
            if (!zu_uri_same_origin(&copy, &u)) abort();   /* copy is the same origin */
            zu_uri_free(&copy);
        }
        zu_uri_free(&u);
    }
    free(exact);
    return 0;
}

/* Target 5 — redirect resolution (§19, §43).
 *
 * The security-relevant question is not "does it crash" but "can a Location
 * header move the request to a different origin while keeping credentials".
 * The assertions below encode §19.2, so a policy regression is a fuzz finding
 * and not merely a failed unit test. */
#include "zuh_uri.h"
#include "zuh_redirect.h"
#include "zuh_alloc.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const char k_base[] = "https://user:pw@example.com/a/b?q=1";
    zuh_uri base, out;
    unsigned char *exact;

    if (size > 8 * 1024) return 0;
    if (zuh_uri_parse(&base, k_base, k_base + sizeof k_base - 1) != ZUH_OK) return 0;

    exact = (unsigned char *)malloc(size ? size : 1);
    if (!exact) { zuh_uri_free(&base); return 0; }
    if (size) memcpy(exact, data, size);

    if (zuh_uri_resolve(&out, &base, (const char *)exact,
                       (const char *)exact + size) == ZUH_OK) {
        if (!out.scheme || !out.host || !out.path_query) abort();
        if (out.path_query[0] != '/') abort();
        /* §19.6: the result must never inherit the BASE's credentials.
         *
         * Not "must have no credentials": an absolute Location replaces the
         * whole authority (RFC 3986 §5.3), so a Location carrying its own
         * userinfo keeps it, and §19.2 then decides whether it may be used
         * cross-origin. The invariant that matters is provenance — anything
         * in out.userinfo must be present in the reference text. */
        if (out.userinfo && out.userinfo[0]) {
            size_t ul = strlen(out.userinfo), j;
            int found = 0;
            for (j = 0; ul <= size && j + ul <= size; j++)
                if (memcmp(exact + j, out.userinfo, ul) == 0) { found = 1; break; }
            if (!found) abort();   /* credentials appeared from nowhere */
        }
        (void)zuh_uri_same_origin(&out, &base);
        zuh_uri_free(&out);
    }
    free(exact);
    zuh_uri_free(&base);
    return 0;
}

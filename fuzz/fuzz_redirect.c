/* Target 5 — redirect resolution (§19, §43).
 *
 * The security-relevant question is not "does it crash" but "can a Location
 * header move the request to a different origin while keeping credentials".
 * The assertions below encode §19.2, so a policy regression is a fuzz finding
 * and not merely a failed unit test. */
#include "zuh_uri.h"
#include "zuh_redirect.h"
#include "zuh_headers.h"
#include "zuh_alloc.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* #230, #269: §19.2's rule, as the engine applies it. A cross-origin hop
 * drops each request field zuh_redirect_is_credential_header() names, one
 * field at a time (zuh_engine.c); the bulk strip this once called was used
 * by nothing else and is gone. The same input, read as "name: value" lines,
 * is the header set: field names are case-insensitive (RFC 9110 §5.1), so
 * the answer for a name may not depend on its case, and a name the header
 * set accepted is classified exactly as zuh_headers stores it. */
static void credential_names(const uint8_t *data, size_t size) {
    size_t i = 0;
    while (i < size) {
        const uint8_t *eol = (const uint8_t *)memchr(data + i, '\n', size - i);
        size_t end = eol ? (size_t)(eol - data) : size;
        const uint8_t *colon = (const uint8_t *)memchr(data + i, ':', end - i);
        if (colon && colon > data + i) {
            size_t nlen = (size_t)(colon - data) - i, k;
            char name[128], flip[128];
            if (nlen < sizeof name) {
                memcpy(name, data + i, nlen);
                name[nlen] = '\0';
                for (k = 0; k <= nlen; k++) {
                    char c = name[k];
                    flip[k] = (char)(c >= 'a' && c <= 'z' ? c - 32 : c >= 'A' && c <= 'Z' ? c + 32 : c);
                }
                if (strlen(name) == nlen &&
                    zuh_redirect_is_credential_header(NULL, name) !=
                    zuh_redirect_is_credential_header(NULL, flip))
                    abort();
            }
        }
        i = end + 1;
    }
}

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
    credential_names(data, size);
    return 0;
}

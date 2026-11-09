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

/* #230: §19.2's strip, which no target reached. The same input, read as
 * "name: value" lines, is the header set a cross-origin redirect carries;
 * afterwards no credential header may remain and nothing else may go. */
static void strip_credentials(const uint8_t *data, size_t size) {
    zuh_headers h;
    size_t i = 0, creds = 0, others = 0, left, j;
    const char *nm, *v;
    zuh_headers_init(&h);
    while (i < size) {
        const uint8_t *eol = (const uint8_t *)memchr(data + i, '\n', size - i);
        size_t end = eol ? (size_t)(eol - data) : size;
        const uint8_t *colon = (const uint8_t *)memchr(data + i, ':', end - i);
        if (colon && colon > data + i) {
            size_t nlen = (size_t)(colon - data) - i;
            const char *val = (const char *)colon + 1;
            size_t vlen = end - (size_t)(colon - data) - 1;
            char name[128];
            if (nlen < sizeof name &&
                zuh_headers_add(&h, (const char *)data + i, nlen, val, vlen) == ZUH_OK) {
                memcpy(name, data + i, nlen);
                name[nlen] = '\0';
                if (zuh_redirect_is_credential_header(NULL, name)) creds++; else others++;
            }
        }
        i = end + 1;
    }
    if (zuh_redirect_strip_credentials(&h, NULL) != creds) abort();
    for (left = 0, j = 0; zuh_headers_at(&h, j, &nm, &v); j++, left++)
        if (zuh_redirect_is_credential_header(NULL, nm)) abort();
    if (left != others) abort();
    zuh_headers_free(&h);
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
    strip_credentials(data, size);
    return 0;
}

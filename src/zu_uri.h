/* zuhttp — URI representation and parsing (design §8.2).
 *
 * D-11 is RESOLVED: a partial vendor of uriparser 0.9.8 supplies RFC 3986
 * parsing, relative resolution and recomposition. See
 * src/vendor/uriparser/VENDOR for which files are vendored and why the rest
 * (six of uriparser's eight historical CVEs) is excluded.
 *
 * The flat struct below is still the boundary: everything above this header —
 * redirects, the pool key, proxy matching — depends on the struct and never on
 * uriparser types, so the parser stays replaceable.
 */
#ifndef ZUHTTP_URI_H
#define ZUHTTP_URI_H

#include "zu_platform.h"
#include "zu_error.h"

typedef struct {
    char    *scheme;      /* lowercased: "http" or "https" */
    char    *host;        /* lowercased; IPv6 literals without brackets */
    char    *path_query;  /* origin-form target, always starting "/" */
    char    *userinfo;    /* credentials, moved out of the URL (§20.4) */
    uint16_t port;        /* explicit or scheme default */
    int      is_https;
    int      port_explicit;
} zu_uri;

void zu_uri_init(zu_uri *u);
void zu_uri_free(zu_uri *u);

/* Parse an absolute URI. The input is a BYTE RANGE, not a C string: a
 * Location header is a range into the response buffer and may not be
 * NUL-terminated. `last` points one past the final byte.
 *
 * On ZU_OK the struct is fully normalised (§8.2): scheme and host lowercased,
 * port resolved to a number, userinfo moved out of the URL (§20.4),
 * path_query in origin form and never empty.
 *
 * Returns ZU_ERR_URL for anything unusable, ZU_ERR_NOMEM on allocation
 * failure. `out` is left zeroed on failure — never partially populated. */
zu_code zu_uri_parse(zu_uri *out, const char *first, const char *last);

/* Resolve a possibly-relative reference against `base` (§19.6) — the
 * Location-header case. An absolute `ref` ignores `base` entirely. */
zu_code zu_uri_resolve(zu_uri *out, const zu_uri *base,
                       const char *ref, const char *ref_last);

/* Deep copy; returns 1 on success. */
int zu_uri_copy(zu_uri *dst, const zu_uri *src);

/* Same origin == same (scheme, host, port). RFC 6454. This is the comparison
 * that governs credential stripping on redirect (§19.2) and pool keying
 * (§26.1), so it is deliberately here rather than duplicated in both. */
int zu_uri_same_origin(const zu_uri *a, const zu_uri *b);

/* Default port for a scheme; 0 if unknown. */
uint16_t zu_uri_default_port(const char *scheme);

/* Serialise as "scheme://host[:port]" — never including userinfo, so the
 * result is safe to put in an error message or a trace (§42). */
int zu_uri_origin_string(const zu_uri *u, char *out, size_t cap);

#endif /* ZUHTTP_URI_H */

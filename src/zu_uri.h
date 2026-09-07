/* zuhttp — URI representation (design §8.2).
 *
 * This is the INTERFACE only. Decision D-11 (vendor uriparser vs. write a
 * project-owned RFC 3986 parser) chooses who populates it. Everything above
 * this header — redirects, the pool key, proxy matching — depends on the
 * struct and not on the parser, so D-11 can be decided by measurement without
 * rewriting its callers (§8.2).
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

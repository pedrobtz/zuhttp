#include "zu_uri.h"
#include "zu_alloc.h"
#include "zu_headers.h"   /* zu_ascii_casecmp */
#include <string.h>
#include <stdio.h>

void zu_uri_init(zu_uri *u) { memset(u, 0, sizeof *u); }

void zu_uri_free(zu_uri *u) {
    if (!u) return;
    zu_free(u->scheme); zu_free(u->host);
    zu_free(u->path_query); zu_free(u->userinfo);
    memset(u, 0, sizeof *u);
}

static char *dup_str(const char *s) {
    size_t n;
    char *p;
    if (!s) return NULL;
    n = strlen(s);
    p = (char *)zu_alloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n + 1);
    return p;
}

int zu_uri_copy(zu_uri *dst, const zu_uri *src) {
    if (!dst || !src) return 0;
    zu_uri_init(dst);
    dst->port = src->port;
    dst->is_https = src->is_https;
    dst->port_explicit = src->port_explicit;
    if (src->scheme     && !(dst->scheme     = dup_str(src->scheme)))     goto fail;
    if (src->host       && !(dst->host       = dup_str(src->host)))       goto fail;
    if (src->path_query && !(dst->path_query = dup_str(src->path_query))) goto fail;
    if (src->userinfo   && !(dst->userinfo   = dup_str(src->userinfo)))   goto fail;
    return 1;
fail:
    zu_uri_free(dst);
    return 0;
}

uint16_t zu_uri_default_port(const char *scheme) {
    if (!scheme) return 0;
    if (zu_ascii_casecmp(scheme, "https") == 0) return 443;
    if (zu_ascii_casecmp(scheme, "http")  == 0) return 80;
    return 0;
}

int zu_uri_same_origin(const zu_uri *a, const zu_uri *b) {
    uint16_t pa, pb;
    if (!a || !b) return 0;
    if (!a->scheme || !b->scheme || !a->host || !b->host) return 0;
    if (zu_ascii_casecmp(a->scheme, b->scheme) != 0) return 0;
    if (zu_ascii_casecmp(a->host, b->host) != 0) return 0;
    pa = a->port ? a->port : zu_uri_default_port(a->scheme);
    pb = b->port ? b->port : zu_uri_default_port(b->scheme);
    return pa == pb;
}

int zu_uri_origin_string(const zu_uri *u, char *out, size_t cap) {
    uint16_t def;
    if (!u || !out || cap == 0) return 0;
    if (!u->scheme || !u->host) { out[0] = '\0'; return 0; }
    def = zu_uri_default_port(u->scheme);
    /* userinfo is deliberately never included (§42.1). */
    if (u->port && u->port != def)
        return snprintf(out, cap, "%s://%s:%u", u->scheme, u->host,
                        (unsigned)u->port) < (int)cap;
    return snprintf(out, cap, "%s://%s", u->scheme, u->host) < (int)cap;
}

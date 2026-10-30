#include "zuh_redirect.h"
#include "zuh_alloc.h"
#include "zuh_buffer.h"
#include <string.h>

void zuh_redirect_policy_init(zuh_redirect_policy *p) {
    p->max_redirects = 10;
    p->allow_downgrade = 0;      /* §19.3 default */
}

int zuh_status_is_redirect(int status) {
    return status == 301 || status == 302 || status == 303 ||
           status == 307 || status == 308;
}

/* §19.2: fields that must never survive a cross-origin redirect are the
 * fields §42.1 calls secret — one list, in zuh_redact.c. This file kept its
 * own three names, so X-API-Key and X-Auth-Token, which the redactor hid from
 * every printout, were sent to whatever origin a redirect named; and a header
 * the caller had configured as secret was never consulted here at all. */
int zuh_redirect_is_credential_header(const zuh_redact_policy *p, const char *name) {
    return name ? zuh_redact_is_secret_header(p, name, strlen(name)) : 0;
}

size_t zuh_redirect_strip_credentials(zuh_headers *h, const zuh_redact_policy *p) {
    size_t i = 0, removed = 0;
    if (!h) return 0;
    while (i < h->n) {
        if (zuh_redact_is_secret_header(p, h->items[i].name, h->items[i].nlen)) {
            /* zuh_headers_remove() takes a name and removes every field so
             * named, freeing the one we would be pointing into; copy it,
             * then start over. */
            char name[ZUH_DEFAULT_MAX_HEADER_NAME + 1];
            size_t n = h->items[i].nlen < sizeof name - 1 ? h->items[i].nlen
                                                          : sizeof name - 1;
            memcpy(name, h->items[i].name, n);
            name[n] = '\0';
            removed += zuh_headers_remove(h, name);
            i = 0;
            continue;
        }
        i++;
    }
    return removed;
}

zuh_code zuh_redirect_decide(const zuh_redirect_policy *p, int status,
                           const char *method, const zuh_uri *from,
                           const zuh_uri *to, size_t hops_so_far,
                           zuh_redirect_decision *out, zuh_error *err) {
    int is_head;
    if (!p || !out || !method || !from || !to) return ZUH_ERR_PARSE;

    memset(out, 0, sizeof *out);
    out->action = ZUH_REDIRECT_NONE;

    if (!zuh_status_is_redirect(status)) return ZUH_OK;

    if (p->max_redirects && hops_so_far >= p->max_redirects) {
        zuh_error_set(err, ZUH_ERR_TOO_MANY_REDIRECTS, ZUH_PHASE_READ,
                     "stopped after %lu redirects, and the server sent another; "
                     "raise `redirects` if the chain is expected",
                     (unsigned long)p->max_redirects);
        return ZUH_ERR_TOO_MANY_REDIRECTS;
    }

    /* §19.3: refusing the downgrade is an error, not a silent stop, so the
     * caller never mistakes it for a successful final response. */
    if (!p->allow_downgrade && from->is_https && !to->is_https) {
        zuh_error_set(err, ZUH_ERR_REDIRECT, ZUH_PHASE_READ,
                     "refusing HTTPS to HTTP redirect");
        return ZUH_ERR_REDIRECT;
    }

    is_head = zuh_ascii_casecmp(method, "HEAD") == 0;

    /* §19.1, normative table. */
    switch (status) {
        case 301:
        case 302:
            /* POST becomes GET; other methods are unchanged. Historical
             * browser behaviour, and what curl does. */
            if (zuh_ascii_casecmp(method, "POST") == 0) {
                out->rewrite_to_get = 1;
                out->drop_body = 1;
            }
            break;
        case 303:
            /* Any method becomes GET, except HEAD which stays HEAD. The body
             * is ALWAYS dropped. */
            if (!is_head) out->rewrite_to_get = 1;
            out->drop_body = 1;
            break;
        case 307:
        case 308:
            /* Method and body are both preserved, so the body must be
             * replayable (§28.2). The caller checks rewindability and raises
             * zu_body_not_replayable rather than truncating. */
            out->needs_rewindable = 1;
            break;
        default:
            break;
    }

    /* §19.2: strip on ANY change of scheme, host or port — not only host. */
    out->strip_credentials = !zuh_uri_same_origin(from, to);
    out->action = ZUH_REDIRECT_FOLLOW;
    return ZUH_OK;
}

/* ---------------- loop detection ---------------- */

void zuh_redirect_trail_init(zuh_redirect_trail *t) { memset(t, 0, sizeof *t); }

void zuh_redirect_trail_free(zuh_redirect_trail *t) {
    size_t i;
    if (!t) return;
    for (i = 0; i < t->n; i++) zuh_free(t->seen[i]);
    zuh_free(t->seen);
    memset(t, 0, sizeof *t);
}

static char *trail_key(const char *method, const zuh_uri *u) {
    zuh_buffer b;
    const char *s = NULL;
    char origin[320];
    char *key;
    if (!zuh_uri_origin_string(u, origin, sizeof origin)) return NULL;
    if (!zuh_buf_init(&b, 96, 0)) return NULL;
    if (!zuh_buf_append_str(&b, method) || !zuh_buf_append_byte(&b, ' ') ||
        !zuh_buf_append_str(&b, origin) ||
        !zuh_buf_append_str(&b, u->path_query ? u->path_query : "/") ||
        !zuh_buf_cstr(&b, &s)) {
        zuh_buf_free(&b);
        return NULL;
    }
    key = (char *)zuh_alloc(b.len + 1);
    if (key) memcpy(key, s, b.len + 1);
    zuh_buf_free(&b);
    return key;
}

zuh_code zuh_redirect_trail_add(zuh_redirect_trail *t, const char *method, const zuh_uri *u) {
    char *key;
    size_t i;
    if (!t || !method || !u) return ZUH_ERR_PARSE;

    key = trail_key(method, u);
    if (!key) return ZUH_ERR_NOMEM;

    for (i = 0; i < t->n; i++) {
        if (strcmp(t->seen[i], key) == 0) { zuh_free(key); return ZUH_ERR_REDIRECT; }
    }
    if (t->n == t->cap) {
        size_t cap = t->cap ? t->cap * 2 : 8, bytes;
        char **p;
        if (!zuh_size_mul(cap, sizeof *p, &bytes)) { zuh_free(key); return ZUH_ERR_NOMEM; }
        p = (char **)zuh_realloc(t->seen, bytes);
        if (!p) { zuh_free(key); return ZUH_ERR_NOMEM; }
        t->seen = p; t->cap = cap;
    }
    t->seen[t->n++] = key;
    return ZUH_OK;
}

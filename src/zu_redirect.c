#include "zu_redirect.h"
#include "zu_alloc.h"
#include "zu_buffer.h"
#include <string.h>

void zu_redirect_policy_init(zu_redirect_policy *p) {
    p->max_redirects = 10;
    p->allow_downgrade = 0;      /* §19.3 default */
}

int zu_status_is_redirect(int status) {
    return status == 301 || status == 302 || status == 303 ||
           status == 307 || status == 308;
}

/* §19.2: fields that must never survive a cross-origin redirect.
 * Proxy-Authorization is here for completeness; §20.4 additionally forbids it
 * from ever reaching an origin at all. */
static const char *const k_credential_headers[] = {
    "Authorization", "Cookie", "Proxy-Authorization", NULL
};

size_t zu_redirect_strip_credentials(zu_headers *h) {
    size_t i, removed = 0;
    if (!h) return 0;
    for (i = 0; k_credential_headers[i]; i++)
        removed += zu_headers_remove(h, k_credential_headers[i]);
    return removed;
}

zu_code zu_redirect_decide(const zu_redirect_policy *p, int status,
                           const char *method, const zu_uri *from,
                           const zu_uri *to, size_t hops_so_far,
                           zu_redirect_decision *out, zu_error *err) {
    int is_head;
    if (!p || !out || !method || !from || !to) return ZU_ERR_PARSE;

    memset(out, 0, sizeof *out);
    out->action = ZU_REDIRECT_NONE;

    if (!zu_status_is_redirect(status)) return ZU_OK;

    if (p->max_redirects && hops_so_far >= p->max_redirects) {
        zu_error_set(err, ZU_ERR_TOO_MANY_REDIRECTS, ZU_PHASE_READ,
                     "exceeded %lu redirects", (unsigned long)p->max_redirects);
        return ZU_ERR_TOO_MANY_REDIRECTS;
    }

    /* §19.3: refusing the downgrade is an error, not a silent stop, so the
     * caller never mistakes it for a successful final response. */
    if (!p->allow_downgrade && from->is_https && !to->is_https) {
        zu_error_set(err, ZU_ERR_REDIRECT, ZU_PHASE_READ,
                     "refusing HTTPS to HTTP redirect");
        return ZU_ERR_REDIRECT;
    }

    is_head = zu_ascii_casecmp(method, "HEAD") == 0;

    /* §19.1, normative table. */
    switch (status) {
        case 301:
        case 302:
            /* POST becomes GET; other methods are unchanged. Historical
             * browser behaviour, and what curl does. */
            if (zu_ascii_casecmp(method, "POST") == 0) {
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
    out->strip_credentials = !zu_uri_same_origin(from, to);
    out->action = ZU_REDIRECT_FOLLOW;
    return ZU_OK;
}

/* ---------------- loop detection ---------------- */

void zu_redirect_trail_init(zu_redirect_trail *t) { memset(t, 0, sizeof *t); }

void zu_redirect_trail_free(zu_redirect_trail *t) {
    size_t i;
    if (!t) return;
    for (i = 0; i < t->n; i++) zu_free(t->seen[i]);
    zu_free(t->seen);
    memset(t, 0, sizeof *t);
}

static char *trail_key(const char *method, const zu_uri *u) {
    zu_buffer b;
    const char *s = NULL;
    char origin[320];
    char *key;
    if (!zu_uri_origin_string(u, origin, sizeof origin)) return NULL;
    if (!zu_buf_init(&b, 96, 0)) return NULL;
    if (!zu_buf_append_str(&b, method) || !zu_buf_append_byte(&b, ' ') ||
        !zu_buf_append_str(&b, origin) ||
        !zu_buf_append_str(&b, u->path_query ? u->path_query : "/") ||
        !zu_buf_cstr(&b, &s)) {
        zu_buf_free(&b);
        return NULL;
    }
    key = (char *)zu_alloc(b.len + 1);
    if (key) memcpy(key, s, b.len + 1);
    zu_buf_free(&b);
    return key;
}

int zu_redirect_trail_add(zu_redirect_trail *t, const char *method, const zu_uri *u) {
    char *key;
    size_t i;
    if (!t || !method || !u) return 0;

    key = trail_key(method, u);
    if (!key) return 0;

    for (i = 0; i < t->n; i++) {
        if (strcmp(t->seen[i], key) == 0) { zu_free(key); return 0; }  /* loop */
    }
    if (t->n == t->cap) {
        size_t cap = t->cap ? t->cap * 2 : 8, bytes;
        char **p;
        if (!zu_size_mul(cap, sizeof *p, &bytes)) { zu_free(key); return 0; }
        p = (char **)zu_realloc(t->seen, bytes);
        if (!p) { zu_free(key); return 0; }
        t->seen = p; t->cap = cap;
    }
    t->seen[t->n++] = key;
    return 1;
}

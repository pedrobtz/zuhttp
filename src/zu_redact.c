#include "zu_redact.h"
#include "zu_headers.h"   /* zu_ascii_ncasecmp */
#include <string.h>

/* §42.1 defaults. */
static const char *const k_headers[] = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    NULL
};

static const char *const k_params[] = {
    "access_token",
    "api_key",
    "signature",
    "sig",
    NULL
};

void zu_redact_policy_init(zu_redact_policy *p) {
    if (!p) return;
    p->extra_headers = NULL;
    p->extra_params  = NULL;
}

static int in_list(const char *const *list, const char *name, size_t nlen) {
    size_t i;
    if (!list) return 0;
    for (i = 0; list[i]; i++)
        if (zu_ascii_ncasecmp(name, nlen, list[i], strlen(list[i])) == 0) return 1;
    return 0;
}

int zu_redact_is_secret_header(const zu_redact_policy *p,
                               const char *name, size_t nlen) {
    if (!name || nlen == 0) return 0;
    if (in_list(k_headers, name, nlen)) return 1;
    return p ? in_list(p->extra_headers, name, nlen) : 0;
}

int zu_redact_is_secret_param(const zu_redact_policy *p,
                              const char *name, size_t nlen) {
    if (!name || nlen == 0) return 0;
    if (in_list(k_params, name, nlen)) return 1;
    return p ? in_list(p->extra_params, name, nlen) : 0;
}

/* Rewrite "a=1&token=SECRET&b=2" with secret values replaced. Separators are
 * preserved exactly, including the '&' vs ';' distinction and empty pairs, so
 * the redacted text still reads like the original. */
static int redact_query(const zu_redact_policy *p, const char *q, size_t len,
                        zu_buffer *out) {
    size_t i = 0;
    while (i < len) {
        size_t start = i, eq = (size_t)-1, end;
        while (i < len && q[i] != '&' && q[i] != ';') {
            if (q[i] == '=' && eq == (size_t)-1) eq = i;
            i++;
        }
        end = i;
        if (eq != (size_t)-1 && zu_redact_is_secret_param(p, q + start, eq - start)) {
            if (!zu_buf_append(out, q + start, eq - start + 1)) return 0;  /* "name=" */
            if (!zu_buf_append_str(out, ZU_REDACTED)) return 0;
        } else if (end > start) {
            if (!zu_buf_append(out, q + start, end - start)) return 0;
        }
        if (i < len) {                     /* keep the separator as written */
            if (!zu_buf_append_byte(out, (unsigned char)q[i])) return 0;
            i++;
        }
    }
    return 1;
}

int zu_redact_url(const zu_redact_policy *p, const char *url, size_t len,
                  zu_buffer *out) {
    const char *scheme_end, *auth, *auth_end, *at, *q;
    size_t i;

    if (!url || !out) return 0;

    /* Find the authority without parsing: this must work on a URL that FAILED
     * to parse, because that is precisely the URL an error message is about. */
    scheme_end = NULL;
    for (i = 0; i + 2 < len; i++) {
        if (url[i] == ':' && url[i + 1] == '/' && url[i + 2] == '/') {
            scheme_end = url + i + 3;
            break;
        }
    }

    if (scheme_end) {
        if (!zu_buf_append(out, url, (size_t)(scheme_end - url))) return 0;
        auth = scheme_end;
        auth_end = auth;
        while (auth_end < url + len && *auth_end != '/' && *auth_end != '?'
               && *auth_end != '#') auth_end++;
        /* The LAST '@' delimits userinfo: a '@' may legitimately appear
         * percent-decoded inside it, and taking the first would truncate. */
        at = NULL;
        for (q = auth; q < auth_end; q++) if (*q == '@') at = q;
        if (at) {
            /* §42.1: userinfo is removed outright, not replaced — a username
             * is identifying even when the password is hidden. */
            if (!zu_buf_append(out, at + 1, (size_t)(auth_end - at - 1))) return 0;
        } else if (!zu_buf_append(out, auth, (size_t)(auth_end - auth))) return 0;
        i = (size_t)(auth_end - url);
    } else {
        i = 0;
    }

    /* Path, then query with secret parameters replaced, then fragment. */
    {
        const char *rest = url + i;
        size_t rlen = len - i;
        const char *qm = (const char *)memchr(rest, '?', rlen);
        if (!qm) return zu_buf_append(out, rest, rlen);
        if (!zu_buf_append(out, rest, (size_t)(qm - rest) + 1)) return 0;
        {
            const char *qs = qm + 1;
            size_t qlen = rlen - (size_t)(qm - rest) - 1;
            const char *hash = (const char *)memchr(qs, '#', qlen);
            size_t only_q = hash ? (size_t)(hash - qs) : qlen;
            if (!redact_query(p, qs, only_q, out)) return 0;
            if (hash) return zu_buf_append(out, hash, qlen - only_q);
        }
    }
    return 1;
}

int zu_redact_form_body(const zu_redact_policy *p, const char *body, size_t len,
                        zu_buffer *out) {
    if (!body || !out) return 0;
    return redact_query(p, body, len, out);
}

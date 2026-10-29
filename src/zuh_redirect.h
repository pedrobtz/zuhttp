/* zuhttp — redirect policy (design §19).
 *
 * Depends on the zuh_uri STRUCT, not on a URI parser, so all of this is
 * settled independently of D-11. Only relative-Location resolution (§19.6)
 * needs the parser, and it lives elsewhere.
 */
#ifndef ZUHTTP_REDIRECT_H
#define ZUHTTP_REDIRECT_H

#include "zuh_platform.h"
#include "zuh_uri.h"
#include "zuh_headers.h"
#include "zuh_redact.h"
#include "zuh_error.h"

typedef struct {
    size_t max_redirects;      /* §19.4; default 10 */
    int    allow_downgrade;    /* HTTPS -> HTTP; default 0 (§19.3) */
} zuh_redirect_policy;

void zuh_redirect_policy_init(zuh_redirect_policy *p);

typedef enum {
    ZUH_REDIRECT_NONE = 0,   /* not a redirect status */
    ZUH_REDIRECT_FOLLOW      /* follow, per the fields below */
} zuh_redirect_action;

typedef struct {
    zuh_redirect_action action;
    int  rewrite_to_get;    /* §19.1: method becomes GET */
    int  drop_body;         /* §19.1: body is discarded */
    int  needs_rewindable;  /* 307/308: body is replayed, must be rewindable */
    int  strip_credentials; /* §19.2: cross-origin */
} zuh_redirect_decision;

/* Is this status a redirect zuhttp follows? */
int zuh_status_is_redirect(int status);

/* §19.1 method/body rewriting plus §19.2 stripping.
 * `method` is the current request method; from/to are the current and target
 * URIs. Returns ZUH_OK, or an error for a policy violation:
 *   ZUH_ERR_REDIRECT             HTTPS->HTTP downgrade refused (§19.3)
 *   ZUH_ERR_TOO_MANY_REDIRECTS   hop count exceeded (§19.4)
 */
zuh_code zuh_redirect_decide(const zuh_redirect_policy *p, int status,
                           const char *method, const zuh_uri *from,
                           const zuh_uri *to, size_t hops_so_far,
                           zuh_redirect_decision *out, zuh_error *err);

/* Apply §19.2 to a header set: remove every credential-bearing field.
 * Returns how many were removed. "Credential-bearing" is §42.1's list of
 * secret headers plus whatever `p` adds (NULL: the defaults). */
size_t zuh_redirect_strip_credentials(zuh_headers *h, const zuh_redact_policy *p);

/* Nonzero if `name` is one of the headers §19.2 strips on a cross-origin
 * redirect. The engine rebuilds each hop's headers from the caller's list,
 * so it filters with this while adding them rather than stripping after. */
int zuh_redirect_is_credential_header(const zuh_redact_policy *p, const char *name);

/* Loop detection (§19.4): has this (method, absolute URL) pair been seen? */
typedef struct {
    char **seen;      /* "METHOD scheme://host:port/path" */
    size_t n, cap;
} zuh_redirect_trail;

void    zuh_redirect_trail_init(zuh_redirect_trail *t);
void    zuh_redirect_trail_free(zuh_redirect_trail *t);
/* Returns 1 if newly recorded, 0 if already present (a loop) or on failure. */
int     zuh_redirect_trail_add(zuh_redirect_trail *t, const char *method, const zuh_uri *u);

#endif /* ZUHTTP_REDIRECT_H */

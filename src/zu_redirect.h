/* zuhttp — redirect policy (design §19).
 *
 * Depends on the zu_uri STRUCT, not on a URI parser, so all of this is
 * settled independently of D-11. Only relative-Location resolution (§19.6)
 * needs the parser, and it lives elsewhere.
 */
#ifndef ZUHTTP_REDIRECT_H
#define ZUHTTP_REDIRECT_H

#include "zu_platform.h"
#include "zu_uri.h"
#include "zu_headers.h"
#include "zu_error.h"

typedef struct {
    size_t max_redirects;      /* §19.4; default 10 */
    int    allow_downgrade;    /* HTTPS -> HTTP; default 0 (§19.3) */
} zu_redirect_policy;

void zu_redirect_policy_init(zu_redirect_policy *p);

typedef enum {
    ZU_REDIRECT_NONE = 0,   /* not a redirect status */
    ZU_REDIRECT_FOLLOW      /* follow, per the fields below */
} zu_redirect_action;

typedef struct {
    zu_redirect_action action;
    int  rewrite_to_get;    /* §19.1: method becomes GET */
    int  drop_body;         /* §19.1: body is discarded */
    int  needs_rewindable;  /* 307/308: body is replayed, must be rewindable */
    int  strip_credentials; /* §19.2: cross-origin */
} zu_redirect_decision;

/* Is this status a redirect zuhttp follows? */
int zu_status_is_redirect(int status);

/* §19.1 method/body rewriting plus §19.2 stripping.
 * `method` is the current request method; from/to are the current and target
 * URIs. Returns ZU_OK, or an error for a policy violation:
 *   ZU_ERR_REDIRECT             HTTPS->HTTP downgrade refused (§19.3)
 *   ZU_ERR_TOO_MANY_REDIRECTS   hop count exceeded (§19.4)
 */
zu_code zu_redirect_decide(const zu_redirect_policy *p, int status,
                           const char *method, const zu_uri *from,
                           const zu_uri *to, size_t hops_so_far,
                           zu_redirect_decision *out, zu_error *err);

/* Apply §19.2 to a header set: remove every credential-bearing field.
 * Returns how many were removed. */
size_t zu_redirect_strip_credentials(zu_headers *h);

/* Loop detection (§19.4): has this (method, absolute URL) pair been seen? */
typedef struct {
    char **seen;      /* "METHOD scheme://host:port/path" */
    size_t n, cap;
} zu_redirect_trail;

void    zu_redirect_trail_init(zu_redirect_trail *t);
void    zu_redirect_trail_free(zu_redirect_trail *t);
/* Returns 1 if newly recorded, 0 if already present (a loop) or on failure. */
int     zu_redirect_trail_add(zu_redirect_trail *t, const char *method, const zu_uri *u);

#endif /* ZUHTTP_REDIRECT_H */

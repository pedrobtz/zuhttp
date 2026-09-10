/* zuhttp — proxy configuration and tunnelling (design §20).
 *
 * Environment reading goes through a seam rather than calling getenv()
 * directly, so the §20.1 and §20.2 rules are tested against a table instead
 * of by mutating the real environment — which is not thread-safe, leaks
 * between tests, and cannot represent "unset" reliably on Windows.
 */
#ifndef ZUHTTP_PROXY_H
#define ZUHTTP_PROXY_H

#include "zu_platform.h"
#include "zu_uri.h"
#include "zu_buffer.h"
#include "zu_error.h"

/* --- §20.1 environment ---------------------------------------------------- */

typedef const char *(*zu_getenv_fn)(void *ctx, const char *name);

typedef struct {
    zu_getenv_fn get;
    void        *ctx;
} zu_env;

/* Backed by the real getenv(). */
void zu_env_system(zu_env *e);

/* --- proxy ---------------------------------------------------------------- */

typedef struct {
    int      in_use;        /* 0 => connect directly */
    char    *scheme;        /* "http" only; https-to-proxy is not supported */
    char    *host;
    uint16_t port;
    char    *username;      /* moved OUT of the URL (§20.4); may be NULL */
    char    *password;
    char    *source;        /* which variable decided this, for §42 traces */
} zu_proxy;

void zu_proxy_init(zu_proxy *p);
void zu_proxy_free(zu_proxy *p);

/* Parse a proxy URL. Credentials are moved out of the URL immediately, so
 * nothing downstream can print them by accident (§20.4). A bare "host:port"
 * with no scheme is accepted, as curl does. */
zu_code zu_proxy_parse(zu_proxy *p, const char *url, zu_error *err);

/* §20.1 + §20.2: which proxy, if any, applies to `target`.
 *
 * Precedence: an explicit `override` always wins over the environment; pass
 * `override_set` with a NULL/empty `override` to mean "proxying is disabled",
 * which is deliberately distinct from "not configured". */
zu_code zu_proxy_resolve(zu_proxy *out, const zu_uri *target, const zu_env *env,
                         const char *override, int override_set, zu_error *err);

/* §20.2. `host` is compared case-insensitively on label boundaries. */
int zu_no_proxy_matches(const char *no_proxy, const char *host, uint16_t port);

/* --- §20.3 request forms -------------------------------------------------- */

/* Absolute-form target for plain HTTP through a proxy:
 * "http://example.com/path?q". Never includes userinfo. */
int zu_proxy_absolute_form(const zu_uri *u, zu_buffer *out);

/* The CONNECT request for tunnelled HTTPS, including Proxy-Authorization when
 * credentials are configured. Ends with the blank line. */
zu_code zu_proxy_connect_request(const zu_proxy *p, const zu_uri *target,
                                 zu_buffer *out, zu_error *err);

/* Parse a CONNECT response with full §18 strictness. Returns ZU_OK only for
 * 2xx; a non-2xx becomes ZU_ERR_PROXY (or ZU_ERR_PROXY_AUTH for 407) with the
 * proxy's status in the message, because in a corporate environment that is
 * frequently the only diagnostic the user gets (§20.3). */
zu_code zu_proxy_connect_response(const char *buf, size_t len, size_t *consumed,
                                  int *status, zu_error *err);

/* --- §20.4 credentials ---------------------------------------------------- */

/* "Basic <base64(user:pass)>". Returns 0 if no credentials are configured. */
int zu_proxy_auth_value(const zu_proxy *p, zu_buffer *out);

/* Base64, exposed because §20.4 auth is its only user and it must be tested
 * against the RFC 4648 vectors rather than assumed. */
int zu_base64_encode(const void *src, size_t n, zu_buffer *out);

#endif /* ZUHTTP_PROXY_H */

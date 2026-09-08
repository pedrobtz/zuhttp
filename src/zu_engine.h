/* zuhttp — the vertical slice (design §63.2).
 *
 * The first code that composes the pieces rather than testing them apart:
 *
 *     URI -> TCP -> TLS -> request -> response -> framing -> body -> redirect
 *
 * Everything below has been unit-tested against a mock stream; this is where
 * we find out whether it composes. Scope is deliberately §63.2's: GET only,
 * one redirect, Content-Length and chunked, transparent gzip, a total
 * deadline, and a memory body.
 *
 * NOT here, and deliberately: proxies, retries, streaming sinks. Each has its
 * own stage and its own tests; wiring them in before the simple path works end
 * to end would make the first integration failure harder to read.
 *
 * The connection pool WAS on that list until S16. It is now opt-in through
 * zu_get_opts.pool: NULL keeps the original behaviour of opening and closing
 * one connection per hop, which is what the offline suites and the fuzzers
 * still use.
 */
#ifndef ZUHTTP_ENGINE_H
#define ZUHTTP_ENGINE_H

#include "zu_platform.h"
#include "zu_error.h"
#include "zu_headers.h"
#include "zu_buffer.h"
#include "zu_net.h"
#include "zu_pool.h"
#include "zu_sink.h"
#include "zu_proxy.h"
#include "zu_tls.h"

/* A request the engine can perform. Headers are parallel arrays rather than a
 * zu_headers, so the R layer can pass them without building one — the engine
 * validates every name and value through zu_headers_add anyway (§17.1). */
typedef struct {
    const char        *method;         /* NULL => "GET" */
    const char *const *header_names;
    const char *const *header_values;
    size_t             n_headers;
    const void        *body;           /* NULL => no body */
    size_t             body_len;
} zu_req_spec;

typedef struct {
    long        timeout_ms;      /* total, across redirects (§24.1); <=0 = 30s */
    int         max_redirects;   /* §63.2 slice ships 1; 0 disables */
    int         verify;          /* TLS peer + hostname; default 1 (§14.1) */
    const char *ca_file;         /* replaces system trust when set (D-12) */

    /* §14. The rest of the trust configuration: ca_extra, pins, revocation,
     * minimum version. NULL means the §14.1 defaults.
     *
     * A pointer to a caller-owned config rather than copies of its fields,
     * so there is one definition of what a TLS configuration IS. `verify`
     * above stays authoritative for verify_peer/verify_hostname — it is
     * already a merged policy argument (§31.9), and letting zu_tls() carry it
     * too would be the "it cannot be both" mistake §31.13 names. `ca_file`
     * above likewise stays the one place a replacement CA is named; a
     * `ca_file` inside `tls` would be a second. */
    const zu_tls_config *tls;
    uint64_t    max_body;        /* §40 cap on the decoded body; 0 = 16 MiB */
    int         no_decode;       /* §21.2: leave Content-Encoding alone and
                                  * hand back the wire bytes. Negated so that
                                  * a zeroed struct still decodes, which is
                                  * what every existing caller expects. */
    const char *user_agent;
    zu_tick_fn  tick;            /* §25.1 interrupt seam; may be NULL */
    void       *tick_ctx;

    /* §26. NULL means "no pooling": every hop opens and closes its own
     * connection, which is the pre-S16 behaviour and still the right one for
     * a one-shot request. The pool is NOT owned here — it outlives any single
     * request, which is the entire point of it (§26.5). */
    zu_pool    *pool;

    /* §27. NULL buffers the body into zu_result.body, which is the pre-S17
     * behaviour. A sink here receives the FINAL response body only — never an
     * intermediate redirect body (§19.5).
     *
     * The engine does not own it and never calls finish() or abort() on it:
     * whether a transfer is committed depends on what the caller does with
     * the return code, and only the caller knows. */
    zu_sink    *sink;

    /* §20. `proxy` is an explicit override; NULL with proxy_set = 0 means
     * "consult the environment" (§20.1). proxy_set = 1 with a NULL or empty
     * `proxy` means proxying is DISABLED — deliberately distinct from "not
     * configured", because a caller who wrote proxy = NULL wants a direct
     * connection, not whatever http_proxy happens to say. */
    const char *proxy;
    int         proxy_set;

    /* Environment seam (§20.1). NULL uses the real getenv(). Present so the
     * proxy rules are testable against a table rather than by mutating the
     * process environment, which is not thread-safe and leaks between
     * tests. */
    const zu_env *env;
} zu_get_opts;

void zu_get_opts_init(zu_get_opts *o);

typedef struct {
    int        status;
    zu_headers headers;
    zu_buffer  body;             /* decoded */
    char      *final_url;        /* after redirects, credential-free */
    char      *tls_version;      /* NULL for http:// */
    char      *tls_cipher;
    int        redirects;
} zu_result;

void zu_result_init(zu_result *r);
void zu_result_free(zu_result *r);

/* Perform one GET. On ZU_OK `out` owns everything and the caller frees it with
 * zu_result_free(); on failure `out` is left empty and `err` describes why. */
/* Perform one request. `req` may be NULL, which means a plain GET.
 *
 * On ZU_OK `out` owns everything and the caller frees it with
 * zu_result_free(); on failure `out` is left empty and `err` says why. */
zu_code zu_engine_perform(zu_result *out, const char *url,
                          const zu_req_spec *req, const zu_get_opts *o,
                          zu_error *err);

/* Convenience wrapper: a GET with no extra headers and no body. */
zu_code zu_engine_get(zu_result *out, const char *url,
                      const zu_get_opts *o, zu_error *err);

#endif /* ZUHTTP_ENGINE_H */

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
 * NOT here, and deliberately: the connection pool (the slice opens and closes
 * one connection), proxies, retries, streaming sinks. Each has its own stage
 * and its own tests; wiring them in before the simple path works end to end
 * would make the first integration failure harder to read.
 */
#ifndef ZUHTTP_ENGINE_H
#define ZUHTTP_ENGINE_H

#include "zu_platform.h"
#include "zu_error.h"
#include "zu_headers.h"
#include "zu_buffer.h"
#include "zu_net.h"

typedef struct {
    long        timeout_ms;      /* total, across redirects (§24.1); <=0 = 30s */
    int         max_redirects;   /* §63.2 slice ships 1; 0 disables */
    int         verify;          /* TLS peer + hostname; default 1 (§14.1) */
    const char *ca_file;         /* replaces system trust when set (D-12) */
    uint64_t    max_body;        /* §40 cap on the decoded body; 0 = 16 MiB */
    const char *user_agent;
    zu_tick_fn  tick;            /* §25.1 interrupt seam; may be NULL */
    void       *tick_ctx;
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
zu_code zu_engine_get(zu_result *out, const char *url,
                      const zu_get_opts *o, zu_error *err);

#endif /* ZUHTTP_ENGINE_H */

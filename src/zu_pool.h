/* zuhttp — connection pool (design §26).
 *
 * Depends on zu_stream, not on TLS or sockets, so the whole pool is testable
 * against the mock stream with no network (§50.1).
 *
 * The two rules that shape this file:
 *
 *   §26.1  "a coarse key that ignores any of the above is a security bug,
 *           not a performance optimisation" — so the key mirrors the spec
 *           field by field rather than collapsing to a hash, and every field
 *           is separately testable.
 *   §26.3  "The safe default is to close." Reuse is opt-in per response, and
 *           the caller must name a reason, so a new code path that forgets to
 *           decide gets the safe answer.
 */
#ifndef ZUHTTP_POOL_H
#define ZUHTTP_POOL_H

#include "zu_platform.h"
#include "zu_stream.h"
#include "zu_fork.h"
#include "zu_time.h"

/* --- §26.1 pool key ------------------------------------------------------
 *
 * Compared BY VALUE. Two clients built from identical settings must share a
 * pool; two with any difference must not. Strings are owned copies. */
typedef struct {
    char    *scheme;          /* "http" / "https" */
    char    *host;            /* as written, PRE-resolution */
    uint16_t port;

    /* Full proxy identity INCLUDING credentials (§20.4): two requests through
     * the same proxy host with different credentials must not share. */
    char    *proxy;

    /* Full TLS configuration, mirroring zu_tls_config. Kept as separate
     * fields rather than a pointer so equality is by value (§26.1). */
    int      verify_peer;
    int      verify_hostname;
    int      revocation;
    int      min_version;
    char    *alpn;
    char    *ca_file;
    char    *ca_extra_file;
    char    *ca_data_id;      /* stable id for inline CA bytes, or NULL */
    char    *pins;            /* canonicalised pin set, or NULL */
    char    *client_cert;     /* client certificate identity, or NULL */
} zu_pool_key;

void zu_pool_key_init(zu_pool_key *k);
void zu_pool_key_free(zu_pool_key *k);
int  zu_pool_key_copy(zu_pool_key *dst, const zu_pool_key *src);   /* 1 = ok */
int  zu_pool_key_eq(const zu_pool_key *a, const zu_pool_key *b);

/* --- §26.3 why a connection is or is not reusable ------------------------
 *
 * One enum member per bullet of §26.3. Naming the reason rather than passing
 * a bare int is what makes "did we close for the right reason?" testable, and
 * it feeds the §42 trace. */
typedef enum {
    ZU_REUSE_OK = 0,              /* body fully read, framing unambiguous */
    ZU_NOREUSE_BODY_INCOMPLETE,   /* incl. early return() from a stream callback */
    ZU_NOREUSE_CANCELLED,         /* cancelled or timed out (§25.3) */
    ZU_NOREUSE_FRAMING,           /* any §18.1 rejection fired */
    ZU_NOREUSE_CLOSE_FRAMED,      /* response used connection-close framing */
    ZU_NOREUSE_CONNECTION_CLOSE,  /* either side sent Connection: close */
    ZU_NOREUSE_REDIRECT_BODY,     /* redirect body exceeded max_redirect_body */
    ZU_NOREUSE_TLS_ERROR,         /* a TLS error occurred at any point */
    ZU_REUSE_REASON_COUNT
} zu_reuse;

const char *zu_reuse_name(zu_reuse r);

/* --- §26.2 policy -------------------------------------------------------- */
typedef struct {
    size_t max_idle;        /* global idle connections */
    size_t max_per_host;    /* per (scheme, host, port) */
    long   idle_timeout_ms;
    int    stale_probe_ms;  /* liveness probe budget; 0 = non-blocking poll */
} zu_pool_config;

/* "Initial defaults are conservative" (§26.2): 16 / 4 / 30s. */
void zu_pool_config_init(zu_pool_config *c);

typedef struct {
    size_t idle;
    size_t hits;
    size_t misses;
    size_t discarded_stale;     /* §26.2 liveness probe said readable */
    size_t discarded_expired;   /* idle_timeout_ms elapsed */
    size_t discarded_capacity;  /* max_idle / max_per_host */
    size_t discarded_unusable;  /* released with a §26.3 reason */
    size_t discarded_fork;      /* §26.4 inherited from the parent */
    size_t forks_detected;
} zu_pool_stats;

typedef struct zu_pool zu_pool;

zu_pool *zu_pool_new(const zu_pool_config *cfg);   /* NULL cfg = defaults */
void     zu_pool_free(zu_pool *p);

/* §26.4 hazard 1. Drops every inherited connection WITHOUT a graceful close —
 * a graceful TLS shutdown from the child would write to a socket the parent
 * still owns — and re-arms the guard. Returns 1 if a fork was detected.
 *
 * Called automatically by acquire and release; exposed because §26.4 requires
 * it "on every acquisition and in every finalizer". */
int zu_pool_check_fork(zu_pool *p);

/* An idle connection matching `key`, or NULL. Runs the fork guard, then the
 * §26.2 expiry and liveness checks, discarding anything that fails. */
zu_stream *zu_pool_acquire(zu_pool *p, const zu_pool_key *key);

/* Hand a connection back. Anything other than ZU_REUSE_OK closes it, as do
 * capacity limits and a failed liveness probe. Takes ownership of `s` either
 * way, so the caller never has to decide who frees it. */
void zu_pool_release(zu_pool *p, const zu_pool_key *key, zu_stream *s, zu_reuse r);

void zu_pool_stats_get(const zu_pool *p, zu_pool_stats *out);
size_t zu_pool_idle_count(const zu_pool *p);

/* Close and drop every idle connection. */
void zu_pool_clear(zu_pool *p);

/* Test seam: the pool reads time through this, so idle expiry can be tested
 * without sleeping. NULL restores the monotonic clock. */
void zu_pool_set_clock(zu_pool *p, zu_millis (*now_ms)(void *), void *ctx);

#endif /* ZUHTTP_POOL_H */

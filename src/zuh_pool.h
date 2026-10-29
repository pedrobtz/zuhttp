/* zuhttp — connection pool (design §26).
 *
 * Depends on zuh_stream, not on TLS or sockets, so the whole pool is testable
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

#include "zuh_platform.h"
#include "zuh_stream.h"
#include "zuh_headers.h"
#include "zuh_framing.h"
#include "zuh_fork.h"
#include "zuh_time.h"

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

    /* Full TLS configuration, mirroring zuh_tls_config. Kept as separate
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
} zuh_pool_key;

void zuh_pool_key_init(zuh_pool_key *k);
void zuh_pool_key_free(zuh_pool_key *k);
int  zuh_pool_key_copy(zuh_pool_key *dst, const zuh_pool_key *src);   /* 1 = ok */
int  zuh_pool_key_eq(const zuh_pool_key *a, const zuh_pool_key *b);

/* --- §26.3 why a connection is or is not reusable ------------------------
 *
 * One enum member per bullet of §26.3. Naming the reason rather than passing
 * a bare int is what makes "did we close for the right reason?" testable, and
 * it feeds the §42 trace. */
typedef enum {
    ZUH_REUSE_OK = 0,              /* body fully read, framing unambiguous */
    ZUH_NOREUSE_BODY_INCOMPLETE,   /* incl. early return() from a stream callback */
    ZUH_NOREUSE_CANCELLED,         /* cancelled or timed out (§25.3) */
    ZUH_NOREUSE_FRAMING,           /* any §18.1 rejection fired */
    ZUH_NOREUSE_CLOSE_FRAMED,      /* response used connection-close framing */
    ZUH_NOREUSE_CONNECTION_CLOSE,  /* either side sent Connection: close */
    ZUH_NOREUSE_REDIRECT_BODY,     /* redirect body exceeded max_redirect_body */
    ZUH_NOREUSE_TLS_ERROR,         /* a TLS error occurred at any point */
    ZUH_REUSE_REASON_COUNT
} zuh_reuse;

const char *zuh_reuse_name(zuh_reuse r);

/* Decide §26.3 for one finished exchange.
 *
 * Lives here rather than in the engine so that the policy is unit-testable
 * with no network and no engine — the same reason the rest of the pool is
 * (§50.1). The engine calls it at the point where the framing and the
 * response headers that justify the answer are still in scope; nothing else
 * can see enough to decide.
 *
 * `rc` is the request's outcome, `fr` its framing, `minor_version` the 0 or 1
 * of HTTP/1.x — 1.0 is not persistent unless the server opts in. */
zuh_reuse zuh_reuse_decide(zuh_code rc, const zuh_framing *fr,
                         const zuh_headers *resp_headers, int minor_version);

/* --- §26.2 policy -------------------------------------------------------- */
typedef struct {
    size_t max_idle;        /* global idle connections */
    size_t max_per_host;    /* per (scheme, host, port) */
    long   idle_timeout_ms;
    int    stale_probe_ms;  /* liveness probe budget; 0 = non-blocking poll */
} zuh_pool_config;

/* "Initial defaults are conservative" (§26.2): 16 / 4 / 30s. */
void zuh_pool_config_init(zuh_pool_config *c);

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
} zuh_pool_stats;

typedef struct zuh_pool zuh_pool;

zuh_pool *zuh_pool_new(const zuh_pool_config *cfg);   /* NULL cfg = defaults */
void     zuh_pool_free(zuh_pool *p);

/* §26.4 hazard 1. Drops every inherited connection WITHOUT a graceful close —
 * a graceful TLS shutdown from the child would write to a socket the parent
 * still owns — and re-arms the guard. Returns 1 if a fork was detected.
 *
 * Called automatically by acquire and release; exposed because §26.4 requires
 * it "on every acquisition and in every finalizer". */
int zuh_pool_check_fork(zuh_pool *p);

/* An idle connection matching `key`, or NULL. Runs the fork guard, then the
 * §26.2 expiry and liveness checks, discarding anything that fails. */
zuh_stream *zuh_pool_acquire(zuh_pool *p, const zuh_pool_key *key);

/* Hand a connection back. Anything other than ZUH_REUSE_OK closes it, as do
 * capacity limits and a failed liveness probe. Takes ownership of `s` either
 * way, so the caller never has to decide who frees it. */
void zuh_pool_release(zuh_pool *p, const zuh_pool_key *key, zuh_stream *s, zuh_reuse r);

void zuh_pool_stats_get(const zuh_pool *p, zuh_pool_stats *out);
size_t zuh_pool_idle_count(const zuh_pool *p);

/* Close and drop every idle connection. */
void zuh_pool_clear(zuh_pool *p);

/* Test seam: the pool reads time through this, so idle expiry can be tested
 * without sleeping. NULL restores the monotonic clock. */
void zuh_pool_set_clock(zuh_pool *p, zuh_millis (*now_ms)(void *), void *ctx);

#endif /* ZUHTTP_POOL_H */

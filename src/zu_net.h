/* zuhttp — TCP transport (design §8.5, §24, §25).
 *
 * Provides a zu_stream over a non-blocking socket. Everything above this file
 * sees only zu_stream (§9), so TLS and the proxy tunnel can be layered without
 * the HTTP engine noticing.
 *
 * Two properties this layer exists to guarantee:
 *   §24  every operation is bounded by a deadline, from a monotonic clock
 *   §25  the caller never blocks longer than one tick without being asked
 *        whether to keep going — that callback is where
 *        R_CheckUserInterrupt() will live, and it is why the core needs no
 *        R headers to be interruptible.
 */
#ifndef ZUHTTP_NET_H
#define ZUHTTP_NET_H

#include "zu_platform.h"
#include "zu_stream.h"
#include "zu_trace.h"
#include "zu_error.h"
#include "zu_time.h"

/* Called at every poll checkpoint. Return non-zero to abort the operation,
 * which surfaces as ZU_ERR_CANCELLED. NULL means "never cancel". */
typedef int (*zu_tick_fn)(void *ctx);

/* Winsock needs process-wide setup; POSIX does not. Idempotent. */
zu_code zu_net_init(void);
void    zu_net_shutdown(void);

typedef struct {
    zu_tick_fn tick;
    void      *tick_ctx;
    int        tick_ms;      /* poll slice; <= 0 uses 100ms (§25.1) */

    /* §35: where dns.start/done and connect.start/done are recorded. Only
     * this layer can split them — from outside, resolution and connection are
     * one call, and reporting them together would hide which of the two a
     * slow request is waiting on, which is usually the question. */
    zu_trace  *trace;

    /* §35.1's dns and connect, filled here because only this layer can split
     * them: from outside, resolution and connection are one call, and
     * reporting the sum hides which of the two a slow request is waiting on —
     * usually the question being asked. */
    zu_timings *timings;
} zu_net_opts;

void zu_net_opts_init(zu_net_opts *o);

/* Resolve `host` and connect, trying each address in turn.
 *
 * NOTE (§8.4, §25.4): getaddrinfo() is synchronous and NOT interruptible on
 * the platforms zuhttp targets. A request blocked in DNS will not respond to
 * the tick callback until the resolver returns. This is a known, documented
 * gap, not an oversight.
 */
zu_code zu_net_connect(zu_stream **out, const char *host, uint16_t port,
                       zu_deadline deadline, const zu_net_opts *opts,
                       zu_error *err);

void zu_net_stream_free(zu_stream *s);

/* Peer address of a connected stream, for §35.2 remote_ip. */
int zu_net_peer_ip(const zu_stream *s, char *out, size_t cap);

#endif /* ZUHTTP_NET_H */

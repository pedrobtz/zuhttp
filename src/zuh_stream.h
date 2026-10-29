/* zuhttp — the generic stream interface.
 *
 * Design §9 and §39: "one of the most important architectural boundaries".
 * The HTTP engine depends only on this, so it can be driven by plain TCP,
 * TLS, a proxy tunnel, or a mock (§50.1) with no conditional logic.
 */
#ifndef ZUHTTP_STREAM_H
#define ZUHTTP_STREAM_H

#include "zuh_platform.h"
#include "zuh_error.h"
#include "zuh_time.h"

typedef struct zuh_stream zuh_stream;

typedef struct {
    const char *name;
    /* Return bytes moved, 0 on orderly close, or -1 with *err set.
     * ZUH_ERR_WOULDBLOCK in *err means "retry", not "failed". */
    zuh_ssize (*read )(zuh_stream *s, void *buf, size_t n, zuh_deadline d, zuh_error *err);
    zuh_ssize (*write)(zuh_stream *s, const void *buf, size_t n, zuh_deadline d, zuh_error *err);
    void     (*close)(zuh_stream *s);
    /* Release the stream and everything it owns, including any wrapped inner
     * stream. Needed because a wrapper (TLS, proxy tunnel) cannot know how to
     * free what it wraps. close() ends the connection; destroy() frees. */
    void     (*destroy)(zuh_stream *s);
    /* Is there data (or an EOF/error) waiting to be read, without blocking
     * longer than timeout_ms? Returns 1 yes, 0 no, -1 cannot tell.
     *
     * This exists for §26.2 stale-connection detection: a pooled socket that
     * is readable BEFORE a request is written has either been closed by the
     * peer or is carrying unread bytes from a previous response, and must be
     * discarded either way. It is a liveness probe, not a read — it must not
     * consume anything. */
    int      (*readable)(zuh_stream *s, int timeout_ms);
} zuh_stream_vtable;

struct zuh_stream {
    const zuh_stream_vtable *vt;
    void                   *impl;
};

zuh_ssize zuh_stream_read (zuh_stream *s, void *buf, size_t n, zuh_deadline d, zuh_error *err);
zuh_ssize zuh_stream_write(zuh_stream *s, const void *buf, size_t n, zuh_deadline d, zuh_error *err);
void     zuh_stream_close(zuh_stream *s);
/* Generic release. Use this rather than a backend-specific free whenever the
 * concrete type is not known — which is the normal case above §9. */
void     zuh_stream_free(zuh_stream *s);
const char *zuh_stream_name(const zuh_stream *s);

/* 1 = readable now, 0 = not, -1 = the backend cannot tell (no probe).
 * Callers must treat -1 as "unknown", never as "fine to reuse". */
int zuh_stream_readable(zuh_stream *s, int timeout_ms);

/* Write everything or fail. Loops over partial writes and WOULDBLOCK. */
int zuh_stream_write_all(zuh_stream *s, const void *buf, size_t n, zuh_deadline d, zuh_error *err);

#endif /* ZUHTTP_STREAM_H */

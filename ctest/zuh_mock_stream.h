/* zuhttp — scripted mock stream.
 *
 * Design §50.1: this is the substitution point zuhttp's OWN tests use. The
 * R-level mock transport (§36) bypasses the C engine entirely, which makes it
 * the right tool for a downstream package's tests and the wrong one for ours.
 * This mock sits under the engine, so parsing, framing, redirects, pooling and
 * decompression all run for real against canned bytes.
 *
 * The script can deliver any byte sequence split at any boundary — including
 * one byte per read — and can inject WOULDBLOCK, errors, and orderly close.
 */
#ifndef ZUHTTP_MOCK_STREAM_H
#define ZUHTTP_MOCK_STREAM_H

#include "zuh_stream.h"
#include "zuh_buffer.h"

typedef enum {
    ZUH_MOCK_DATA = 0,   /* hand out `len` bytes from `data` */
    ZUH_MOCK_WOULDBLOCK, /* one -1 / ZUH_ERR_WOULDBLOCK, then continue */
    ZUH_MOCK_ERROR,      /* -1 with `code`, permanently */
    ZUH_MOCK_EOF         /* orderly close: read returns 0 */
} zuh_mock_kind;

typedef struct {
    zuh_mock_kind kind;
    const void  *data;
    size_t       len;
    zuh_code      code;  /* ZUH_MOCK_ERROR only */
} zuh_mock_step;

/* max_read  0 = give as much as the caller asked for; 1 = one byte at a time.
 * max_write 0 = accept everything; N = accept at most N bytes per write, so
 *           partial-write handling in zuh_stream_write_all is exercised. */
zuh_stream *zuh_mock_stream_new(const zuh_mock_step *steps, size_t nsteps,
                              size_t max_read, size_t max_write);

/* Convenience for the common case: one canned response blob. */
zuh_stream *zuh_mock_stream_from_bytes(const void *data, size_t len, size_t max_read);

void zuh_mock_stream_free(zuh_stream *s);

/* Everything the engine wrote, for asserting on generated requests (§17). */
const zuh_buffer *zuh_mock_stream_written(const zuh_stream *s);

/* Did the script run to completion? Catches tests that assert success while
 * silently leaving canned input unread. */
int zuh_mock_stream_exhausted(const zuh_stream *s);

/* Pin what the §26.2 liveness probe reports, so a pool test can construct a
 * stale connection without a real peer. `value` is 1, 0 or -1; pass forced=0
 * to go back to deriving it from the script. */
void zuh_mock_stream_set_readable(zuh_stream *s, int forced, int value);

#endif /* ZUHTTP_MOCK_STREAM_H */

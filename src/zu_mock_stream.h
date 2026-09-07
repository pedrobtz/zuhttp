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

#include "zu_stream.h"
#include "zu_buffer.h"

typedef enum {
    ZU_MOCK_DATA = 0,   /* hand out `len` bytes from `data` */
    ZU_MOCK_WOULDBLOCK, /* one -1 / ZU_ERR_WOULDBLOCK, then continue */
    ZU_MOCK_ERROR,      /* -1 with `code`, permanently */
    ZU_MOCK_EOF         /* orderly close: read returns 0 */
} zu_mock_kind;

typedef struct {
    zu_mock_kind kind;
    const void  *data;
    size_t       len;
    zu_code      code;  /* ZU_MOCK_ERROR only */
} zu_mock_step;

/* max_read  0 = give as much as the caller asked for; 1 = one byte at a time.
 * max_write 0 = accept everything; N = accept at most N bytes per write, so
 *           partial-write handling in zu_stream_write_all is exercised. */
zu_stream *zu_mock_stream_new(const zu_mock_step *steps, size_t nsteps,
                              size_t max_read, size_t max_write);

/* Convenience for the common case: one canned response blob. */
zu_stream *zu_mock_stream_from_bytes(const void *data, size_t len, size_t max_read);

void zu_mock_stream_free(zu_stream *s);

/* Everything the engine wrote, for asserting on generated requests (§17). */
const zu_buffer *zu_mock_stream_written(const zu_stream *s);

/* Did the script run to completion? Catches tests that assert success while
 * silently leaving canned input unread. */
int zu_mock_stream_exhausted(const zu_stream *s);

#endif /* ZUHTTP_MOCK_STREAM_H */

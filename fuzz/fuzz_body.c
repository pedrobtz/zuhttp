/* Target 9 — the response body path (§27, §21, §40).
 *
 * New surface as of S17: zu_body.c streams wire bytes through an optional
 * inflater into a sink, and it is the code every response body passes
 * through. The §21.4 caps were already found wrong once here by fuzzing —
 * zu_inflate checked its limit AFTER appending a 16 KB chunk, so a 1 MB
 * max_decompressed_bytes delivered 1 MB + 16 KB — and S17 moved that logic
 * into a streaming loop, which is exactly when a limit check drifts.
 *
 * So the assertion is the limit itself: whatever the input, the SINK must
 * never receive more than max_body bytes. §40 calls that a bound, and a
 * bound a caller sizes memory from has to be exact rather than approximate.
 */
#include "zu_body.h"
#include "zu_sink.h"
#include "zu_mock_stream.h"
#include "zu_alloc.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BODY  (64u * 1024u)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    zu_mock_step step;
    zu_stream *s;
    zu_body_pipe p;
    zu_framing fr;
    zu_headers h;
    zu_error e;
    zu_sink *sink;
    uint8_t sel;
    int no_decode;

    if (size < 2 || size > (1u << 20)) return 0;

    /* First byte picks the shape: framing, encoding, and whether decoding is
     * on. One corpus then covers every combination the engine can build. */
    sel = data[0];
    data++; size--;

    zu_headers_init(&h);
    switch ((sel >> 2) & 3) {
        case 0: zu_headers_add_str(&h, "Content-Encoding", "gzip");    break;
        case 1: zu_headers_add_str(&h, "Content-Encoding", "deflate"); break;
        case 2: zu_headers_add_str(&h, "Content-Encoding", "br");      break;
        default: break;   /* identity */
    }
    no_decode = (sel >> 4) & 1;

    memset(&fr, 0, sizeof fr);
    fr.poolable = 1;
    switch (sel & 3) {
        case 0: fr.kind = ZU_FRAME_LENGTH; fr.length = size;     break;
        case 1: fr.kind = ZU_FRAME_LENGTH; fr.length = MAX_BODY * 4; break;
        case 2: fr.kind = ZU_FRAME_CHUNKED;                      break;
        default: fr.kind = ZU_FRAME_UNTIL_CLOSE;                 break;
    }

    step.kind = ZU_MOCK_DATA;
    step.data = (const char *)data;
    step.len  = size;
    step.code = ZU_OK;

    s = zu_mock_stream_new(&step, 1, 0, 0);
    if (!s) { zu_headers_free(&h); return 0; }

    sink = zu_sink_discard();
    if (!sink) { zu_stream_free(s); zu_headers_free(&h); return 0; }

    if (zu_body_pipe_init(&p, sink, &h, no_decode, MAX_BODY, &e) == ZU_OK) {
        (void)zu_body_read(s, &fr, &p, NULL, 0, MAX_BODY, zu_deadline_in(1000), &e);

        /* §40. Not "eventually noticed": a sink must never be handed a byte
         * past the cap, because the cap is what a caller sized a buffer or a
         * disk quota from. Overshooting by one read chunk is the bug this
         * target exists to catch. */
        if (sink->written > MAX_BODY) abort();
    }
    zu_body_pipe_free(&p);
    zu_sink_free(sink);
    zu_stream_free(s);
    zu_headers_free(&h);
    return 0;
}

/* Target 9 — the response body path (§27, §21, §40).
 *
 * zuh_body.c streams wire bytes through an optional inflater into a sink,
 * and every response body passes through it. Its first oracle was the §40
 * cap: whatever the input, the sink never receives more than max_body bytes.
 * That oracle catches a cap that overshoots and nothing else; a decoder that
 * hands the sink the wrong bytes, or a limit that means different things
 * under different framings, crashes nothing. Both happened (#210, #212), so
 * the target now compares runs that must agree (#227):
 *
 *   - READ SIZE. The same wire bytes read whole and one byte at a time both
 *     succeed, with the same body, or both fail. On a failure, what the
 *     whole read delivered is a prefix of what the byte-wise read did: a
 *     failed call delivers nothing of its own, so smaller reads can only have
 *     delivered more of the valid prefix, never different bytes. #210 handed
 *     the sink the raw framing bytes and fails this.
 *   - FRAMING. The input taken as a payload and sent as Content-Length, as
 *     chunked (re-encoded here, validly) and as close-delimited either all
 *     succeed with the same body or all fail. #212 refused under chunked
 *     framing what it accepted under Content-Length, and fails this.
 *
 * Two failures need not be the same failure. An input with two faults, a
 * bad gzip stream inside bad chunk framing, fails on whichever its reads
 * reach first: read whole, the framing is parsed before any byte is
 * inflated; byte by byte, the first chunk is inflated before the bad
 * framing arrives. The libFuzzer smoke found exactly that within seconds
 * of an oracle that compared codes (regress-227-two-faults).
 *
 * Option byte: bits 0-1 the framing of the first run (0 LENGTH = size,
 * 1 LENGTH oversized, 2 CHUNKED, 3 UNTIL_CLOSE); bits 2-3 the encoding
 * (0 gzip, 1 deflate, 2 br, 3 identity); bit 4 decoding off; bit 5 a tiny
 * max_body (8), so the cap can fall between the decoded and the compressed
 * size; bits 6-7 the chunk size of the re-encoding (1, 7, 300, 16384).
 */
#include "zuh_body.h"
#include "zuh_sink.h"
#include "zuh_mock_stream.h"
#include "zuh_alloc.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BODY   (64u * 1024u)
#define SMALL_BODY 8u
/* One byte per read costs a decoder call per byte; past this the read-size
 * oracle is skipped rather than slowing every other input down. */
#define BYTEWISE_MAX (16u * 1024u)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

typedef struct {
    zuh_code   rc;
    zuh_buffer out;
    uint64_t   written;
} run_result;

static void set_encoding(zuh_headers *h, uint8_t sel) {
    switch ((sel >> 2) & 3) {
        case 0: zuh_headers_add_str(h, "Content-Encoding", "gzip");    break;
        case 1: zuh_headers_add_str(h, "Content-Encoding", "deflate"); break;
        case 2: zuh_headers_add_str(h, "Content-Encoding", "br");      break;
        default: break;   /* identity */
    }
}

/* One body through the pipe into memory. 0 when the harness itself ran out
 * of memory, which says nothing about the code under test. */
static int run(const uint8_t *wire, size_t len, zuh_frame_kind kind, uint64_t length,
               uint8_t sel, size_t max_read, uint64_t max_body, run_result *res) {
    zuh_mock_step step;
    zuh_stream *s;
    zuh_body_pipe p;
    zuh_framing fr;
    zuh_headers h;
    zuh_error e;
    zuh_sink sink;

    memset(res, 0, sizeof *res);
    if (!zuh_buf_init(&res->out, 0, (size_t)-1)) return 0;
    zuh_sink_memory_init(&sink, &res->out);
    zuh_headers_init(&h);
    set_encoding(&h, sel);
    memset(&fr, 0, sizeof fr);
    fr.poolable = 1; fr.kind = kind; fr.length = length;
    step.kind = ZUH_MOCK_DATA; step.data = (const char *)wire; step.len = len;
    step.code = ZUH_OK;
    s = zuh_mock_stream_new(&step, 1, max_read, 0);
    if (!s) { zuh_headers_free(&h); zuh_buf_free(&res->out); return 0; }
    zuh_error_clear(&e);
    res->rc = zuh_body_pipe_init(&p, &sink, &h, (sel >> 4) & 1, max_body, &e);
    if (res->rc == ZUH_OK)
        res->rc = zuh_body_read(s, &fr, &p, NULL, 0, zuh_deadline_in(1000), &e);
    res->written = sink.written;
    zuh_body_pipe_free(&p);
    zuh_stream_free(s);
    zuh_headers_free(&h);
    return res->rc != ZUH_ERR_NOMEM;
}

static int same_bytes(const zuh_buffer *a, const zuh_buffer *b) {
    return a->len == b->len && (a->len == 0 || memcmp(a->data, b->data, a->len) == 0);
}

static int is_prefix(const zuh_buffer *a, const zuh_buffer *b) {
    return a->len <= b->len && (a->len == 0 || memcmp(a->data, b->data, a->len) == 0);
}

/* The payload as valid chunked framing, in pieces of `piece` bytes. */
static int chunk_encode(const uint8_t *d, size_t n, size_t piece, zuh_buffer *out) {
    size_t off = 0;
    char hex[24];
    while (off < n) {
        size_t k = n - off < piece ? n - off : piece;
        snprintf(hex, sizeof hex, "%lx\r\n", (unsigned long)k);
        if (!zuh_buf_append(out, hex, strlen(hex)) || !zuh_buf_append(out, d + off, k) ||
            !zuh_buf_append(out, "\r\n", 2))
            return 0;
        off += k;
    }
    return zuh_buf_append(out, "0\r\n\r\n", 5);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const size_t pieces[4] = { 1, 7, 300, 16384 };
    static const zuh_frame_kind kinds[4] = {
        ZUH_FRAME_LENGTH, ZUH_FRAME_LENGTH, ZUH_FRAME_CHUNKED, ZUH_FRAME_UNTIL_CLOSE };
    run_result whole, bytewise, alt[3];
    zuh_frame_kind kind;
    uint64_t length, max_body;
    zuh_buffer enc;
    uint8_t sel;
    size_t piece;
    int k, ok;

    if (size < 2 || size > (1u << 20)) return 0;
    sel = data[0];
    data++; size--;
    max_body = (sel & 0x20) ? SMALL_BODY : MAX_BODY;
    kind = kinds[sel & 3];
    length = (sel & 3) == 1 ? (uint64_t)MAX_BODY * 4 : (uint64_t)size;

    /* §40: never a byte past the cap, whatever the input. */
    if (!run(data, size, kind, length, sel, 0, max_body, &whole)) {
        zuh_buf_free(&whole.out);
        return 0;
    }
    if (whole.written > max_body) abort();

    /* Read size. Not for the oversized LENGTH, whose end is a truncation the
     * two read patterns reach after different amounts of work. */
    memset(&bytewise, 0, sizeof bytewise);
    if ((sel & 3) != 1 && size <= BYTEWISE_MAX &&
        run(data, size, kind, length, sel, 1, max_body, &bytewise)) {
        if ((bytewise.rc == ZUH_OK) != (whole.rc == ZUH_OK)) abort();
        if (whole.rc == ZUH_OK ? !same_bytes(&whole.out, &bytewise.out)
                               : !is_prefix(&whole.out, &bytewise.out))
            abort();
    }
    zuh_buf_free(&bytewise.out);

    /* Framing: the input as a payload, three ways. Five bytes of framing per
     * 1-byte chunk is 83% overhead, which picohttpparser refuses once it
     * passes 100 KB (§18.1): a real limit, so 1-byte chunks are kept to
     * payloads that stay under it. */
    piece = pieces[(sel >> 6) & 3];
    if (piece == 1 && size > 16384) piece = 7;
    memset(alt, 0, sizeof alt);
    ok = zuh_buf_init(&enc, 0, (size_t)-1) &&
         chunk_encode(data, size, piece, &enc) &&
         run(data, size, ZUH_FRAME_LENGTH, (uint64_t)size, sel, 0, max_body, &alt[0]) &&
         run((const uint8_t *)enc.data, enc.len, ZUH_FRAME_CHUNKED, 0, sel, 0, max_body, &alt[1]) &&
         run(data, size, ZUH_FRAME_UNTIL_CLOSE, 0, sel, 0, max_body, &alt[2]);
    if (ok) {
        for (k = 1; k < 3; k++) {
            if ((alt[k].rc == ZUH_OK) != (alt[0].rc == ZUH_OK)) abort();
            if (alt[0].rc == ZUH_OK && !same_bytes(&alt[k].out, &alt[0].out)) abort();
        }
    }
    for (k = 0; k < 3; k++) zuh_buf_free(&alt[k].out);
    zuh_buf_free(&enc);
    zuh_buf_free(&whole.out);
    return 0;
}

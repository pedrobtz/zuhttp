/* zuhttp — body sinks (design §27).
 *
 * §27 asks for "one core body-sink abstraction" powering in-memory responses,
 * file downloads, R connections and callback streaming. This is it, and the
 * engine knows nothing else about where a body goes.
 *
 * The write function is §27's `zu_body_sink` signature. What is added here is
 * a LIFECYCLE, because §27.1's atomicity requirement is not expressible in a
 * write callback alone: the file sink writes to a temporary file beside the
 * destination and renames only on success, so it needs to be told whether the
 * transfer ended well. Hence finish/abort. A sink that is destroyed without
 * finish() must leave nothing behind at the target path — that is §27.1's
 * "an interrupted or failed download never leaves a truncated file", and it
 * is the reason abort() exists rather than being implied by destroy().
 */
#ifndef ZUHTTP_SINK_H
#define ZUHTTP_SINK_H

#include "zu_platform.h"
#include "zu_error.h"
#include "zu_buffer.h"

typedef struct zu_sink zu_sink;

struct zu_sink {
    /* §27's contract. Returns ZU_OK, or an error code that stops the
     * transfer. A sink may also return ZU_ERR_CANCELLED to stop cleanly —
     * §27.2's "sentinel return" — which makes the connection unpoolable
     * (§26.3) without being reported as a failure. */
    zu_code (*write)(zu_sink *s, const unsigned char *data, size_t n,
                     zu_error *err);

    /* Commit. Called exactly once, only when the body arrived whole. */
    zu_code (*finish)(zu_sink *s, zu_error *err);

    /* Discard partial work. Called instead of finish on any failure,
     * cancellation or interrupt. Must be safe to call after a partial write
     * and must not report errors of its own — the caller already has one. */
    void    (*abort)(zu_sink *s);

    void    (*destroy)(zu_sink *s);

    void   *ctx;
    uint64_t written;      /* bytes handed to the sink, post-decode */

    /* §27.2's sentinel: the sink asked to stop, and that is not a failure.
     * A flag rather than a distinct return code because every layer between
     * here and the engine would otherwise have to forward it, and the one
     * that forgot would turn a clean stop into an error. */
    int      stopped;
};

/* Convenience wrappers that tolerate a NULL sink, so the engine's error paths
 * do not each need a null check. */
zu_code zu_sink_write(zu_sink *s, const void *data, size_t n, zu_error *err);
zu_code zu_sink_finish(zu_sink *s, zu_error *err);
void    zu_sink_abort(zu_sink *s);
void    zu_sink_free(zu_sink *s);

/* --- built-ins -----------------------------------------------------------
 *
 * Each returns NULL on allocation failure. Ownership passes to the caller,
 * who frees with zu_sink_free().
 */

/* Appends to `out`, which the caller owns and must have initialised. This is
 * the default and reproduces the pre-S17 behaviour exactly.
 *
 * The _init form fills a caller-provided struct and allocates nothing, which
 * is what the engine uses: a heap sink would need freeing on each of the
 * request loop's dozen error paths, and that is the kind of bookkeeping that
 * leaks the first time someone adds a thirteenth. */
void     zu_sink_memory_init(zu_sink *s, zu_buffer *out);
zu_sink *zu_sink_memory(zu_buffer *out);

/* Counts bytes and discards them. §19.5 drains intermediate redirect bodies
 * through one of these so the connection stays poolable without the body
 * ever reaching the caller's sink. */
zu_sink *zu_sink_discard(void);

/* §27.1 atomic file sink: writes to a temporary file in the SAME directory as
 * `path` — same directory because rename() is only atomic within a
 * filesystem — and renames on finish(). abort() closes and unlinks. */
zu_sink *zu_sink_file(const char *path, zu_error *err);

/* The temporary path a file sink is currently writing to, for tests. NULL for
 * any other sink kind. */
const char *zu_sink_file_tmp_path(const zu_sink *s);

#endif /* ZUHTTP_SINK_H */

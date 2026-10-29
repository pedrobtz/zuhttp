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

#include "zuh_platform.h"
#include "zuh_error.h"
#include "zuh_buffer.h"

typedef struct zuh_sink zuh_sink;

struct zuh_sink {
    /* §27's contract. Returns ZUH_OK, or an error code that stops the
     * transfer. A sink may also return ZUH_ERR_CANCELLED to stop cleanly —
     * §27.2's "sentinel return" — which makes the connection unpoolable
     * (§26.3) without being reported as a failure. */
    zuh_code (*write)(zuh_sink *s, const unsigned char *data, size_t n,
                     zuh_error *err);

    /* Commit. Called exactly once, only when the body arrived whole. */
    zuh_code (*finish)(zuh_sink *s, zuh_error *err);

    /* Discard partial work. Called instead of finish on any failure,
     * cancellation or interrupt. Must be safe to call after a partial write
     * and must not report errors of its own — the caller already has one. */
    void    (*abort)(zuh_sink *s);

    void    (*destroy)(zuh_sink *s);

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
zuh_code zuh_sink_write(zuh_sink *s, const void *data, size_t n, zuh_error *err);
zuh_code zuh_sink_finish(zuh_sink *s, zuh_error *err);
void    zuh_sink_abort(zuh_sink *s);
void    zuh_sink_free(zuh_sink *s);

/* --- built-ins -----------------------------------------------------------
 *
 * Each returns NULL on allocation failure. Ownership passes to the caller,
 * who frees with zuh_sink_free().
 */

/* Appends to `out`, which the caller owns and must have initialised. This is
 * the default and reproduces the pre-S17 behaviour exactly.
 *
 * The _init form fills a caller-provided struct and allocates nothing, which
 * is what the engine uses: a heap sink would need freeing on each of the
 * request loop's dozen error paths, and that is the kind of bookkeeping that
 * leaks the first time someone adds a thirteenth. */
void     zuh_sink_memory_init(zuh_sink *s, zuh_buffer *out);
zuh_sink *zuh_sink_memory(zuh_buffer *out);

/* Counts bytes and discards them. §19.5 drains intermediate redirect bodies
 * through one of these so the connection stays poolable without the body
 * ever reaching the caller's sink. */
zuh_sink *zuh_sink_discard(void);

/* §27.1 atomic file sink: writes to a temporary file in the SAME directory as
 * `path` — same directory because rename() is only atomic within a
 * filesystem — and renames on finish(). abort() closes and unlinks. */
zuh_sink *zuh_sink_file(const char *path, zuh_error *err);

/* The temporary path a file sink is currently writing to, for tests. NULL for
 * any other sink kind. */
const char *zuh_sink_file_tmp_path(const zuh_sink *s);

#endif /* ZUHTTP_SINK_H */

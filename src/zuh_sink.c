/* zuh_sink.c uses unistd.h for the temp-file path, so it needs the same
 * feature-test preamble as zuh_net.c and zuh_time.c: -std=c99 defines
 * __STRICT_ANSI__, which makes glibc hide POSIX declarations. tools/check-
 * feature-macros enforces this, and the rule exists because the class has
 * bitten twice — once silently, when zuh_now_ms() returned 0 forever on Linux
 * and no deadline expired. MUST precede every system header. */
#if !defined(_WIN32)
#  if defined(__APPLE__)
#    define _DARWIN_C_SOURCE
#  else
#    define _POSIX_C_SOURCE 200112L
#  endif
#endif

#include "zuh_sink.h"
#include "zuh_alloc.h"
#include "zuh_fork.h"   /* zuh_pid_current, for a temp name unique across processes */
#include <stdio.h>
#include <string.h>

#include <errno.h>
#include <fcntl.h>
#if defined(ZUH_POSIX)
#  include <unistd.h>
#endif
#if defined(_WIN32)
#  include <io.h>
#  include <sys/stat.h>
#  include <windows.h>
#endif

zuh_code zuh_sink_write(zuh_sink *s, const void *data, size_t n, zuh_error *err) {
    zuh_code rc;
    if (!s || !s->write) return ZUH_OK;
    if (n == 0) return ZUH_OK;
    rc = s->write(s, (const unsigned char *)data, n, err);
    if (rc == ZUH_OK) s->written += (uint64_t)n;
    return rc;
}

zuh_code zuh_sink_finish(zuh_sink *s, zuh_error *err) {
    if (!s || !s->finish) return ZUH_OK;
    return s->finish(s, err);
}

void zuh_sink_abort(zuh_sink *s) {
    if (s && s->abort) s->abort(s);
}

void zuh_sink_free(zuh_sink *s) {
    if (!s) return;
    if (s->destroy) s->destroy(s);
    zuh_free(s);
}

/* --- memory -------------------------------------------------------------- */

static zuh_code mem_write(zuh_sink *s, const unsigned char *d, size_t n,
                         zuh_error *err) {
    zuh_buffer *b = (zuh_buffer *)s->ctx;
    if (!zuh_buf_append(b, d, n)) {
        zuh_error_set(err, ZUH_ERR_NOMEM, ZUH_PHASE_READ,
                     "out of memory buffering the response body");
        return ZUH_ERR_NOMEM;
    }
    return ZUH_OK;
}

void zuh_sink_memory_init(zuh_sink *s, zuh_buffer *out) {
    if (!s) return;
    memset(s, 0, sizeof *s);
    s->write = mem_write;
    s->ctx   = out;
}

zuh_sink *zuh_sink_memory(zuh_buffer *out) {
    zuh_sink *s;
    if (!out) return NULL;
    s = (zuh_sink *)zuh_calloc(1, sizeof *s);
    if (!s) return NULL;
    zuh_sink_memory_init(s, out);
    return s;
}

/* --- discard ------------------------------------------------------------- */

static zuh_code discard_write(zuh_sink *s, const unsigned char *d, size_t n,
                             zuh_error *err) {
    ZUH_UNUSED(s); ZUH_UNUSED(d); ZUH_UNUSED(n); ZUH_UNUSED(err);
    return ZUH_OK;
}

zuh_sink *zuh_sink_discard(void) {
    zuh_sink *s = (zuh_sink *)zuh_calloc(1, sizeof *s);
    if (!s) return NULL;
    s->write = discard_write;
    return s;
}

/* --- file (§27.1) --------------------------------------------------------
 *
 * The temporary file lives in the destination's own directory, not in
 * tmpdir(): rename() is atomic only within a filesystem, and a /tmp on a
 * different mount turns the commit into a copy that can fail halfway — which
 * is the exact failure §27.1 exists to prevent.
 */

typedef struct {
    FILE *fp;
    char *tmp;      /* path being written */
    char *final;    /* path to rename to on finish */
    int   committed;
} file_ctx;

static void file_cleanup(file_ctx *c) {
    if (!c) return;
    if (c->fp) { fclose(c->fp); c->fp = NULL; }
    if (c->tmp && !c->committed) remove(c->tmp);
}

static zuh_code file_write(zuh_sink *s, const unsigned char *d, size_t n,
                          zuh_error *err) {
    file_ctx *c = (file_ctx *)s->ctx;
    if (!c->fp) {
        zuh_error_set(err, ZUH_ERR_IO, ZUH_PHASE_READ, "download file is not open");
        return ZUH_ERR_IO;
    }
    if (fwrite(d, 1, n, c->fp) != n) {
        zuh_error_set(err, ZUH_ERR_IO, ZUH_PHASE_READ,
                     "short write to %s", c->tmp ? c->tmp : "(download)");
        return ZUH_ERR_IO;
    }
    return ZUH_OK;
}

static zuh_code file_finish(zuh_sink *s, zuh_error *err) {
    file_ctx *c = (file_ctx *)s->ctx;
    if (!c->fp) return ZUH_OK;
    /* Flush before rename, or the rename can publish a file whose tail is
     * still in a stdio buffer. */
    {
        /* Both, always: a failed flush must still close the stream, which the
         * short-circuit form `fflush() || fclose()` skipped. */
        int flushed = fflush(c->fp) == 0;
        int closed  = fclose(c->fp) == 0;
        if (flushed && closed) goto flushed_ok;
        c->fp = NULL;
        zuh_error_set(err, ZUH_ERR_IO, ZUH_PHASE_READ,
                     "could not flush %s", c->tmp ? c->tmp : "(download)");
        return ZUH_ERR_IO;
    }
flushed_ok:
    c->fp = NULL;
    /* D-53: the previous file is replaced only by the rename. It used to be
     * removed first, on every platform, so a rename that then failed left no
     * download at all, and even a successful one opened a window with no
     * file. POSIX rename() replaces atomically; Windows needs MoveFileEx to
     * replace, since its rename() refuses an existing target. */
#if defined(_WIN32)
    if (!MoveFileExA(c->tmp, c->final, MOVEFILE_REPLACE_EXISTING)) {
#else
    if (rename(c->tmp, c->final) != 0) {
#endif
        zuh_error_set(err, ZUH_ERR_IO, ZUH_PHASE_READ,
                     "could not move the download into place at %s", c->final);
        return ZUH_ERR_IO;
    }
    c->committed = 1;
    return ZUH_OK;
}

static void file_abort(zuh_sink *s) {
    file_cleanup((file_ctx *)s->ctx);
}

static void file_destroy(zuh_sink *s) {
    file_ctx *c = (file_ctx *)s->ctx;
    if (!c) return;
    file_cleanup(c);
    zuh_free(c->tmp);
    zuh_free(c->final);
    zuh_free(c);
}

zuh_sink *zuh_sink_file(const char *path, zuh_error *err) {
    zuh_sink *s = NULL;
    file_ctx *c = NULL;
    size_t n, tmp_len;

    if (!path || !*path) {
        zuh_error_set(err, ZUH_ERR_IO, ZUH_PHASE_NONE, "empty download path");
        return NULL;
    }
    n = strlen(path);

    s = (zuh_sink *)zuh_calloc(1, sizeof *s);
    c = (file_ctx *)zuh_calloc(1, sizeof *c);
    if (!s || !c) goto nomem;

    c->final = (char *)zuh_alloc(n + 1);
    /* ".zudl", a long's digits, ".NN" for a taken name, and NUL: 29 at
     * most, within the 32 allowed. The first draft allowed 16,
     * which is not enough for a 20-digit pid — and snprintf, not sprintf:
     * CRAN forbids the latter outright, and here it would have been a real
     * overflow rather than a policy violation. */
    tmp_len  = n + 32;
    c->tmp   = (char *)zuh_alloc(tmp_len);
    if (!c->final || !c->tmp) goto nomem;
    memcpy(c->final, path, n + 1);
    /* Same directory as the destination (see above). The name is
     * predictable, so it is CREATED, exclusively: fopen("wb") truncated a
     * file already there and followed a symlink planted there, writing the
     * download wherever it pointed. O_EXCL fails on any existing name, a
     * dangling or live symlink included, and the sink tries the next one —
     * which is also what keeps two downloads to one path apart. */
    {
        unsigned attempt;
        int fd = -1;
        for (attempt = 0; attempt < 100 && fd < 0; attempt++) {
            if (attempt == 0)
                snprintf(c->tmp, tmp_len, "%s.zudl%ld", path, zuh_pid_current());
            else
                snprintf(c->tmp, tmp_len, "%s.zudl%ld.%u", path, zuh_pid_current(),
                         attempt);
#if defined(_WIN32)
            fd = _open(c->tmp, _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY,
                       _S_IREAD | _S_IWRITE);
#else
            fd = open(c->tmp, O_WRONLY | O_CREAT | O_EXCL, 0666);
#endif
            if (fd < 0 && errno != EEXIST) break;
        }
        if (fd >= 0) {
#if defined(_WIN32)
            c->fp = _fdopen(fd, "wb");
            if (!c->fp) _close(fd);
#else
            c->fp = fdopen(fd, "wb");
            if (!c->fp) close(fd);
#endif
            if (!c->fp) remove(c->tmp);
        }
    }
    if (!c->fp) {
        zuh_error_set(err, ZUH_ERR_IO, ZUH_PHASE_NONE,
                     "cannot create a temporary file beside %s", path);
        goto fail;
    }

    s->write   = file_write;
    s->finish  = file_finish;
    s->abort   = file_abort;
    s->destroy = file_destroy;
    s->ctx     = c;
    return s;

nomem:
    zuh_error_set(err, ZUH_ERR_NOMEM, ZUH_PHASE_NONE, "out of memory");
fail:
    if (c) { zuh_free(c->tmp); zuh_free(c->final); zuh_free(c); }
    zuh_free(s);
    return NULL;
}

const char *zuh_sink_file_tmp_path(const zuh_sink *s) {
    if (!s || s->write != file_write) return NULL;
    return ((const file_ctx *)s->ctx)->tmp;
}

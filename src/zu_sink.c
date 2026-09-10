/* zu_sink.c uses unistd.h for the temp-file path, so it needs the same
 * feature-test preamble as zu_net.c and zu_time.c: -std=c99 defines
 * __STRICT_ANSI__, which makes glibc hide POSIX declarations. tools/check-
 * feature-macros enforces this, and the rule exists because the class has
 * bitten twice — once silently, when zu_now_ms() returned 0 forever on Linux
 * and no deadline expired. MUST precede every system header. */
#if !defined(_WIN32)
#  if defined(__APPLE__)
#    define _DARWIN_C_SOURCE
#  else
#    define _POSIX_C_SOURCE 200112L
#  endif
#endif

#include "zu_sink.h"
#include "zu_alloc.h"
#include "zu_fork.h"   /* zu_pid_current, for a temp name unique across processes */
#include <stdio.h>
#include <string.h>

#if defined(ZU_POSIX)
#  include <unistd.h>
#endif

zu_code zu_sink_write(zu_sink *s, const void *data, size_t n, zu_error *err) {
    zu_code rc;
    if (!s || !s->write) return ZU_OK;
    if (n == 0) return ZU_OK;
    rc = s->write(s, (const unsigned char *)data, n, err);
    if (rc == ZU_OK) s->written += (uint64_t)n;
    return rc;
}

zu_code zu_sink_finish(zu_sink *s, zu_error *err) {
    if (!s || !s->finish) return ZU_OK;
    return s->finish(s, err);
}

void zu_sink_abort(zu_sink *s) {
    if (s && s->abort) s->abort(s);
}

void zu_sink_free(zu_sink *s) {
    if (!s) return;
    if (s->destroy) s->destroy(s);
    zu_free(s);
}

/* --- memory -------------------------------------------------------------- */

static zu_code mem_write(zu_sink *s, const unsigned char *d, size_t n,
                         zu_error *err) {
    zu_buffer *b = (zu_buffer *)s->ctx;
    if (!zu_buf_append(b, d, n)) {
        zu_error_set(err, ZU_ERR_NOMEM, ZU_PHASE_READ,
                     "out of memory buffering the response body");
        return ZU_ERR_NOMEM;
    }
    return ZU_OK;
}

void zu_sink_memory_init(zu_sink *s, zu_buffer *out) {
    if (!s) return;
    memset(s, 0, sizeof *s);
    s->write = mem_write;
    s->ctx   = out;
}

zu_sink *zu_sink_memory(zu_buffer *out) {
    zu_sink *s;
    if (!out) return NULL;
    s = (zu_sink *)zu_calloc(1, sizeof *s);
    if (!s) return NULL;
    zu_sink_memory_init(s, out);
    return s;
}

/* --- discard ------------------------------------------------------------- */

static zu_code discard_write(zu_sink *s, const unsigned char *d, size_t n,
                             zu_error *err) {
    ZU_UNUSED(s); ZU_UNUSED(d); ZU_UNUSED(n); ZU_UNUSED(err);
    return ZU_OK;
}

zu_sink *zu_sink_discard(void) {
    zu_sink *s = (zu_sink *)zu_calloc(1, sizeof *s);
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

static zu_code file_write(zu_sink *s, const unsigned char *d, size_t n,
                          zu_error *err) {
    file_ctx *c = (file_ctx *)s->ctx;
    if (!c->fp) {
        zu_error_set(err, ZU_ERR_IO, ZU_PHASE_READ, "download file is not open");
        return ZU_ERR_IO;
    }
    if (fwrite(d, 1, n, c->fp) != n) {
        zu_error_set(err, ZU_ERR_IO, ZU_PHASE_READ,
                     "short write to %s", c->tmp ? c->tmp : "(download)");
        return ZU_ERR_IO;
    }
    return ZU_OK;
}

static zu_code file_finish(zu_sink *s, zu_error *err) {
    file_ctx *c = (file_ctx *)s->ctx;
    if (!c->fp) return ZU_OK;
    /* Flush before rename, or the rename can publish a file whose tail is
     * still in a stdio buffer. */
    if (fflush(c->fp) != 0 || fclose(c->fp) != 0) {
        c->fp = NULL;
        zu_error_set(err, ZU_ERR_IO, ZU_PHASE_READ,
                     "could not flush %s", c->tmp ? c->tmp : "(download)");
        return ZU_ERR_IO;
    }
    c->fp = NULL;
    /* rename() refuses to replace an existing file on Windows, so the target
     * is removed first. The window this opens is accepted: the alternative,
     * MoveFileEx, is not available through plain C89 stdio, and the caller
     * asked for the file to be replaced. */
    remove(c->final);
    if (rename(c->tmp, c->final) != 0) {
        zu_error_set(err, ZU_ERR_IO, ZU_PHASE_READ,
                     "could not move the download into place at %s", c->final);
        return ZU_ERR_IO;
    }
    c->committed = 1;
    return ZU_OK;
}

static void file_abort(zu_sink *s) {
    file_cleanup((file_ctx *)s->ctx);
}

static void file_destroy(zu_sink *s) {
    file_ctx *c = (file_ctx *)s->ctx;
    if (!c) return;
    file_cleanup(c);
    zu_free(c->tmp);
    zu_free(c->final);
    zu_free(c);
}

zu_sink *zu_sink_file(const char *path, zu_error *err) {
    zu_sink *s = NULL;
    file_ctx *c = NULL;
    size_t n, tmp_len;

    if (!path || !*path) {
        zu_error_set(err, ZU_ERR_IO, ZU_PHASE_NONE, "empty download path");
        return NULL;
    }
    n = strlen(path);

    s = (zu_sink *)zu_calloc(1, sizeof *s);
    c = (file_ctx *)zu_calloc(1, sizeof *c);
    if (!s || !c) goto nomem;

    c->final = (char *)zu_alloc(n + 1);
    /* ".zudl" plus a long's digits plus NUL. The first draft allowed 16,
     * which is not enough for a 20-digit pid — and snprintf, not sprintf:
     * CRAN forbids the latter outright, and here it would have been a real
     * overflow rather than a policy violation. */
    tmp_len  = n + 32;
    c->tmp   = (char *)zu_alloc(tmp_len);
    if (!c->final || !c->tmp) goto nomem;
    memcpy(c->final, path, n + 1);
    /* Same directory as the destination, and a name unlikely to collide with
     * a real file the caller cares about. */
    snprintf(c->tmp, tmp_len, "%s.zudl%ld", path, zu_pid_current());

    c->fp = fopen(c->tmp, "wb");
    if (!c->fp) {
        zu_error_set(err, ZU_ERR_IO, ZU_PHASE_NONE,
                     "cannot write to %s", c->tmp);
        goto fail;
    }

    s->write   = file_write;
    s->finish  = file_finish;
    s->abort   = file_abort;
    s->destroy = file_destroy;
    s->ctx     = c;
    return s;

nomem:
    zu_error_set(err, ZU_ERR_NOMEM, ZU_PHASE_NONE, "out of memory");
fail:
    if (c) { zu_free(c->tmp); zu_free(c->final); zu_free(c); }
    zu_free(s);
    return NULL;
}

const char *zu_sink_file_tmp_path(const zu_sink *s) {
    if (!s || s->write != file_write) return NULL;
    return ((const file_ctx *)s->ctx)->tmp;
}

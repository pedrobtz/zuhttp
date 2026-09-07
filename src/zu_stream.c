#include "zu_stream.h"

zu_ssize zu_stream_read(zu_stream *s, void *buf, size_t n, zu_deadline d, zu_error *err) {
    if (!s || !s->vt || !s->vt->read) {
        zu_error_set(err, ZU_ERR_IO, ZU_PHASE_READ, "stream is not readable");
        return -1;
    }
    if (n > (size_t)ZU_SSIZE_MAX) n = (size_t)ZU_SSIZE_MAX;
    return s->vt->read(s, buf, n, d, err);
}

zu_ssize zu_stream_write(zu_stream *s, const void *buf, size_t n, zu_deadline d, zu_error *err) {
    if (!s || !s->vt || !s->vt->write) {
        zu_error_set(err, ZU_ERR_IO, ZU_PHASE_WRITE, "stream is not writable");
        return -1;
    }
    if (n > (size_t)ZU_SSIZE_MAX) n = (size_t)ZU_SSIZE_MAX;
    return s->vt->write(s, buf, n, d, err);
}

void zu_stream_close(zu_stream *s) {
    if (s && s->vt && s->vt->close) s->vt->close(s);
}

void zu_stream_free(zu_stream *s) {
    if (!s) return;
    if (s->vt && s->vt->destroy) { s->vt->destroy(s); return; }
    /* A stream with no destroy still gets closed, so a missing hook leaks
     * memory rather than a file descriptor. */
    zu_stream_close(s);
}

const char *zu_stream_name(const zu_stream *s) {
    if (!s || !s->vt || !s->vt->name) return "unknown";
    return s->vt->name;
}

int zu_stream_write_all(zu_stream *s, const void *buf, size_t n, zu_deadline d, zu_error *err) {
    const unsigned char *p = (const unsigned char *)buf;
    size_t off = 0;
    while (off < n) {
        zu_ssize w;
        if (zu_deadline_expired(d)) {
            zu_error_set(err, ZU_ERR_TIMEOUT, ZU_PHASE_WRITE, "write deadline exceeded");
            return 0;
        }
        w = zu_stream_write(s, p + off, n - off, d, err);
        if (w > 0) { off += (size_t)w; continue; }
        if (w == 0) {
            zu_error_set(err, ZU_ERR_CLOSED, ZU_PHASE_WRITE, "connection closed while writing");
            return 0;
        }
        if (err && err->code == ZU_ERR_WOULDBLOCK) { zu_error_clear(err); continue; }
        return 0;
    }
    return 1;
}

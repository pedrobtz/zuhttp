#include "zuh_stream.h"

zuh_ssize zuh_stream_read(zuh_stream *s, void *buf, size_t n, zuh_deadline d, zuh_error *err) {
    if (!s || !s->vt || !s->vt->read) {
        zuh_error_set(err, ZUH_ERR_IO, ZUH_PHASE_READ, "stream is not readable");
        return -1;
    }
    if (n > (size_t)ZUH_SSIZE_MAX) n = (size_t)ZUH_SSIZE_MAX;
    return s->vt->read(s, buf, n, d, err);
}

zuh_ssize zuh_stream_write(zuh_stream *s, const void *buf, size_t n, zuh_deadline d, zuh_error *err) {
    if (!s || !s->vt || !s->vt->write) {
        zuh_error_set(err, ZUH_ERR_IO, ZUH_PHASE_WRITE, "stream is not writable");
        return -1;
    }
    if (n > (size_t)ZUH_SSIZE_MAX) n = (size_t)ZUH_SSIZE_MAX;
    return s->vt->write(s, buf, n, d, err);
}

void zuh_stream_close(zuh_stream *s) {
    if (s && s->vt && s->vt->close) s->vt->close(s);
}

void zuh_stream_free(zuh_stream *s) {
    if (!s) return;
    if (s->vt && s->vt->destroy) { s->vt->destroy(s); return; }
    /* A stream with no destroy still gets closed, so a missing hook leaks
     * memory rather than a file descriptor. */
    zuh_stream_close(s);
}

int zuh_stream_readable(zuh_stream *s, int timeout_ms) {
    if (!s || !s->vt || !s->vt->readable) return -1;
    return s->vt->readable(s, timeout_ms);
}

const char *zuh_stream_name(const zuh_stream *s) {
    if (!s || !s->vt || !s->vt->name) return "unknown";
    return s->vt->name;
}

int zuh_stream_write_all(zuh_stream *s, const void *buf, size_t n, zuh_deadline d, zuh_error *err) {
    const unsigned char *p = (const unsigned char *)buf;
    size_t off = 0;
    while (off < n) {
        zuh_ssize w;
        if (zuh_deadline_expired(d)) {
            zuh_error_set(err, ZUH_ERR_TIMEOUT, ZUH_PHASE_WRITE, "write deadline exceeded");
            return 0;
        }
        w = zuh_stream_write(s, p + off, n - off, d, err);
        if (w > 0) { off += (size_t)w; continue; }
        if (w == 0) {
            zuh_error_set(err, ZUH_ERR_CLOSED, ZUH_PHASE_WRITE, "connection closed while writing");
            return 0;
        }
        if (err && err->code == ZUH_ERR_WOULDBLOCK) { zuh_error_clear(err); continue; }
        return 0;
    }
    return 1;
}

#include "zu_mock_stream.h"
#include "zu_alloc.h"
#include <string.h>

typedef struct {
    const zu_mock_step *steps;
    size_t              nsteps;
    size_t              step;       /* current step index */
    size_t              off;        /* bytes consumed within the current step */
    size_t              max_read;
    size_t              max_write;
    int                 failed;     /* sticky: ZU_MOCK_ERROR was reached */
    zu_code             fail_code;
    zu_buffer           written;
    void               *owned;      /* script allocated on our behalf, if any */
} mock_impl;

static zu_ssize mock_read(zu_stream *s, void *buf, size_t n, zu_deadline d, zu_error *err) {
    mock_impl *m = (mock_impl *)s->impl;
    ZU_UNUSED(d);

    if (m->failed) {
        zu_error_set(err, m->fail_code, ZU_PHASE_READ, "mock stream error");
        return -1;
    }
    if (n == 0) return 0;

    while (m->step < m->nsteps) {
        const zu_mock_step *st = &m->steps[m->step];

        switch (st->kind) {
            case ZU_MOCK_DATA: {
                size_t avail = st->len - m->off;
                size_t give;
                if (avail == 0) { m->step++; m->off = 0; continue; }
                give = n < avail ? n : avail;
                if (m->max_read && give > m->max_read) give = m->max_read;
                memcpy(buf, (const unsigned char *)st->data + m->off, give);
                m->off += give;
                if (m->off == st->len) { m->step++; m->off = 0; }
                return (zu_ssize)give;
            }
            case ZU_MOCK_WOULDBLOCK:
                m->step++; m->off = 0;
                zu_error_set(err, ZU_ERR_WOULDBLOCK, ZU_PHASE_READ, "mock would block");
                return -1;

            case ZU_MOCK_ERROR:
                m->failed = 1;
                m->fail_code = st->code ? st->code : ZU_ERR_IO;
                zu_error_set(err, m->fail_code, ZU_PHASE_READ, "mock stream error");
                return -1;

            case ZU_MOCK_EOF:
                return 0;
        }
    }
    return 0;   /* script exhausted == orderly close */
}

static zu_ssize mock_write(zu_stream *s, const void *buf, size_t n, zu_deadline d, zu_error *err) {
    mock_impl *m = (mock_impl *)s->impl;
    size_t take = n;
    ZU_UNUSED(d);

    if (m->max_write && take > m->max_write) take = m->max_write;
    if (take == 0) return 0;
    if (!zu_buf_append(&m->written, buf, take)) {
        zu_error_set(err, ZU_ERR_NOMEM, ZU_PHASE_WRITE, "mock write buffer exhausted");
        return -1;
    }
    return (zu_ssize)take;
}

static void mock_close(zu_stream *s) { ZU_UNUSED(s); }

static const zu_stream_vtable k_mock_vt = {
    "mock", mock_read, mock_write, mock_close
};

zu_stream *zu_mock_stream_new(const zu_mock_step *steps, size_t nsteps,
                              size_t max_read, size_t max_write) {
    zu_stream *s = (zu_stream *)zu_calloc(1, sizeof *s);
    mock_impl *m;
    if (!s) return NULL;
    m = (mock_impl *)zu_calloc(1, sizeof *m);
    if (!m) { zu_free(s); return NULL; }

    m->steps = steps; m->nsteps = nsteps;
    m->max_read = max_read; m->max_write = max_write;
    if (!zu_buf_init(&m->written, 256, 0)) { zu_free(m); zu_free(s); return NULL; }

    s->vt = &k_mock_vt;
    s->impl = m;
    return s;
}

zu_stream *zu_mock_stream_from_bytes(const void *data, size_t len, size_t max_read) {
    /* The caller has no script to keep alive, so the stream owns a one-step
     * one and releases it in zu_mock_stream_free. */
    zu_mock_step *step = (zu_mock_step *)zu_calloc(1, sizeof *step);
    zu_stream *s;
    if (!step) return NULL;
    step->kind = ZU_MOCK_DATA;
    step->data = data;
    step->len  = len;

    s = zu_mock_stream_new(step, 1, max_read, 0);
    if (!s) { zu_free(step); return NULL; }
    ((mock_impl *)s->impl)->owned = step;
    return s;
}

void zu_mock_stream_free(zu_stream *s) {
    mock_impl *m;
    if (!s) return;
    m = (mock_impl *)s->impl;
    if (m) { zu_buf_free(&m->written); zu_free(m->owned); zu_free(m); }
    zu_free(s);
}

const zu_buffer *zu_mock_stream_written(const zu_stream *s) {
    if (!s || !s->impl) return NULL;
    return &((mock_impl *)s->impl)->written;
}

int zu_mock_stream_exhausted(const zu_stream *s) {
    const mock_impl *m;
    if (!s || !s->impl) return 0;
    m = (const mock_impl *)s->impl;
    return m->step >= m->nsteps;
}

#include "zu_test.h"
#include "zu_mock_stream.h"
#include "zu_alloc.h"
#include <string.h>

void suite_stream(void);

static const char RESP[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";

/* Read until EOF, returning total bytes and tolerating WOULDBLOCK. */
static size_t drain(zu_stream *s, char *out, size_t cap, int *wouldblocks) {
    zu_error err;
    size_t got = 0;
    zu_deadline d = zu_deadline_never();
    zu_error_clear(&err);
    for (;;) {
        zu_ssize n = zu_stream_read(s, out + got, cap - got, d, &err);
        if (n > 0) { got += (size_t)n; continue; }
        if (n == 0) break;
        if (err.code == ZU_ERR_WOULDBLOCK) {
            if (wouldblocks) (*wouldblocks)++;
            zu_error_clear(&err);
            continue;
        }
        break;
    }
    return got;
}

void suite_stream(void) {
    char buf[256];

    ZU_CASE("a whole response arrives in one read");
    {
        zu_stream *s = zu_mock_stream_from_bytes(RESP, sizeof RESP - 1, 0);
        size_t n = drain(s, buf, sizeof buf, NULL);
        ZU_CHECK_EQ_INT(n, sizeof RESP - 1);
        ZU_CHECK_MEM(buf, RESP, sizeof RESP - 1);
        ZU_CHECK(zu_mock_stream_exhausted(s));
        zu_mock_stream_free(s);
    }

    /* S2 exit criterion: any byte sequence, split at any boundary. */
    ZU_CASE("the same bytes arrive one at a time");
    {
        zu_stream *s = zu_mock_stream_from_bytes(RESP, sizeof RESP - 1, 1);
        size_t n = drain(s, buf, sizeof buf, NULL);
        ZU_CHECK_EQ_INT(n, sizeof RESP - 1);
        ZU_CHECK_MEM(buf, RESP, sizeof RESP - 1);
        zu_mock_stream_free(s);
    }

    ZU_CASE("every chunk size from 1..N yields identical bytes");
    {
        size_t chunk;
        for (chunk = 1; chunk <= sizeof RESP; chunk++) {
            zu_stream *s = zu_mock_stream_from_bytes(RESP, sizeof RESP - 1, chunk);
            size_t n;
            memset(buf, 0, sizeof buf);
            n = drain(s, buf, sizeof buf, NULL);
            ZU_CHECK_EQ_INT(n, sizeof RESP - 1);
            ZU_CHECK_MEM(buf, RESP, sizeof RESP - 1);
            zu_mock_stream_free(s);
        }
    }

    ZU_CASE("WOULDBLOCK is injectable and is not an error");
    {
        zu_mock_step steps[] = {
            { ZU_MOCK_DATA,       "HTTP/1.1 ", 9, ZU_OK },
            { ZU_MOCK_WOULDBLOCK, NULL,        0, ZU_OK },
            { ZU_MOCK_DATA,       "200 OK",    6, ZU_OK }
        };
        int wb = 0;
        zu_stream *s = zu_mock_stream_new(steps, 3, 0, 0);
        size_t n = drain(s, buf, sizeof buf, &wb);
        ZU_CHECK_EQ_INT(n, 15);
        ZU_CHECK_MEM(buf, "HTTP/1.1 200 OK", 15);
        ZU_CHECK_EQ_INT(wb, 1);
        zu_mock_stream_free(s);
    }

    ZU_CASE("an injected error is sticky and reported with its code");
    {
        zu_mock_step steps[] = {
            { ZU_MOCK_DATA,  "partial", 7, ZU_OK },
            { ZU_MOCK_ERROR, NULL,      0, ZU_ERR_IO }
        };
        zu_stream *s = zu_mock_stream_new(steps, 2, 0, 0);
        zu_error err; zu_ssize n;
        zu_deadline d = zu_deadline_never();
        zu_error_clear(&err);
        n = zu_stream_read(s, buf, sizeof buf, d, &err);
        ZU_CHECK_EQ_INT(n, 7);
        n = zu_stream_read(s, buf, sizeof buf, d, &err);
        ZU_CHECK_EQ_INT(n, -1);
        ZU_CHECK_EQ_INT(err.code, ZU_ERR_IO);
        /* sticky: still failing on the next call */
        n = zu_stream_read(s, buf, sizeof buf, d, &err);
        ZU_CHECK_EQ_INT(n, -1);
        zu_mock_stream_free(s);
    }

    ZU_CASE("a truncated body ends in orderly close, not an error");
    {
        zu_mock_step steps[] = {
            { ZU_MOCK_DATA, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort", 43, ZU_OK },
            { ZU_MOCK_EOF,  NULL, 0, ZU_OK }
        };
        zu_stream *s = zu_mock_stream_new(steps, 2, 0, 0);
        size_t n = drain(s, buf, sizeof buf, NULL);
        ZU_CHECK_EQ_INT(n, 43);
        zu_mock_stream_free(s);
    }

    ZU_CASE("writes are captured for asserting on generated requests (§17)");
    {
        zu_stream *s = zu_mock_stream_from_bytes(RESP, sizeof RESP - 1, 0);
        zu_error err; const zu_buffer *w;
        zu_deadline d = zu_deadline_never();
        zu_error_clear(&err);
        ZU_CHECK(zu_stream_write_all(s, "GET / HTTP/1.1\r\n\r\n", 18, d, &err));
        w = zu_mock_stream_written(s);
        ZU_CHECK_EQ_INT(w->len, 18);
        ZU_CHECK_MEM(w->data, "GET / HTTP/1.1\r\n\r\n", 18);
        zu_mock_stream_free(s);
    }

    ZU_CASE("write_all loops over short writes");
    {
        zu_stream *s = zu_mock_stream_new(NULL, 0, 0, 3);   /* 3 bytes per write */
        zu_error err; const zu_buffer *w;
        zu_deadline d = zu_deadline_never();
        zu_error_clear(&err);
        ZU_CHECK(zu_stream_write_all(s, "0123456789", 10, d, &err));
        w = zu_mock_stream_written(s);
        ZU_CHECK_EQ_INT(w->len, 10);
        ZU_CHECK_MEM(w->data, "0123456789", 10);
        zu_mock_stream_free(s);
    }

    ZU_CASE("a stream with no vtable entry fails rather than crashing");
    {
        zu_stream bare; zu_error err;
        zu_deadline d = zu_deadline_never();
        memset(&bare, 0, sizeof bare);
        zu_error_clear(&err);
        ZU_CHECK_EQ_INT(zu_stream_read(&bare, buf, 1, d, &err), -1);
        ZU_CHECK_EQ_INT(err.code, ZU_ERR_IO);
        zu_stream_close(&bare);   /* must not crash */
    }

    ZU_CASE("no leaks across the suite");
    {
        zu_alloc_stats st;
        zu_alloc_stats_get(&st);
        ZU_CHECK_EQ_INT(st.live_blocks, 0);
    }
}

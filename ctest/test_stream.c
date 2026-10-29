#include "zuh_test.h"
#include "zuh_mock_stream.h"
#include "zuh_alloc.h"
#include <string.h>

void suite_stream(void);

static const char RESP[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";

/* Read until EOF, returning total bytes and tolerating WOULDBLOCK. */
static size_t drain(zuh_stream *s, char *out, size_t cap, int *wouldblocks) {
    zuh_error err;
    size_t got = 0;
    zuh_deadline d = zuh_deadline_never();
    zuh_error_clear(&err);
    for (;;) {
        zuh_ssize n = zuh_stream_read(s, out + got, cap - got, d, &err);
        if (n > 0) { got += (size_t)n; continue; }
        if (n == 0) break;
        if (err.code == ZUH_ERR_WOULDBLOCK) {
            if (wouldblocks) (*wouldblocks)++;
            zuh_error_clear(&err);
            continue;
        }
        break;
    }
    return got;
}

void suite_stream(void) {
    char buf[256];

    ZUH_CASE("a whole response arrives in one read");
    {
        zuh_stream *s = zuh_mock_stream_from_bytes(RESP, sizeof RESP - 1, 0);
        size_t n = drain(s, buf, sizeof buf, NULL);
        ZUH_CHECK_EQ_INT(n, sizeof RESP - 1);
        ZUH_CHECK_MEM(buf, RESP, sizeof RESP - 1);
        ZUH_CHECK(zuh_mock_stream_exhausted(s));
        zuh_mock_stream_free(s);
    }

    /* S2 exit criterion: any byte sequence, split at any boundary. */
    ZUH_CASE("the same bytes arrive one at a time");
    {
        zuh_stream *s = zuh_mock_stream_from_bytes(RESP, sizeof RESP - 1, 1);
        size_t n = drain(s, buf, sizeof buf, NULL);
        ZUH_CHECK_EQ_INT(n, sizeof RESP - 1);
        ZUH_CHECK_MEM(buf, RESP, sizeof RESP - 1);
        zuh_mock_stream_free(s);
    }

    ZUH_CASE("every chunk size from 1..N yields identical bytes");
    {
        size_t chunk;
        for (chunk = 1; chunk <= sizeof RESP; chunk++) {
            zuh_stream *s = zuh_mock_stream_from_bytes(RESP, sizeof RESP - 1, chunk);
            size_t n;
            memset(buf, 0, sizeof buf);
            n = drain(s, buf, sizeof buf, NULL);
            ZUH_CHECK_EQ_INT(n, sizeof RESP - 1);
            ZUH_CHECK_MEM(buf, RESP, sizeof RESP - 1);
            zuh_mock_stream_free(s);
        }
    }

    ZUH_CASE("WOULDBLOCK is injectable and is not an error");
    {
        zuh_mock_step steps[] = {
            { ZUH_MOCK_DATA,       "HTTP/1.1 ", 9, ZUH_OK },
            { ZUH_MOCK_WOULDBLOCK, NULL,        0, ZUH_OK },
            { ZUH_MOCK_DATA,       "200 OK",    6, ZUH_OK }
        };
        int wb = 0;
        zuh_stream *s = zuh_mock_stream_new(steps, 3, 0, 0);
        size_t n = drain(s, buf, sizeof buf, &wb);
        ZUH_CHECK_EQ_INT(n, 15);
        ZUH_CHECK_MEM(buf, "HTTP/1.1 200 OK", 15);
        ZUH_CHECK_EQ_INT(wb, 1);
        zuh_mock_stream_free(s);
    }

    ZUH_CASE("an injected error is sticky and reported with its code");
    {
        zuh_mock_step steps[] = {
            { ZUH_MOCK_DATA,  "partial", 7, ZUH_OK },
            { ZUH_MOCK_ERROR, NULL,      0, ZUH_ERR_IO }
        };
        zuh_stream *s = zuh_mock_stream_new(steps, 2, 0, 0);
        zuh_error err; zuh_ssize n;
        zuh_deadline d = zuh_deadline_never();
        zuh_error_clear(&err);
        n = zuh_stream_read(s, buf, sizeof buf, d, &err);
        ZUH_CHECK_EQ_INT(n, 7);
        n = zuh_stream_read(s, buf, sizeof buf, d, &err);
        ZUH_CHECK_EQ_INT(n, -1);
        ZUH_CHECK_EQ_INT(err.code, ZUH_ERR_IO);
        /* sticky: still failing on the next call */
        n = zuh_stream_read(s, buf, sizeof buf, d, &err);
        ZUH_CHECK_EQ_INT(n, -1);
        zuh_mock_stream_free(s);
    }

    ZUH_CASE("a truncated body ends in orderly close, not an error");
    {
        zuh_mock_step steps[] = {
            { ZUH_MOCK_DATA, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort", 43, ZUH_OK },
            { ZUH_MOCK_EOF,  NULL, 0, ZUH_OK }
        };
        zuh_stream *s = zuh_mock_stream_new(steps, 2, 0, 0);
        size_t n = drain(s, buf, sizeof buf, NULL);
        ZUH_CHECK_EQ_INT(n, 43);
        zuh_mock_stream_free(s);
    }

    ZUH_CASE("writes are captured for asserting on generated requests (§17)");
    {
        zuh_stream *s = zuh_mock_stream_from_bytes(RESP, sizeof RESP - 1, 0);
        zuh_error err; const zuh_buffer *w;
        zuh_deadline d = zuh_deadline_never();
        zuh_error_clear(&err);
        ZUH_CHECK(zuh_stream_write_all(s, "GET / HTTP/1.1\r\n\r\n", 18, d, &err));
        w = zuh_mock_stream_written(s);
        ZUH_CHECK_EQ_INT(w->len, 18);
        ZUH_CHECK_MEM(w->data, "GET / HTTP/1.1\r\n\r\n", 18);
        zuh_mock_stream_free(s);
    }

    ZUH_CASE("write_all loops over short writes");
    {
        zuh_stream *s = zuh_mock_stream_new(NULL, 0, 0, 3);   /* 3 bytes per write */
        zuh_error err; const zuh_buffer *w;
        zuh_deadline d = zuh_deadline_never();
        zuh_error_clear(&err);
        ZUH_CHECK(zuh_stream_write_all(s, "0123456789", 10, d, &err));
        w = zuh_mock_stream_written(s);
        ZUH_CHECK_EQ_INT(w->len, 10);
        ZUH_CHECK_MEM(w->data, "0123456789", 10);
        zuh_mock_stream_free(s);
    }

    ZUH_CASE("a stream with no vtable entry fails rather than crashing");
    {
        zuh_stream bare; zuh_error err;
        zuh_deadline d = zuh_deadline_never();
        memset(&bare, 0, sizeof bare);
        zuh_error_clear(&err);
        ZUH_CHECK_EQ_INT(zuh_stream_read(&bare, buf, 1, d, &err), -1);
        ZUH_CHECK_EQ_INT(err.code, ZUH_ERR_IO);
        zuh_stream_close(&bare);   /* must not crash */
    }

    ZUH_CASE("no leaks across the suite");
    {
        zuh_alloc_stats st;
        zuh_alloc_stats_get(&st);
        ZUH_CHECK_EQ_INT(st.live_blocks, 0);
    }
}

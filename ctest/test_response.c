#include "zu_test.h"
#include "zu_response.h"
#include "zu_alloc.h"
#include <string.h>

void suite_response(void);

static zu_code parse(zu_response *r, const char *s, size_t *consumed) {
    zu_error e;
    zu_error_clear(&e);
    return zu_response_parse(r, s, strlen(s), 0, consumed, &e);
}

void suite_response(void) {
    zu_response r;
    size_t used;

    ZU_CASE("a well-formed response head parses");
    zu_response_init(&r);
    ZU_CHECK_EQ_INT(parse(&r,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 5\r\n"
        "\r\n", &used), ZU_OK);
    ZU_CHECK_EQ_INT(r.status, 200);
    ZU_CHECK_EQ_INT(r.minor_version, 1);
    ZU_CHECK(strcmp(r.reason, "OK") == 0);
    ZU_CHECK_EQ_INT(r.headers.n, 2);
    ZU_CHECK(strcmp(zu_headers_get(&r.headers, "content-type"), "application/json") == 0);
    zu_response_free(&r);

    ZU_CASE("an incomplete head asks for more bytes rather than failing");
    zu_response_init(&r);
    ZU_CHECK_EQ_INT(parse(&r, "HTTP/1.1 200 OK\r\nContent-Len", &used), ZU_ERR_WOULDBLOCK);
    ZU_CHECK_EQ_INT(parse(&r, "HTTP/1.1 200 OK\r\n", &used), ZU_ERR_WOULDBLOCK);
    ZU_CHECK_EQ_INT(parse(&r, "HTT", &used), ZU_ERR_WOULDBLOCK);
    ZU_CHECK_EQ_INT(parse(&r, "", &used), ZU_ERR_WOULDBLOCK);
    zu_response_free(&r);

    ZU_CASE("byte-at-a-time feeding converges on the same result");
    {
        const char *full =
            "HTTP/1.1 404 Not Found\r\nX-A: 1\r\nX-B: 2\r\n\r\n";
        size_t total = strlen(full), i;
        zu_response_init(&r);
        for (i = 1; i <= total; i++) {
            zu_error e; size_t c;
            zu_code rc;
            zu_error_clear(&e);
            rc = zu_response_parse(&r, full, i, i > 0 ? i - 1 : 0, &c, &e);
            if (i < total) {
                ZU_CHECK_EQ_INT(rc, ZU_ERR_WOULDBLOCK);
            } else {
                ZU_CHECK_EQ_INT(rc, ZU_OK);
                ZU_CHECK_EQ_INT(r.status, 404);
                ZU_CHECK(strcmp(r.reason, "Not Found") == 0);
                ZU_CHECK_EQ_INT(r.headers.n, 2);
                ZU_CHECK_EQ_INT(c, total);
            }
        }
        zu_response_free(&r);
    }

    ZU_CASE("§18.1: obsolete line folding is rejected, not unfolded");
    zu_response_init(&r);
    ZU_CHECK_EQ_INT(parse(&r,
        "HTTP/1.1 200 OK\r\nX-Long: one\r\n  two\r\n\r\n", &used), ZU_ERR_PARSE);
    zu_response_free(&r);

    ZU_CASE("a malformed status line is rejected");
    {
        const char *bad[] = {
            "XTTP/1.1 200 OK\r\n\r\n",
            "HTTP/1.1 xyz OK\r\n\r\n",
            "HTTP/9.9 200 OK\r\n\r\n",
            "HTTP/1.1 20 OK\r\n\r\n",
            "HTTP/1.1 1000 OK\r\n\r\n"
        };
        size_t i;
        for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            zu_response_init(&r);
            ZU_CHECK_EQ_INT(parse(&r, bad[i], &used), ZU_ERR_PARSE);
            zu_response_free(&r);
        }
    }

    ZU_CASE("an invalid header name is rejected by our storage layer");
    zu_response_init(&r);
    ZU_CHECK_EQ_INT(parse(&r, "HTTP/1.1 200 OK\r\nBad Name: v\r\n\r\n", &used), ZU_ERR_PARSE);
    zu_response_free(&r);

    ZU_CASE("interim 1xx is detected so the engine can skip it");
    zu_response_init(&r);
    ZU_CHECK_EQ_INT(parse(&r, "HTTP/1.1 100 Continue\r\n\r\n", &used), ZU_OK);
    ZU_CHECK(zu_response_is_informational(&r));
    ZU_CHECK_EQ_INT(used, 25);
    zu_response_free(&r);

    ZU_CASE("parsing feeds §18.1, and smuggling attempts still fail there");
    {
        zu_error e;
        zu_error_clear(&e);
        zu_response_init(&r);
        ZU_CHECK_EQ_INT(parse(&r,
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
            &used), ZU_OK);                                   /* parses fine ... */
        ZU_CHECK_EQ_INT(zu_response_decide_framing(&r, 0, &e), ZU_ERR_PARSE); /* ... rejected here */
        zu_response_free(&r);

        zu_error_clear(&e);
        zu_response_init(&r);
        ZU_CHECK_EQ_INT(parse(&r,
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
            &used), ZU_OK);
        ZU_CHECK_EQ_INT(zu_response_decide_framing(&r, 0, &e), ZU_ERR_PARSE);
        zu_response_free(&r);

        zu_error_clear(&e);
        zu_response_init(&r);
        ZU_CHECK_EQ_INT(parse(&r,
            "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n", &used), ZU_OK);
        ZU_CHECK_EQ_INT(zu_response_decide_framing(&r, 0, &e), ZU_OK);
        ZU_CHECK_EQ_INT(r.framing.kind, ZU_FRAME_LENGTH);
        ZU_CHECK_EQ_INT(r.framing.length, 7);
        zu_response_free(&r);
    }

    ZU_CASE("§18.2: chunked decoding, including trailers");
    {
        zu_chunked c; zu_error e; size_t len; zu_code rc;
        char buf[256];
        const char *body = "5\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: v\r\n\r\n";
        zu_error_clear(&e);
        ZU_CHECK_EQ_INT(zu_chunked_init(&c, 0, 0), ZU_OK);
        len = strlen(body);
        memcpy(buf, body, len);
        rc = zu_chunked_decode(&c, buf, &len, &e);
        ZU_CHECK_EQ_INT(rc, ZU_OK);
        ZU_CHECK_EQ_INT(len, 11);
        ZU_CHECK_MEM(buf, "hello world", 11);
        zu_chunked_free(&c);
    }

    ZU_CASE("chunked decoding asks for more input when truncated");
    {
        zu_chunked c; zu_error e; size_t len; char buf[64];
        const char *partial = "5\r\nhel";
        zu_error_clear(&e);
        zu_chunked_init(&c, 0, 0);
        len = strlen(partial);
        memcpy(buf, partial, len);
        ZU_CHECK_EQ_INT(zu_chunked_decode(&c, buf, &len, &e), ZU_ERR_WOULDBLOCK);
        zu_chunked_free(&c);
    }

    ZU_CASE("a malformed chunk size is rejected");
    {
        const char *bad[] = { "zz\r\nhello\r\n", "-5\r\nhello\r\n" };
        size_t i;
        for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            zu_chunked c; zu_error e; size_t len; char buf[64];
            zu_error_clear(&e);
            zu_chunked_init(&c, 0, 0);
            len = strlen(bad[i]);
            memcpy(buf, bad[i], len);
            ZU_CHECK_EQ_INT(zu_chunked_decode(&c, buf, &len, &e), ZU_ERR_PARSE);
            zu_chunked_free(&c);
        }
    }

    ZU_CASE("§40: the decoded body total is bounded");
    {
        zu_chunked c; zu_error e; size_t len; char buf[64];
        const char *body = "5\r\nhello\r\n0\r\n\r\n";
        zu_error_clear(&e);
        zu_chunked_init(&c, 0, 3);          /* max_total = 3 bytes */
        len = strlen(body);
        memcpy(buf, body, len);
        ZU_CHECK_EQ_INT(zu_chunked_decode(&c, buf, &len, &e), ZU_ERR_BODY_LIMIT);
        zu_chunked_free(&c);
    }

    ZU_CASE("no leaks across the suite");
    {
        zu_alloc_stats st;
        zu_alloc_stats_get(&st);
        ZU_CHECK_EQ_INT(st.live_blocks, 0);
    }
}

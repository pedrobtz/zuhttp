#include "zuh_test.h"
#include "zuh_response.h"
#include "zuh_alloc.h"
#include <string.h>

void suite_response(void);

static zuh_code parse(zuh_response *r, const char *s, size_t *consumed) {
    zuh_error e;
    zuh_error_clear(&e);
    return zuh_response_parse(r, s, strlen(s), 0, consumed, &e);
}

void suite_response(void) {
    zuh_response r;
    size_t used;

    ZUH_CASE("a well-formed response head parses");
    zuh_response_init(&r);
    ZUH_CHECK_EQ_INT(parse(&r,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 5\r\n"
        "\r\n", &used), ZUH_OK);
    ZUH_CHECK_EQ_INT(r.status, 200);
    ZUH_CHECK_EQ_INT(r.minor_version, 1);
    ZUH_CHECK(strcmp(r.reason, "OK") == 0);
    ZUH_CHECK_EQ_INT(r.headers.n, 2);
    ZUH_CHECK(strcmp(zuh_headers_get(&r.headers, "content-type"), "application/json") == 0);
    zuh_response_free(&r);

    ZUH_CASE("an incomplete head asks for more bytes rather than failing");
    zuh_response_init(&r);
    ZUH_CHECK_EQ_INT(parse(&r, "HTTP/1.1 200 OK\r\nContent-Len", &used), ZUH_ERR_WOULDBLOCK);
    ZUH_CHECK_EQ_INT(parse(&r, "HTTP/1.1 200 OK\r\n", &used), ZUH_ERR_WOULDBLOCK);
    ZUH_CHECK_EQ_INT(parse(&r, "HTT", &used), ZUH_ERR_WOULDBLOCK);
    ZUH_CHECK_EQ_INT(parse(&r, "", &used), ZUH_ERR_WOULDBLOCK);
    zuh_response_free(&r);

    ZUH_CASE("byte-at-a-time feeding converges on the same result");
    {
        const char *full =
            "HTTP/1.1 404 Not Found\r\nX-A: 1\r\nX-B: 2\r\n\r\n";
        size_t total = strlen(full), i;
        zuh_response_init(&r);
        for (i = 1; i <= total; i++) {
            zuh_error e; size_t c;
            zuh_code rc;
            zuh_error_clear(&e);
            rc = zuh_response_parse(&r, full, i, i > 0 ? i - 1 : 0, &c, &e);
            if (i < total) {
                ZUH_CHECK_EQ_INT(rc, ZUH_ERR_WOULDBLOCK);
            } else {
                ZUH_CHECK_EQ_INT(rc, ZUH_OK);
                ZUH_CHECK_EQ_INT(r.status, 404);
                ZUH_CHECK(strcmp(r.reason, "Not Found") == 0);
                ZUH_CHECK_EQ_INT(r.headers.n, 2);
                ZUH_CHECK_EQ_INT(c, total);
            }
        }
        zuh_response_free(&r);
    }

    ZUH_CASE("§18.1: obsolete line folding is rejected, not unfolded");
    zuh_response_init(&r);
    ZUH_CHECK_EQ_INT(parse(&r,
        "HTTP/1.1 200 OK\r\nX-Long: one\r\n  two\r\n\r\n", &used), ZUH_ERR_PARSE);
    zuh_response_free(&r);

    ZUH_CASE("a malformed status line is rejected");
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
            zuh_response_init(&r);
            ZUH_CHECK_EQ_INT(parse(&r, bad[i], &used), ZUH_ERR_PARSE);
            zuh_response_free(&r);
        }
    }

    ZUH_CASE("an invalid header name is rejected by our storage layer");
    zuh_response_init(&r);
    ZUH_CHECK_EQ_INT(parse(&r, "HTTP/1.1 200 OK\r\nBad Name: v\r\n\r\n", &used), ZUH_ERR_PARSE);
    zuh_response_free(&r);

    ZUH_CASE("interim 1xx is detected so the engine can skip it");
    zuh_response_init(&r);
    ZUH_CHECK_EQ_INT(parse(&r, "HTTP/1.1 100 Continue\r\n\r\n", &used), ZUH_OK);
    ZUH_CHECK(zuh_response_is_informational(&r));
    ZUH_CHECK_EQ_INT(used, 25);
    zuh_response_free(&r);

    ZUH_CASE("parsing feeds §18.1, and smuggling attempts still fail there");
    {
        zuh_error e;
        zuh_error_clear(&e);
        zuh_response_init(&r);
        ZUH_CHECK_EQ_INT(parse(&r,
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
            &used), ZUH_OK);                                   /* parses fine ... */
        ZUH_CHECK_EQ_INT(zuh_response_decide_framing(&r, 0, &e), ZUH_ERR_PARSE); /* ... rejected here */
        zuh_response_free(&r);

        zuh_error_clear(&e);
        zuh_response_init(&r);
        ZUH_CHECK_EQ_INT(parse(&r,
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
            &used), ZUH_OK);
        ZUH_CHECK_EQ_INT(zuh_response_decide_framing(&r, 0, &e), ZUH_ERR_PARSE);
        zuh_response_free(&r);

        zuh_error_clear(&e);
        zuh_response_init(&r);
        ZUH_CHECK_EQ_INT(parse(&r,
            "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n", &used), ZUH_OK);
        ZUH_CHECK_EQ_INT(zuh_response_decide_framing(&r, 0, &e), ZUH_OK);
        ZUH_CHECK_EQ_INT(r.framing.kind, ZUH_FRAME_LENGTH);
        ZUH_CHECK_EQ_INT(r.framing.length, 7);
        zuh_response_free(&r);
    }

    ZUH_CASE("§18.2: chunked decoding, including trailers");
    {
        zuh_chunked c; zuh_error e; size_t len; zuh_code rc;
        char buf[256];
        const char *body = "5\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: v\r\n\r\n";
        zuh_error_clear(&e);
        ZUH_CHECK_EQ_INT(zuh_chunked_init(&c, 0, 0), ZUH_OK);
        len = strlen(body);
        memcpy(buf, body, len);
        rc = zuh_chunked_decode(&c, buf, &len, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        ZUH_CHECK_EQ_INT(len, 11);
        ZUH_CHECK_MEM(buf, "hello world", 11);
        zuh_chunked_free(&c);
    }

    ZUH_CASE("chunked decoding asks for more input when truncated");
    {
        zuh_chunked c; zuh_error e; size_t len; char buf[64];
        const char *partial = "5\r\nhel";
        zuh_error_clear(&e);
        zuh_chunked_init(&c, 0, 0);
        len = strlen(partial);
        memcpy(buf, partial, len);
        ZUH_CHECK_EQ_INT(zuh_chunked_decode(&c, buf, &len, &e), ZUH_ERR_WOULDBLOCK);
        zuh_chunked_free(&c);
    }

    ZUH_CASE("a malformed chunk size is rejected");
    {
        const char *bad[] = { "zz\r\nhello\r\n", "-5\r\nhello\r\n" };
        size_t i;
        for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            zuh_chunked c; zuh_error e; size_t len; char buf[64];
            zuh_error_clear(&e);
            zuh_chunked_init(&c, 0, 0);
            len = strlen(bad[i]);
            memcpy(buf, bad[i], len);
            ZUH_CHECK_EQ_INT(zuh_chunked_decode(&c, buf, &len, &e), ZUH_ERR_PARSE);
            zuh_chunked_free(&c);
        }
    }

    ZUH_CASE("§40: the decoded body total is bounded");
    {
        zuh_chunked c; zuh_error e; size_t len; char buf[64];
        const char *body = "5\r\nhello\r\n0\r\n\r\n";
        zuh_error_clear(&e);
        zuh_chunked_init(&c, 0, 3);          /* max_total = 3 bytes */
        len = strlen(body);
        memcpy(buf, body, len);
        ZUH_CHECK_EQ_INT(zuh_chunked_decode(&c, buf, &len, &e), ZUH_ERR_BODY_LIMIT);
        zuh_chunked_free(&c);
    }

    ZUH_CASE("no leaks across the suite");
    {
        zuh_alloc_stats st;
        zuh_alloc_stats_get(&st);
        ZUH_CHECK_EQ_INT(st.live_blocks, 0);
    }
}

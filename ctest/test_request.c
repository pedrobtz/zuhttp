#include "zu_test.h"
#include "zu_request.h"
#include "zu_alloc.h"
#include <string.h>

void suite_request(void);

static const char *build(zu_request *r, zu_buffer *b, zu_code *rc) {
    const char *s = NULL;
    zu_buf_init(b, 0, 0);
    *rc = zu_request_write(r, b);
    if (*rc == ZU_OK) zu_buf_cstr(b, &s);
    return s;
}

void suite_request(void) {
    zu_request r;
    zu_buffer b;
    zu_code rc;

    ZU_CASE("§17: a plain GET serialises exactly");
    zu_request_init(&r);
    r.method = "GET"; r.target = "/api?q=1"; r.host = "example.com";
    ZU_CHECK_EQ_INT(zu_request_add_defaults(&r, "zuhttp/0.1"), ZU_OK);
    {
        const char *s = build(&r, &b, &rc);
        ZU_CHECK_EQ_INT(rc, ZU_OK);
        ZU_CHECK(s && strcmp(s,
            "GET /api?q=1 HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "User-Agent: zuhttp/0.1\r\n"
            "Accept: */*\r\n"
            "Accept-Encoding: gzip\r\n"
            "Connection: keep-alive\r\n"
            "\r\n") == 0);
        zu_buf_free(&b);
    }
    zu_request_free(&r);

    ZU_CASE("§17.2: a caller override wins over the default");
    zu_request_init(&r);
    r.method = "GET"; r.target = "/"; r.host = "example.com";
    zu_headers_add_str(&r.headers, "Accept", "application/json");
    zu_request_add_defaults(&r, "zuhttp/0.1");
    ZU_CHECK_EQ_INT(zu_headers_count(&r.headers, "Accept"), 1);
    ZU_CHECK(strcmp(zu_headers_get(&r.headers, "Accept"), "application/json") == 0);
    zu_request_free(&r);

    ZU_CASE("§17.1: a method containing a space is rejected (request splitting)");
    zu_request_init(&r);
    r.method = "GET /evil HTTP/1.1"; r.target = "/"; r.host = "h";
    zu_request_add_defaults(&r, NULL);
    build(&r, &b, &rc);
    ZU_CHECK_EQ_INT(rc, ZU_ERR_PARSE);
    zu_buf_free(&b);
    zu_request_free(&r);

    ZU_CASE("a target containing CTLs, SP, CR or LF is rejected");
    {
        const char *bad[] = { "/a b", "/a\r\nX: 1", "/a\nb", "/a\tb", "/a\x7f" };
        size_t i;
        for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            zu_request_init(&r);
            r.method = "GET"; r.target = bad[i]; r.host = "h";
            zu_request_add_defaults(&r, NULL);
            build(&r, &b, &rc);
            ZU_CHECK_EQ_INT(rc, ZU_ERR_PARSE);
            zu_buf_free(&b);
            zu_request_free(&r);
        }
    }

    ZU_CASE("HTTP/1.1 without Host is refused rather than sent degraded");
    zu_request_init(&r);
    r.method = "GET"; r.target = "/";     /* no host, no defaults applied */
    build(&r, &b, &rc);
    ZU_CHECK_EQ_INT(rc, ZU_ERR_PARSE);
    zu_buf_free(&b);
    zu_request_free(&r);

    ZU_CASE("Content-Length is emitted from the struct, not the header list");
    zu_request_init(&r);
    r.method = "POST"; r.target = "/u"; r.host = "h";
    r.body = ZU_BODY_LENGTH; r.content_length = 18446744073709551615ull;
    zu_request_add_defaults(&r, "ua");
    {
        const char *s = build(&r, &b, &rc);
        ZU_CHECK_EQ_INT(rc, ZU_OK);
        ZU_CHECK(s && strstr(s, "Content-Length: 18446744073709551615\r\n") != NULL);
        zu_buf_free(&b);
    }
    zu_request_free(&r);

    ZU_CASE("a chunked request body emits Transfer-Encoding (§28.1)");
    zu_request_init(&r);
    r.method = "POST"; r.target = "/u"; r.host = "h"; r.body = ZU_BODY_CHUNKED;
    zu_request_add_defaults(&r, "ua");
    {
        const char *s = build(&r, &b, &rc);
        ZU_CHECK_EQ_INT(rc, ZU_OK);
        ZU_CHECK(s && strstr(s, "Transfer-Encoding: chunked\r\n") != NULL);
        ZU_CHECK(s && strstr(s, "Content-Length") == NULL);
        zu_buf_free(&b);
    }
    zu_request_free(&r);

    ZU_CASE("we never generate both Content-Length and Transfer-Encoding");
    zu_request_init(&r);
    r.method = "POST"; r.target = "/u"; r.host = "h";
    zu_headers_add_str(&r.headers, "Content-Length", "5");
    zu_headers_add_str(&r.headers, "Transfer-Encoding", "chunked");
    build(&r, &b, &rc);
    ZU_CHECK_EQ_INT(rc, ZU_ERR_PARSE);
    zu_buf_free(&b);
    zu_request_free(&r);

    ZU_CASE("CONNECT uses authority-form and needs no Host (§20.3)");
    zu_request_init(&r);
    r.method = "CONNECT"; r.target = "example.com:443";
    r.form = ZU_TARGET_AUTHORITY;
    {
        const char *s = build(&r, &b, &rc);
        ZU_CHECK_EQ_INT(rc, ZU_OK);
        ZU_CHECK(s && strncmp(s, "CONNECT example.com:443 HTTP/1.1\r\n", 34) == 0);
        zu_buf_free(&b);
    }
    zu_request_free(&r);

    ZU_CASE("arbitrary methods are allowed (§31.5)");
    zu_request_init(&r);
    r.method = "PROPFIND"; r.target = "/"; r.host = "h";
    zu_request_add_defaults(&r, "ua");
    {
        const char *s = build(&r, &b, &rc);
        ZU_CHECK_EQ_INT(rc, ZU_OK);
        ZU_CHECK(s && strncmp(s, "PROPFIND / HTTP/1.1\r\n", 21) == 0);
        zu_buf_free(&b);
    }
    zu_request_free(&r);

    ZU_CASE("no leaks across the suite");
    {
        zu_alloc_stats st;
        zu_alloc_stats_get(&st);
        ZU_CHECK_EQ_INT(st.live_blocks, 0);
    }
}

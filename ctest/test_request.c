#include "zuh_test.h"
#include "zuh_request.h"
#include "zuh_alloc.h"
#include <string.h>

void suite_request(void);

static const char *build(zuh_request *r, zuh_buffer *b, zuh_code *rc) {
    const char *s = NULL;
    zuh_buf_init(b, 0, 0);
    *rc = zuh_request_write(r, b);
    if (*rc == ZUH_OK) zuh_buf_cstr(b, &s);
    return s;
}

void suite_request(void) {
    zuh_request r;
    zuh_buffer b;
    zuh_code rc;

    ZUH_CASE("§17: a plain GET serialises exactly");
    zuh_request_init(&r);
    r.method = "GET"; r.target = "/api?q=1"; r.host = "example.com";
    ZUH_CHECK_EQ_INT(zuh_request_add_defaults(&r, "zuhttp/0.1"), ZUH_OK);
    {
        const char *s = build(&r, &b, &rc);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        ZUH_CHECK(s && strcmp(s,
            "GET /api?q=1 HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "User-Agent: zuhttp/0.1\r\n"
            "Accept: */*\r\n"
            "Accept-Encoding: gzip\r\n"
            "Connection: keep-alive\r\n"
            "\r\n") == 0);
        zuh_buf_free(&b);
    }
    zuh_request_free(&r);

    ZUH_CASE("§17.2: a caller override wins over the default");
    zuh_request_init(&r);
    r.method = "GET"; r.target = "/"; r.host = "example.com";
    zuh_headers_add_str(&r.headers, "Accept", "application/json");
    zuh_request_add_defaults(&r, "zuhttp/0.1");
    ZUH_CHECK_EQ_INT(zuh_headers_count(&r.headers, "Accept"), 1);
    ZUH_CHECK(strcmp(zuh_headers_get(&r.headers, "Accept"), "application/json") == 0);
    zuh_request_free(&r);

    ZUH_CASE("§17.1: a method containing a space is rejected (request splitting)");
    zuh_request_init(&r);
    r.method = "GET /evil HTTP/1.1"; r.target = "/"; r.host = "h";
    zuh_request_add_defaults(&r, NULL);
    build(&r, &b, &rc);
    ZUH_CHECK_EQ_INT(rc, ZUH_ERR_PARSE);
    zuh_buf_free(&b);
    zuh_request_free(&r);

    ZUH_CASE("a target containing CTLs, SP, CR or LF is rejected");
    {
        const char *bad[] = { "/a b", "/a\r\nX: 1", "/a\nb", "/a\tb", "/a\x7f" };
        size_t i;
        for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            zuh_request_init(&r);
            r.method = "GET"; r.target = bad[i]; r.host = "h";
            zuh_request_add_defaults(&r, NULL);
            build(&r, &b, &rc);
            ZUH_CHECK_EQ_INT(rc, ZUH_ERR_PARSE);
            zuh_buf_free(&b);
            zuh_request_free(&r);
        }
    }

    ZUH_CASE("HTTP/1.1 without Host is refused rather than sent degraded");
    zuh_request_init(&r);
    r.method = "GET"; r.target = "/";     /* no host, no defaults applied */
    build(&r, &b, &rc);
    ZUH_CHECK_EQ_INT(rc, ZUH_ERR_PARSE);
    zuh_buf_free(&b);
    zuh_request_free(&r);

    ZUH_CASE("Content-Length is emitted from the struct, not the header list");
    zuh_request_init(&r);
    r.method = "POST"; r.target = "/u"; r.host = "h";
    r.body = ZUH_BODY_LENGTH; r.content_length = 18446744073709551615ull;
    zuh_request_add_defaults(&r, "ua");
    {
        const char *s = build(&r, &b, &rc);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        ZUH_CHECK(s && strstr(s, "Content-Length: 18446744073709551615\r\n") != NULL);
        zuh_buf_free(&b);
    }
    zuh_request_free(&r);

    ZUH_CASE("a chunked request body emits Transfer-Encoding (§28.1)");
    zuh_request_init(&r);
    r.method = "POST"; r.target = "/u"; r.host = "h"; r.body = ZUH_BODY_CHUNKED;
    zuh_request_add_defaults(&r, "ua");
    {
        const char *s = build(&r, &b, &rc);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        ZUH_CHECK(s && strstr(s, "Transfer-Encoding: chunked\r\n") != NULL);
        ZUH_CHECK(s && strstr(s, "Content-Length") == NULL);
        zuh_buf_free(&b);
    }
    zuh_request_free(&r);

    ZUH_CASE("we never generate both Content-Length and Transfer-Encoding");
    zuh_request_init(&r);
    r.method = "POST"; r.target = "/u"; r.host = "h";
    zuh_headers_add_str(&r.headers, "Content-Length", "5");
    zuh_headers_add_str(&r.headers, "Transfer-Encoding", "chunked");
    build(&r, &b, &rc);
    ZUH_CHECK_EQ_INT(rc, ZUH_ERR_PARSE);
    zuh_buf_free(&b);
    zuh_request_free(&r);

    ZUH_CASE("CONNECT uses authority-form and needs no Host (§20.3)");
    zuh_request_init(&r);
    r.method = "CONNECT"; r.target = "example.com:443";
    r.form = ZUH_TARGET_AUTHORITY;
    {
        const char *s = build(&r, &b, &rc);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        ZUH_CHECK(s && strncmp(s, "CONNECT example.com:443 HTTP/1.1\r\n", 34) == 0);
        zuh_buf_free(&b);
    }
    zuh_request_free(&r);

    ZUH_CASE("arbitrary methods are allowed (§31.5)");
    zuh_request_init(&r);
    r.method = "PROPFIND"; r.target = "/"; r.host = "h";
    zuh_request_add_defaults(&r, "ua");
    {
        const char *s = build(&r, &b, &rc);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        ZUH_CHECK(s && strncmp(s, "PROPFIND / HTTP/1.1\r\n", 21) == 0);
        zuh_buf_free(&b);
    }
    zuh_request_free(&r);

    ZUH_CASE("no leaks across the suite");
    {
        zuh_alloc_stats st;
        zuh_alloc_stats_get(&st);
        ZUH_CHECK_EQ_INT(st.live_blocks, 0);
    }
}

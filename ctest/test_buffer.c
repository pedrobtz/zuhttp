#include "zuh_test.h"
#include "zuh_buffer.h"
#include "zuh_alloc.h"
#include <string.h>

void suite_buffer(void);

void suite_buffer(void) {
    zuh_buffer b;

    ZUH_CASE("append and grow");
    ZUH_CHECK(zuh_buf_init(&b, 0, 0));
    ZUH_CHECK(zuh_buf_append_str(&b, "GET / HTTP/1.1\r\n"));
    ZUH_CHECK_EQ_INT(b.len, 16);
    ZUH_CHECK_MEM(b.data, "GET / HTTP/1.1\r\n", 16);
    ZUH_CHECK(zuh_buf_append_str(&b, "Host: x\r\n"));
    ZUH_CHECK_EQ_INT(b.len, 25);
    zuh_buf_free(&b);

    ZUH_CASE("append of zero bytes succeeds; NULL source is rejected");
    ZUH_CHECK(zuh_buf_init(&b, 8, 0));
    ZUH_CHECK(zuh_buf_append(&b, NULL, 0));
    ZUH_CHECK(!zuh_buf_append(&b, NULL, 4));
    ZUH_CHECK_EQ_INT(b.len, 0);
    zuh_buf_free(&b);

    ZUH_CASE("the cap is enforced and distinguishable from OOM (§40)");
    ZUH_CHECK(zuh_buf_init(&b, 0, 10));
    ZUH_CHECK(zuh_buf_append_str(&b, "0123456789"));
    ZUH_CHECK_EQ_INT(b.len, 10);
    ZUH_CHECK(!zuh_buf_append_byte(&b, 'x'));      /* one past the cap */
    ZUH_CHECK(zuh_buf_hit_limit(&b));              /* => zu_body_limit_error */
    ZUH_CHECK_EQ_INT(b.len, 10);                  /* unchanged after failure */
    zuh_buf_free(&b);

    ZUH_CASE("init clamps an initial capacity above the cap");
    ZUH_CHECK(zuh_buf_init(&b, 1000, 16));
    ZUH_CHECK(b.cap <= 16);
    zuh_buf_free(&b);

    ZUH_CASE("overflow-safe u64 to decimal (§17)");
    {
        struct { uint64_t v; const char *s; } cases[] = {
            {0, "0"}, {1, "1"}, {9, "9"}, {10, "10"}, {12345, "12345"},
            {4294967295ull, "4294967295"},
            {18446744073709551615ull, "18446744073709551615"}
        };
        size_t i;
        for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
            const char *s;
            ZUH_CHECK(zuh_buf_init(&b, 0, 0));
            ZUH_CHECK(zuh_buf_append_u64(&b, cases[i].v));
            ZUH_CHECK(zuh_buf_cstr(&b, &s));
            ZUH_CHECK(strcmp(s, cases[i].s) == 0);
            zuh_buf_free(&b);
        }
    }

    ZUH_CASE("consume shifts the remainder down");
    ZUH_CHECK(zuh_buf_init(&b, 0, 0));
    ZUH_CHECK(zuh_buf_append_str(&b, "HEADERS\r\n\r\nBODY"));
    zuh_buf_consume(&b, 11);
    ZUH_CHECK_EQ_INT(b.len, 4);
    ZUH_CHECK_MEM(b.data, "BODY", 4);
    zuh_buf_consume(&b, 999);              /* over-consume clamps to empty */
    ZUH_CHECK_EQ_INT(b.len, 0);
    zuh_buf_free(&b);

    ZUH_CASE("cstr terminates without counting the NUL");
    {
        const char *s;
        ZUH_CHECK(zuh_buf_init(&b, 0, 0));
        ZUH_CHECK(zuh_buf_append_str(&b, "abc"));
        ZUH_CHECK(zuh_buf_cstr(&b, &s));
        ZUH_CHECK_EQ_INT(b.len, 3);
        ZUH_CHECK(strcmp(s, "abc") == 0);
        zuh_buf_free(&b);
    }

    ZUH_CASE("append survives OOM without corrupting length");
    {
        /* Must cross the current capacity to force a realloc; the first
         * allocation is 64 bytes, so a small append would never allocate. */
        char big[200];
        memset(big, 'z', sizeof big);
        ZUH_CHECK(zuh_buf_init(&b, 0, 0));
        ZUH_CHECK(zuh_buf_append_str(&b, "ab"));
        ZUH_CHECK(b.cap < sizeof big);
        zuh_alloc_fail_after(0);
        ZUH_CHECK(!zuh_buf_append(&b, big, sizeof big));
        zuh_alloc_fail_after(-1);
        ZUH_CHECK_EQ_INT(b.len, 2);
        ZUH_CHECK_MEM(b.data, "ab", 2);
        ZUH_CHECK(!zuh_buf_hit_limit(&b));   /* OOM, not the cap */
        zuh_buf_free(&b);
    }

    ZUH_CASE("no leaks across the suite");
    {
        zuh_alloc_stats st;
        zuh_alloc_stats_get(&st);
        ZUH_CHECK_EQ_INT(st.live_blocks, 0);
    }
}

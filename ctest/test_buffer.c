#include "zu_test.h"
#include "zu_buffer.h"
#include "zu_alloc.h"
#include <string.h>

void suite_buffer(void);

void suite_buffer(void) {
    zu_buffer b;

    ZU_CASE("append and grow");
    ZU_CHECK(zu_buf_init(&b, 0, 0));
    ZU_CHECK(zu_buf_append_str(&b, "GET / HTTP/1.1\r\n"));
    ZU_CHECK_EQ_INT(b.len, 16);
    ZU_CHECK_MEM(b.data, "GET / HTTP/1.1\r\n", 16);
    ZU_CHECK(zu_buf_append_str(&b, "Host: x\r\n"));
    ZU_CHECK_EQ_INT(b.len, 25);
    zu_buf_free(&b);

    ZU_CASE("append of zero bytes succeeds; NULL source is rejected");
    ZU_CHECK(zu_buf_init(&b, 8, 0));
    ZU_CHECK(zu_buf_append(&b, NULL, 0));
    ZU_CHECK(!zu_buf_append(&b, NULL, 4));
    ZU_CHECK_EQ_INT(b.len, 0);
    zu_buf_free(&b);

    ZU_CASE("the cap is enforced and distinguishable from OOM (§40)");
    ZU_CHECK(zu_buf_init(&b, 0, 10));
    ZU_CHECK(zu_buf_append_str(&b, "0123456789"));
    ZU_CHECK_EQ_INT(b.len, 10);
    ZU_CHECK(!zu_buf_append_byte(&b, 'x'));      /* one past the cap */
    ZU_CHECK(zu_buf_hit_limit(&b));              /* => zu_body_limit_error */
    ZU_CHECK_EQ_INT(b.len, 10);                  /* unchanged after failure */
    zu_buf_free(&b);

    ZU_CASE("init clamps an initial capacity above the cap");
    ZU_CHECK(zu_buf_init(&b, 1000, 16));
    ZU_CHECK(b.cap <= 16);
    zu_buf_free(&b);

    ZU_CASE("overflow-safe u64 to decimal (§17)");
    {
        struct { uint64_t v; const char *s; } cases[] = {
            {0, "0"}, {1, "1"}, {9, "9"}, {10, "10"}, {12345, "12345"},
            {4294967295ull, "4294967295"},
            {18446744073709551615ull, "18446744073709551615"}
        };
        size_t i;
        for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
            const char *s;
            ZU_CHECK(zu_buf_init(&b, 0, 0));
            ZU_CHECK(zu_buf_append_u64(&b, cases[i].v));
            ZU_CHECK(zu_buf_cstr(&b, &s));
            ZU_CHECK(strcmp(s, cases[i].s) == 0);
            zu_buf_free(&b);
        }
    }

    ZU_CASE("consume shifts the remainder down");
    ZU_CHECK(zu_buf_init(&b, 0, 0));
    ZU_CHECK(zu_buf_append_str(&b, "HEADERS\r\n\r\nBODY"));
    zu_buf_consume(&b, 11);
    ZU_CHECK_EQ_INT(b.len, 4);
    ZU_CHECK_MEM(b.data, "BODY", 4);
    zu_buf_consume(&b, 999);              /* over-consume clamps to empty */
    ZU_CHECK_EQ_INT(b.len, 0);
    zu_buf_free(&b);

    ZU_CASE("cstr terminates without counting the NUL");
    {
        const char *s;
        ZU_CHECK(zu_buf_init(&b, 0, 0));
        ZU_CHECK(zu_buf_append_str(&b, "abc"));
        ZU_CHECK(zu_buf_cstr(&b, &s));
        ZU_CHECK_EQ_INT(b.len, 3);
        ZU_CHECK(strcmp(s, "abc") == 0);
        zu_buf_free(&b);
    }

    ZU_CASE("append survives OOM without corrupting length");
    {
        /* Must cross the current capacity to force a realloc; the first
         * allocation is 64 bytes, so a small append would never allocate. */
        char big[200];
        memset(big, 'z', sizeof big);
        ZU_CHECK(zu_buf_init(&b, 0, 0));
        ZU_CHECK(zu_buf_append_str(&b, "ab"));
        ZU_CHECK(b.cap < sizeof big);
        zu_alloc_fail_after(0);
        ZU_CHECK(!zu_buf_append(&b, big, sizeof big));
        zu_alloc_fail_after(-1);
        ZU_CHECK_EQ_INT(b.len, 2);
        ZU_CHECK_MEM(b.data, "ab", 2);
        ZU_CHECK(!zu_buf_hit_limit(&b));   /* OOM, not the cap */
        zu_buf_free(&b);
    }

    ZU_CASE("no leaks across the suite");
    {
        zu_alloc_stats st;
        zu_alloc_stats_get(&st);
        ZU_CHECK_EQ_INT(st.live_blocks, 0);
    }
}

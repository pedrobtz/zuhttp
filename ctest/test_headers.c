#include "zu_test.h"
#include "zu_headers.h"
#include "zu_alloc.h"
#include <string.h>

void suite_headers(void);

void suite_headers(void) {
    zu_headers h;

    ZU_CASE("§17.1: CR/LF in a name or value is rejected, never stripped");
    zu_headers_init(&h);
    ZU_CHECK_EQ_INT(zu_headers_add_str(&h, "X-Evil", "a\r\nInjected: 1"), ZU_ERR_PARSE);
    ZU_CHECK_EQ_INT(zu_headers_add_str(&h, "X-Evil", "a\nInjected: 1"),   ZU_ERR_PARSE);
    ZU_CHECK_EQ_INT(zu_headers_add_str(&h, "X-Evil", "a\rb"),             ZU_ERR_PARSE);
    ZU_CHECK_EQ_INT(zu_headers_add_str(&h, "X\r\nEvil", "v"),             ZU_ERR_PARSE);
    ZU_CHECK_EQ_INT(zu_headers_add_str(&h, "X Evil", "v"),                ZU_ERR_PARSE);
    ZU_CHECK_EQ_INT(zu_headers_add_str(&h, "X:Evil", "v"),                ZU_ERR_PARSE);
    ZU_CHECK_EQ_INT(zu_headers_add_str(&h, "", "v"),                      ZU_ERR_PARSE);
    ZU_CHECK_EQ_INT(h.n, 0);                    /* nothing was stored */
    zu_headers_free(&h);

    ZU_CASE("valid token names and printable values are accepted");
    zu_headers_init(&h);
    ZU_CHECK_EQ_INT(zu_headers_add_str(&h, "Content-Type", "application/json"), ZU_OK);
    ZU_CHECK_EQ_INT(zu_headers_add_str(&h, "X-Api-Key!#$%&'*+-.^_`|~", "v"), ZU_OK);
    ZU_CHECK_EQ_INT(zu_headers_add_str(&h, "X-Tab", "a\tb"), ZU_OK);   /* HTAB is legal */
    ZU_CHECK_EQ_INT(h.n, 3);
    zu_headers_free(&h);

    ZU_CASE("lookup is case-insensitive and ASCII-only");
    zu_headers_init(&h);
    zu_headers_add_str(&h, "Content-Type", "text/plain");
    ZU_CHECK(strcmp(zu_headers_get(&h, "content-type"), "text/plain") == 0);
    ZU_CHECK(strcmp(zu_headers_get(&h, "CONTENT-TYPE"), "text/plain") == 0);
    ZU_CHECK(zu_headers_get(&h, "Content-Typ") == NULL);
    ZU_CHECK(zu_headers_get(&h, "Content-Types") == NULL);
    zu_headers_free(&h);

    ZU_CASE("§18.3: duplicates are preserved and addressable, never joined");
    zu_headers_init(&h);
    zu_headers_add_str(&h, "Set-Cookie", "a=1");
    zu_headers_add_str(&h, "Set-Cookie", "b=2");
    zu_headers_add_str(&h, "Set-Cookie", "c=3");
    ZU_CHECK_EQ_INT(zu_headers_count(&h, "set-cookie"), 3);
    ZU_CHECK(strcmp(zu_headers_get_at(&h, "Set-Cookie", 0), "a=1") == 0);
    ZU_CHECK(strcmp(zu_headers_get_at(&h, "Set-Cookie", 1), "b=2") == 0);
    ZU_CHECK(strcmp(zu_headers_get_at(&h, "Set-Cookie", 2), "c=3") == 0);
    ZU_CHECK(zu_headers_get_at(&h, "Set-Cookie", 3) == NULL);
    ZU_CHECK(strcmp(zu_headers_get(&h, "Set-Cookie"), "a=1") == 0);  /* first */
    zu_headers_free(&h);

    ZU_CASE("set replaces every instance; remove removes every instance");
    zu_headers_init(&h);
    zu_headers_add_str(&h, "Accept", "a");
    zu_headers_add_str(&h, "Accept", "b");
    zu_headers_add_str(&h, "Other", "keep");
    ZU_CHECK_EQ_INT(zu_headers_set(&h, "accept", "only"), ZU_OK);
    ZU_CHECK_EQ_INT(zu_headers_count(&h, "Accept"), 1);
    ZU_CHECK(strcmp(zu_headers_get(&h, "Accept"), "only") == 0);
    ZU_CHECK(strcmp(zu_headers_get(&h, "Other"), "keep") == 0);
    ZU_CHECK_EQ_INT(zu_headers_remove(&h, "ACCEPT"), 1);
    ZU_CHECK_EQ_INT(zu_headers_count(&h, "Accept"), 0);
    ZU_CHECK_EQ_INT(h.n, 1);
    zu_headers_free(&h);

    ZU_CASE("a rejected set does not destroy the existing value");
    zu_headers_init(&h);
    zu_headers_add_str(&h, "Authorization", "Bearer good");
    ZU_CHECK_EQ_INT(zu_headers_set(&h, "Authorization", "bad\r\nX: 1"), ZU_ERR_PARSE);
    ZU_CHECK(strcmp(zu_headers_get(&h, "Authorization"), "Bearer good") == 0);
    zu_headers_free(&h);

    ZU_CASE("§40: count, name, value and total-byte limits are enforced");
    zu_headers_init_limited(&h, 2, 8, 16, 0);
    ZU_CHECK_EQ_INT(zu_headers_add_str(&h, "A", "1"), ZU_OK);
    ZU_CHECK_EQ_INT(zu_headers_add_str(&h, "B", "2"), ZU_OK);
    ZU_CHECK_EQ_INT(zu_headers_add_str(&h, "C", "3"), ZU_ERR_BODY_LIMIT);  /* count */
    zu_headers_free(&h);

    zu_headers_init_limited(&h, 0, 8, 16, 0);
    ZU_CHECK_EQ_INT(zu_headers_add_str(&h, "ThisNameIsWayTooLong", "v"), ZU_ERR_BODY_LIMIT);
    ZU_CHECK_EQ_INT(zu_headers_add_str(&h, "Ok", "0123456789abcdefghij"), ZU_ERR_BODY_LIMIT);
    zu_headers_free(&h);

    zu_headers_init_limited(&h, 0, 0, 0, 20);
    ZU_CHECK_EQ_INT(zu_headers_add_str(&h, "AAAA", "bbbb"), ZU_OK);        /* 12 bytes */
    ZU_CHECK_EQ_INT(zu_headers_add_str(&h, "CCCC", "dddd"), ZU_ERR_BODY_LIMIT);
    zu_headers_free(&h);

    ZU_CASE("removal reclaims the byte budget");
    zu_headers_init_limited(&h, 0, 0, 0, 20);
    ZU_CHECK_EQ_INT(zu_headers_add_str(&h, "AAAA", "bbbb"), ZU_OK);
    ZU_CHECK_EQ_INT(zu_headers_remove(&h, "AAAA"), 1);
    ZU_CHECK_EQ_INT(zu_headers_add_str(&h, "CCCC", "dddd"), ZU_OK);
    zu_headers_free(&h);

    ZU_CASE("serialisation preserves order and original case");
    {
        zu_buffer b; const char *s;
        zu_headers_init(&h);
        zu_headers_add_str(&h, "Host", "example.com");
        zu_headers_add_str(&h, "X-Second", "2");
        zu_buf_init(&b, 0, 0);
        ZU_CHECK(zu_headers_write(&h, &b));
        ZU_CHECK(zu_buf_cstr(&b, &s));
        ZU_CHECK(strcmp(s, "Host: example.com\r\nX-Second: 2\r\n") == 0);
        zu_buf_free(&b);
        zu_headers_free(&h);
    }

    ZU_CASE("no leaks across the suite");
    {
        zu_alloc_stats st;
        zu_alloc_stats_get(&st);
        ZU_CHECK_EQ_INT(st.live_blocks, 0);
    }
}

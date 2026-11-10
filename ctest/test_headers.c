#include "zuh_test.h"
#include "zuh_headers.h"
#include "zuh_alloc.h"
#include <string.h>

void suite_headers(void);

void suite_headers(void) {
    zuh_headers h;

    ZUH_CASE("§17.1: CR/LF in a name or value is rejected, never stripped");
    zuh_headers_init(&h);
    ZUH_CHECK_EQ_INT(zuh_headers_add_str(&h, "X-Evil", "a\r\nInjected: 1"), ZUH_ERR_PARSE);
    ZUH_CHECK_EQ_INT(zuh_headers_add_str(&h, "X-Evil", "a\nInjected: 1"),   ZUH_ERR_PARSE);
    ZUH_CHECK_EQ_INT(zuh_headers_add_str(&h, "X-Evil", "a\rb"),             ZUH_ERR_PARSE);
    ZUH_CHECK_EQ_INT(zuh_headers_add_str(&h, "X\r\nEvil", "v"),             ZUH_ERR_PARSE);
    ZUH_CHECK_EQ_INT(zuh_headers_add_str(&h, "X Evil", "v"),                ZUH_ERR_PARSE);
    ZUH_CHECK_EQ_INT(zuh_headers_add_str(&h, "X:Evil", "v"),                ZUH_ERR_PARSE);
    ZUH_CHECK_EQ_INT(zuh_headers_add_str(&h, "", "v"),                      ZUH_ERR_PARSE);
    ZUH_CHECK_EQ_INT(h.n, 0);                    /* nothing was stored */
    zuh_headers_free(&h);

    ZUH_CASE("valid token names and printable values are accepted");
    zuh_headers_init(&h);
    ZUH_CHECK_EQ_INT(zuh_headers_add_str(&h, "Content-Type", "application/json"), ZUH_OK);
    ZUH_CHECK_EQ_INT(zuh_headers_add_str(&h, "X-Api-Key!#$%&'*+-.^_`|~", "v"), ZUH_OK);
    ZUH_CHECK_EQ_INT(zuh_headers_add_str(&h, "X-Tab", "a\tb"), ZUH_OK);   /* HTAB is legal */
    ZUH_CHECK_EQ_INT(h.n, 3);
    zuh_headers_free(&h);

    ZUH_CASE("lookup is case-insensitive and ASCII-only");
    zuh_headers_init(&h);
    zuh_headers_add_str(&h, "Content-Type", "text/plain");
    ZUH_CHECK(strcmp(zuh_headers_get(&h, "content-type"), "text/plain") == 0);
    ZUH_CHECK(strcmp(zuh_headers_get(&h, "CONTENT-TYPE"), "text/plain") == 0);
    ZUH_CHECK(zuh_headers_get(&h, "Content-Typ") == NULL);
    ZUH_CHECK(zuh_headers_get(&h, "Content-Types") == NULL);
    zuh_headers_free(&h);

    ZUH_CASE("§18.3: duplicates are preserved and addressable, never joined");
    zuh_headers_init(&h);
    zuh_headers_add_str(&h, "Set-Cookie", "a=1");
    zuh_headers_add_str(&h, "Set-Cookie", "b=2");
    zuh_headers_add_str(&h, "Set-Cookie", "c=3");
    ZUH_CHECK_EQ_INT(zuh_headers_count(&h, "set-cookie"), 3);
    ZUH_CHECK(strcmp(zuh_headers_get_at(&h, "Set-Cookie", 0), "a=1") == 0);
    ZUH_CHECK(strcmp(zuh_headers_get_at(&h, "Set-Cookie", 1), "b=2") == 0);
    ZUH_CHECK(strcmp(zuh_headers_get_at(&h, "Set-Cookie", 2), "c=3") == 0);
    ZUH_CHECK(zuh_headers_get_at(&h, "Set-Cookie", 3) == NULL);
    ZUH_CHECK(strcmp(zuh_headers_get(&h, "Set-Cookie"), "a=1") == 0);  /* first */
    zuh_headers_free(&h);

    ZUH_CASE("set replaces every instance; remove removes every instance");
    zuh_headers_init(&h);
    zuh_headers_add_str(&h, "Accept", "a");
    zuh_headers_add_str(&h, "Accept", "b");
    zuh_headers_add_str(&h, "Other", "keep");
    ZUH_CHECK_EQ_INT(zuh_headers_set(&h, "accept", "only"), ZUH_OK);
    ZUH_CHECK_EQ_INT(zuh_headers_count(&h, "Accept"), 1);
    ZUH_CHECK(strcmp(zuh_headers_get(&h, "Accept"), "only") == 0);
    ZUH_CHECK(strcmp(zuh_headers_get(&h, "Other"), "keep") == 0);
    ZUH_CHECK_EQ_INT(zuh_headers_remove(&h, "ACCEPT"), 1);
    ZUH_CHECK_EQ_INT(zuh_headers_count(&h, "Accept"), 0);
    ZUH_CHECK_EQ_INT(h.n, 1);
    zuh_headers_free(&h);

    ZUH_CASE("a rejected set does not destroy the existing value");
    zuh_headers_init(&h);
    zuh_headers_add_str(&h, "Authorization", "Bearer good");
    ZUH_CHECK_EQ_INT(zuh_headers_set(&h, "Authorization", "bad\r\nX: 1"), ZUH_ERR_PARSE);
    ZUH_CHECK(strcmp(zuh_headers_get(&h, "Authorization"), "Bearer good") == 0);
    zuh_headers_free(&h);

    ZUH_CASE("§40: count, name, value and total-byte limits are enforced");
    zuh_headers_init_limited(&h, 2, 8, 16, 0);
    ZUH_CHECK_EQ_INT(zuh_headers_add_str(&h, "A", "1"), ZUH_OK);
    ZUH_CHECK_EQ_INT(zuh_headers_add_str(&h, "B", "2"), ZUH_OK);
    ZUH_CHECK_EQ_INT(zuh_headers_add_str(&h, "C", "3"), ZUH_ERR_BODY_LIMIT);  /* count */
    zuh_headers_free(&h);

    zuh_headers_init_limited(&h, 0, 8, 16, 0);
    ZUH_CHECK_EQ_INT(zuh_headers_add_str(&h, "ThisNameIsWayTooLong", "v"), ZUH_ERR_BODY_LIMIT);
    ZUH_CHECK_EQ_INT(zuh_headers_add_str(&h, "Ok", "0123456789abcdefghij"), ZUH_ERR_BODY_LIMIT);
    zuh_headers_free(&h);

    /* D-101: a field costs name + value + 32, so two of 40 pass 80 and not 79. */
    zuh_headers_init_limited(&h, 0, 0, 0, 79);
    ZUH_CHECK_EQ_INT(zuh_headers_add_str(&h, "AAAA", "bbbb"), ZUH_OK);        /* 40 bytes */
    ZUH_CHECK_EQ_INT(zuh_headers_add_str(&h, "CCCC", "dddd"), ZUH_ERR_BODY_LIMIT);
    zuh_headers_free(&h);
    zuh_headers_init_limited(&h, 0, 0, 0, 80);
    ZUH_CHECK_EQ_INT(zuh_headers_add_str(&h, "AAAA", "bbbb"), ZUH_OK);
    ZUH_CHECK_EQ_INT(zuh_headers_add_str(&h, "CCCC", "dddd"), ZUH_OK);
    zuh_headers_free(&h);

    ZUH_CASE("removal reclaims the byte budget");
    zuh_headers_init_limited(&h, 0, 0, 0, 79);
    ZUH_CHECK_EQ_INT(zuh_headers_add_str(&h, "AAAA", "bbbb"), ZUH_OK);
    ZUH_CHECK_EQ_INT(zuh_headers_remove(&h, "AAAA"), 1);
    ZUH_CHECK_EQ_INT(zuh_headers_add_str(&h, "CCCC", "dddd"), ZUH_OK);
    zuh_headers_free(&h);

    /* PR #261's survivors: the count itself, after each step. Removing what
     * was added gives back exactly its cost (D-101), so the total returns
     * to 0 and a later add is charged from there, not from a stale sum. */
    ZUH_CASE("the byte count follows add, remove and add exactly (D-101)");
    zuh_headers_init_limited(&h, 0, 0, 0, 0);
    ZUH_CHECK_EQ_INT(zuh_headers_add_str(&h, "AAAA", "bbbbbb"), ZUH_OK);
    ZUH_CHECK_EQ_INT(h.bytes, 4 + 6 + ZUH_HEADER_FIELD_OVERHEAD);
    ZUH_CHECK_EQ_INT(zuh_headers_add_str(&h, "aaaa", "c"), ZUH_OK);
    ZUH_CHECK_EQ_INT(h.bytes, 4 + 6 + 4 + 1 + 2 * ZUH_HEADER_FIELD_OVERHEAD);
    ZUH_CHECK_EQ_INT(zuh_headers_add_str(&h, "Z", ""), ZUH_OK);
    ZUH_CHECK_EQ_INT(zuh_headers_remove(&h, "AAAA"), 2);      /* both spellings */
    ZUH_CHECK_EQ_INT(h.bytes, 1 + ZUH_HEADER_FIELD_OVERHEAD);
    ZUH_CHECK_EQ_INT(zuh_headers_remove(&h, "Z"), 1);
    ZUH_CHECK_EQ_INT(h.bytes, 0);
    ZUH_CHECK_EQ_INT(zuh_headers_add_str(&h, "Q", "r"), ZUH_OK);
    ZUH_CHECK_EQ_INT(h.bytes, 2 + ZUH_HEADER_FIELD_OVERHEAD);
    zuh_headers_free(&h);

    ZUH_CASE("serialisation preserves order and original case");
    {
        zuh_buffer b; const char *s;
        zuh_headers_init(&h);
        zuh_headers_add_str(&h, "Host", "example.com");
        zuh_headers_add_str(&h, "X-Second", "2");
        zuh_buf_init(&b, 0, 0);
        ZUH_CHECK(zuh_headers_write(&h, &b));
        ZUH_CHECK(zuh_buf_cstr(&b, &s));
        ZUH_CHECK(strcmp(s, "Host: example.com\r\nX-Second: 2\r\n") == 0);
        zuh_buf_free(&b);
        zuh_headers_free(&h);
    }

    /* #271: zuh_ascii_ncasecmp orders like strcmp after lowering, by length
     * first; equal names compare 0 in any case. */
    ZUH_CASE("#271: zuh_ascii_ncasecmp orders in both directions");
    {
        ZUH_CHECK(zuh_ascii_ncasecmp("a", 1, "b", 1) < 0);
        ZUH_CHECK(zuh_ascii_ncasecmp("b", 1, "a", 1) > 0);
        ZUH_CHECK(zuh_ascii_ncasecmp("B", 1, "a", 1) > 0);
        ZUH_CHECK(zuh_ascii_ncasecmp("a", 1, "ab", 2) < 0);
        ZUH_CHECK(zuh_ascii_ncasecmp("ab", 2, "a", 1) > 0);
        ZUH_CHECK(zuh_ascii_ncasecmp("Ab", 2, "aB", 2) == 0);
        /* Every ASCII boundary of the case fold: '@' '[' '`' '{' are not
         * letters and fold to nothing. */
        ZUH_CHECK(zuh_ascii_ncasecmp("@", 1, "`", 1) != 0);
        ZUH_CHECK(zuh_ascii_ncasecmp("[", 1, "{", 1) != 0);
        ZUH_CHECK(zuh_ascii_ncasecmp("A", 1, "a", 1) == 0);
        ZUH_CHECK(zuh_ascii_ncasecmp("Z", 1, "z", 1) == 0);
    }

    ZUH_CASE("#271: zuh_headers_at answers at the last index and not one past it");
    {
        const char *n, *v;
        zuh_headers_init(&h);
        zuh_headers_add_str(&h, "A", "1");
        zuh_headers_add_str(&h, "B", "2");
        ZUH_CHECK(zuh_headers_at(&h, 1, &n, &v) && strcmp(n, "B") == 0 && strcmp(v, "2") == 0);
        ZUH_CHECK(!zuh_headers_at(&h, 2, &n, &v));
        zuh_headers_free(&h);
    }

    ZUH_CASE("#271: a NULL value is valid only when empty");
    ZUH_CHECK(zuh_header_value_valid(NULL, 0));
    ZUH_CHECK(!zuh_header_value_valid(NULL, 1));

    ZUH_CASE("no leaks across the suite");
    {
        zuh_alloc_stats st;
        zuh_alloc_stats_get(&st);
        ZUH_CHECK_EQ_INT(st.live_blocks, 0);
    }
}

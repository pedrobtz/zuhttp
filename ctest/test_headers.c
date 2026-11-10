#include "zuh_test.h"
#include "zuh_headers.h"
#include "zuh_alloc.h"
#include <string.h>

void suite_headers(void);

/* #275: an oracle for zuh_utf8_valid() that shares nothing with it. The
 * validator works from a table of first-byte ranges and second-byte bounds;
 * this decodes the code point and asks RFC 3629's questions of it: the
 * right number of 10xxxxxx bytes, the shortest form, not a surrogate, not
 * past U+10FFFF. */
static int ref_utf8_valid(const unsigned char *p, size_t len) {
    size_t i = 0;
    while (i < len) {
        unsigned c = p[i], cp, min;
        size_t need, k;
        if (c < 0x80) { i++; continue; }
        if ((c & 0xE0) == 0xC0)      { need = 1; cp = c & 0x1F; min = 0x80; }
        else if ((c & 0xF0) == 0xE0) { need = 2; cp = c & 0x0F; min = 0x800; }
        else if ((c & 0xF8) == 0xF0) { need = 3; cp = c & 0x07; min = 0x10000; }
        else return 0;
        if (len - i <= need) return 0;
        for (k = 1; k <= need; k++) {
            if ((p[i + k] & 0xC0) != 0x80) return 0;
            cp = (cp << 6) | (p[i + k] & 0x3F);
        }
        if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return 0;
        i += need + 1;
    }
    return 1;
}

/* One sequence, alone and between ASCII bytes, and every proper prefix of it
 * with the rest of the bytes still in memory after `len`, so a validator
 * that reads past its length accepts what it should not. */
static int utf8_agrees(const unsigned char *seq, size_t n) {
    unsigned char buf[8];
    size_t cut;
    if (zuh_utf8_valid((const char *)seq, n) != ref_utf8_valid(seq, n)) return 0;
    buf[0] = 'a'; memcpy(buf + 1, seq, n); buf[n + 1] = 'b';
    if (zuh_utf8_valid((const char *)buf, n + 2) != ref_utf8_valid(buf, n + 2)) return 0;
    for (cut = 1; cut < n; cut++)
        if (zuh_utf8_valid((const char *)seq, cut) != ref_utf8_valid(seq, cut)) return 0;
    return 1;
}

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

    ZUH_CASE("#275: zuh_utf8_valid agrees with an independent decoder");
    {
        /* Every 1- and 2-byte string; every 3-byte one whose last byte is at
         * a continuation boundary; every 4-byte one whose 2nd byte is at one
         * of the bounds the table uses and whose 3rd and 4th are at a
         * continuation boundary. Each first byte and each table bound is
         * met on both sides. */
        static const unsigned char edge[] = { 0x00, 0x7F, 0x80, 0xBF, 0xC0, 0xFF };
        static const unsigned char edge2[] = {
            0x00, 0x7F, 0x80, 0x8F, 0x90, 0x9F, 0xA0, 0xBF, 0xC0, 0xFF };
        unsigned a, b, c, d;
        unsigned long bad = 0, valid = 0;
        unsigned char q[4];
        for (a = 0; a < 256; a++) {
            q[0] = (unsigned char)a;
            if (!utf8_agrees(q, 1)) bad++;
            for (b = 0; b < 256; b++) {
                q[1] = (unsigned char)b;
                if (!utf8_agrees(q, 2)) bad++;
                valid += (unsigned long)ref_utf8_valid(q, 2);
                for (c = 0; c < sizeof edge; c++) {
                    q[2] = edge[c];
                    if (!utf8_agrees(q, 3)) bad++;
                    valid += (unsigned long)ref_utf8_valid(q, 3);
                }
            }
            for (b = 0; b < sizeof edge2; b++) for (c = 0; c < sizeof edge; c++)
                for (d = 0; d < sizeof edge; d++) {
                    q[1] = edge2[b]; q[2] = edge[c]; q[3] = edge[d];
                    if (!utf8_agrees(q, 4)) bad++;
                    valid += (unsigned long)ref_utf8_valid(q, 4);
                }
        }
        ZUH_CHECK_EQ_INT(bad, 0);
        ZUH_CHECK(valid > 1000);            /* the sweep met valid input too */
    }

    ZUH_CASE("#275: the UTF-8 cases by name (Kuhn's stress test)");
    {
        ZUH_CHECK(zuh_utf8_valid(NULL, 0));
        ZUH_CHECK(!zuh_utf8_valid(NULL, 1));
        ZUH_CHECK(zuh_utf8_valid("", 0));
        ZUH_CHECK(zuh_utf8_valid("\x7F", 1));
        ZUH_CHECK(zuh_utf8_valid("\xC2\x80", 2));            /* U+0080 */
        ZUH_CHECK(!zuh_utf8_valid("\xC1\xBF", 2));           /* overlong U+007F */
        ZUH_CHECK(zuh_utf8_valid("\xE0\xA0\x80", 3));       /* U+0800 */
        ZUH_CHECK(!zuh_utf8_valid("\xE0\x9F\xBF", 3));      /* overlong U+07FF */
        ZUH_CHECK(zuh_utf8_valid("\xED\x9F\xBF", 3));       /* U+D7FF */
        ZUH_CHECK(!zuh_utf8_valid("\xED\xA0\x80", 3));      /* U+D800, a surrogate */
        ZUH_CHECK(zuh_utf8_valid("\xEE\x80\x80", 3));       /* U+E000 */
        ZUH_CHECK(zuh_utf8_valid("\xF0\x90\x80\x80", 4));   /* U+10000 */
        ZUH_CHECK(!zuh_utf8_valid("\xF0\x8F\xBF\xBF", 4));  /* overlong U+FFFF */
        ZUH_CHECK(zuh_utf8_valid("\xF4\x8F\xBF\xBF", 4));   /* U+10FFFF */
        ZUH_CHECK(!zuh_utf8_valid("\xF4\x90\x80\x80", 4));  /* U+110000 */
        ZUH_CHECK(!zuh_utf8_valid("\xF5\x80\x80\x80", 4));
        ZUH_CHECK(!zuh_utf8_valid("\xF0\x90\x80", 3));      /* truncated at the end */
        ZUH_CHECK(!zuh_utf8_valid("a\xC2", 2));
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

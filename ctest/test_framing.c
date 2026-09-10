#include "zu_test.h"
#include "zu_framing.h"
#include "zu_alloc.h"
#include <string.h>

void suite_framing(void);

/* Each row of the §18.1 table is a test. */
static zu_code decide(zu_headers *h, int status, int head, zu_framing *f) {
    zu_error e;
    zu_error_clear(&e);
    return zu_framing_decide(h, status, head, f, &e);
}

void suite_framing(void) {
    zu_headers h;
    zu_framing f;

    ZU_CASE("strict u64: digits only, overflow-checked");
    {
        uint64_t v;
        ZU_CHECK(zu_parse_u64_strict("0", 1, &v) && v == 0);
        ZU_CHECK(zu_parse_u64_strict("12345", 5, &v) && v == 12345);
        ZU_CHECK(zu_parse_u64_strict("18446744073709551615", 20, &v)
                 && v == 18446744073709551615ull);
        ZU_CHECK(!zu_parse_u64_strict("18446744073709551616", 20, &v)); /* overflow */
        ZU_CHECK(!zu_parse_u64_strict("99999999999999999999", 20, &v));
        ZU_CHECK(!zu_parse_u64_strict("+5", 2, &v));
        ZU_CHECK(!zu_parse_u64_strict("-5", 2, &v));
        ZU_CHECK(!zu_parse_u64_strict("5 ", 2, &v));
        ZU_CHECK(!zu_parse_u64_strict(" 5", 2, &v));
        ZU_CHECK(!zu_parse_u64_strict("0x5", 3, &v));
        ZU_CHECK(!zu_parse_u64_strict("5,5", 3, &v));
        ZU_CHECK(!zu_parse_u64_strict("", 0, &v));
    }

    ZU_CASE("row: Transfer-Encoding chunked => chunked framing");
    zu_headers_init(&h);
    zu_headers_add_str(&h, "Transfer-Encoding", "chunked");
    ZU_CHECK_EQ_INT(decide(&h, 200, 0, &f), ZU_OK);
    ZU_CHECK_EQ_INT(f.kind, ZU_FRAME_CHUNKED);
    ZU_CHECK(f.poolable);
    zu_headers_free(&h);

    ZU_CASE("row: chunked is matched case-insensitively and OWS-tolerantly");
    zu_headers_init(&h);
    zu_headers_add_str(&h, "Transfer-Encoding", "  ChUnKeD\t");
    ZU_CHECK_EQ_INT(decide(&h, 200, 0, &f), ZU_OK);
    ZU_CHECK_EQ_INT(f.kind, ZU_FRAME_CHUNKED);
    zu_headers_free(&h);

    ZU_CASE("row: TE present but not chunked => REJECT");
    {
        const char *bad[] = { "gzip", "gzip, chunked", "chunked, gzip",
                              "identity", "chunked;q=1", "" };
        size_t i;
        for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            zu_headers_init(&h);
            zu_headers_add_str(&h, "Transfer-Encoding", bad[i]);
            ZU_CHECK_EQ_INT(decide(&h, 200, 0, &f), ZU_ERR_PARSE);
            zu_headers_free(&h);
        }
    }

    ZU_CASE("row: CL + TE together => REJECT, with no preference for either");
    zu_headers_init(&h);
    zu_headers_add_str(&h, "Content-Length", "5");
    zu_headers_add_str(&h, "Transfer-Encoding", "chunked");
    ZU_CHECK_EQ_INT(decide(&h, 200, 0, &f), ZU_ERR_PARSE);
    zu_headers_free(&h);

    ZU_CASE("row: duplicate Content-Length with DIFFERING values => REJECT");
    zu_headers_init(&h);
    zu_headers_add_str(&h, "Content-Length", "5");
    zu_headers_add_str(&h, "Content-Length", "6");
    ZU_CHECK_EQ_INT(decide(&h, 200, 0, &f), ZU_ERR_PARSE);
    zu_headers_free(&h);

    ZU_CASE("row: duplicate Content-Length with IDENTICAL values => still REJECT");
    zu_headers_init(&h);
    zu_headers_add_str(&h, "Content-Length", "5");
    zu_headers_add_str(&h, "Content-Length", "5");
    ZU_CHECK_EQ_INT(decide(&h, 200, 0, &f), ZU_ERR_PARSE);
    zu_headers_free(&h);

    ZU_CASE("row: duplicate Transfer-Encoding => REJECT");
    zu_headers_init(&h);
    zu_headers_add_str(&h, "Transfer-Encoding", "chunked");
    zu_headers_add_str(&h, "Transfer-Encoding", "chunked");
    ZU_CHECK_EQ_INT(decide(&h, 200, 0, &f), ZU_ERR_PARSE);
    zu_headers_free(&h);

    ZU_CASE("row: a malformed or overflowing Content-Length => REJECT");
    {
        const char *bad[] = { "5, 5", "+5", "-1", "0x10", "5x", "", " ",
                              "18446744073709551616", "1 1" };
        size_t i;
        for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            zu_headers_init(&h);
            zu_headers_add_str(&h, "Content-Length", bad[i]);
            ZU_CHECK_EQ_INT(decide(&h, 200, 0, &f), ZU_ERR_PARSE);
            zu_headers_free(&h);
        }
    }

    ZU_CASE("row: a single valid Content-Length => length framing");
    zu_headers_init(&h);
    zu_headers_add_str(&h, "Content-Length", " 1234 ");   /* OWS is trimmed */
    ZU_CHECK_EQ_INT(decide(&h, 200, 0, &f), ZU_OK);
    ZU_CHECK_EQ_INT(f.kind, ZU_FRAME_LENGTH);
    ZU_CHECK_EQ_INT(f.length, 1234);
    zu_headers_free(&h);

    ZU_CASE("row: no framing headers => read to close, NOT poolable (§26.3)");
    zu_headers_init(&h);
    ZU_CHECK_EQ_INT(decide(&h, 200, 0, &f), ZU_OK);
    ZU_CHECK_EQ_INT(f.kind, ZU_FRAME_UNTIL_CLOSE);
    ZU_CHECK(!f.poolable);
    zu_headers_free(&h);

    ZU_CASE("row: HEAD has no body even with Content-Length");
    zu_headers_init(&h);
    zu_headers_add_str(&h, "Content-Length", "1234");
    ZU_CHECK_EQ_INT(decide(&h, 200, 1, &f), ZU_OK);
    ZU_CHECK_EQ_INT(f.kind, ZU_FRAME_NONE);
    ZU_CHECK_EQ_INT(f.length, 0);
    ZU_CHECK(f.poolable);
    zu_headers_free(&h);

    ZU_CASE("row: 204, 304 and 1xx never have a body");
    {
        int codes[] = { 100, 101, 199, 204, 304 };
        size_t i;
        for (i = 0; i < sizeof codes / sizeof codes[0]; i++) {
            zu_headers_init(&h);
            zu_headers_add_str(&h, "Content-Length", "99");
            ZU_CHECK_EQ_INT(decide(&h, codes[i], 0, &f), ZU_OK);
            ZU_CHECK_EQ_INT(f.kind, ZU_FRAME_NONE);
            zu_headers_free(&h);
        }
    }

    /* A bodyless status must not become a way to smuggle past the checks. */
    ZU_CASE("a bodyless status still validates its framing headers first");
    zu_headers_init(&h);
    zu_headers_add_str(&h, "Content-Length", "5");
    zu_headers_add_str(&h, "Content-Length", "6");
    ZU_CHECK_EQ_INT(decide(&h, 204, 0, &f), ZU_ERR_PARSE);
    zu_headers_free(&h);

    zu_headers_init(&h);
    zu_headers_add_str(&h, "Content-Length", "5");
    zu_headers_add_str(&h, "Transfer-Encoding", "chunked");
    ZU_CHECK_EQ_INT(decide(&h, 304, 0, &f), ZU_ERR_PARSE);
    zu_headers_free(&h);

    zu_headers_init(&h);
    zu_headers_add_str(&h, "Content-Length", "5, 5");
    ZU_CHECK_EQ_INT(decide(&h, 204, 1, &f), ZU_ERR_PARSE);
    zu_headers_free(&h);

    ZU_CASE("an out-of-range status is rejected");
    zu_headers_init(&h);
    ZU_CHECK_EQ_INT(decide(&h, 99,  0, &f), ZU_ERR_PARSE);
    ZU_CHECK_EQ_INT(decide(&h, 600, 0, &f), ZU_ERR_PARSE);
    ZU_CHECK_EQ_INT(decide(&h, 0,   0, &f), ZU_ERR_PARSE);
    ZU_CHECK_EQ_INT(decide(&h, -1,  0, &f), ZU_ERR_PARSE);
    zu_headers_free(&h);

    ZU_CASE("Content-Length: 0 is a valid empty body, not 'no framing'");
    zu_headers_init(&h);
    zu_headers_add_str(&h, "Content-Length", "0");
    ZU_CHECK_EQ_INT(decide(&h, 200, 0, &f), ZU_OK);
    ZU_CHECK_EQ_INT(f.kind, ZU_FRAME_LENGTH);
    ZU_CHECK_EQ_INT(f.length, 0);
    ZU_CHECK(f.poolable);
    zu_headers_free(&h);

    ZU_CASE("no leaks across the suite");
    {
        zu_alloc_stats st;
        zu_alloc_stats_get(&st);
        ZU_CHECK_EQ_INT(st.live_blocks, 0);
    }
}

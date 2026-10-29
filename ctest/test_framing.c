#include "zuh_test.h"
#include "zuh_framing.h"
#include "zuh_alloc.h"
#include <string.h>

void suite_framing(void);

/* Each row of the §18.1 table is a test. */
static zuh_code decide(zuh_headers *h, int status, int head, zuh_framing *f) {
    zuh_error e;
    zuh_error_clear(&e);
    return zuh_framing_decide(h, status, head, f, &e);
}

void suite_framing(void) {
    zuh_headers h;
    zuh_framing f;

    ZUH_CASE("strict u64: digits only, overflow-checked");
    {
        uint64_t v;
        ZUH_CHECK(zuh_parse_u64_strict("0", 1, &v) && v == 0);
        ZUH_CHECK(zuh_parse_u64_strict("12345", 5, &v) && v == 12345);
        ZUH_CHECK(zuh_parse_u64_strict("18446744073709551615", 20, &v)
                 && v == 18446744073709551615ull);
        ZUH_CHECK(!zuh_parse_u64_strict("18446744073709551616", 20, &v)); /* overflow */
        ZUH_CHECK(!zuh_parse_u64_strict("99999999999999999999", 20, &v));
        ZUH_CHECK(!zuh_parse_u64_strict("+5", 2, &v));
        ZUH_CHECK(!zuh_parse_u64_strict("-5", 2, &v));
        ZUH_CHECK(!zuh_parse_u64_strict("5 ", 2, &v));
        ZUH_CHECK(!zuh_parse_u64_strict(" 5", 2, &v));
        ZUH_CHECK(!zuh_parse_u64_strict("0x5", 3, &v));
        ZUH_CHECK(!zuh_parse_u64_strict("5,5", 3, &v));
        ZUH_CHECK(!zuh_parse_u64_strict("", 0, &v));
    }

    ZUH_CASE("row: Transfer-Encoding chunked => chunked framing");
    zuh_headers_init(&h);
    zuh_headers_add_str(&h, "Transfer-Encoding", "chunked");
    ZUH_CHECK_EQ_INT(decide(&h, 200, 0, &f), ZUH_OK);
    ZUH_CHECK_EQ_INT(f.kind, ZUH_FRAME_CHUNKED);
    ZUH_CHECK(f.poolable);
    zuh_headers_free(&h);

    ZUH_CASE("row: chunked is matched case-insensitively and OWS-tolerantly");
    zuh_headers_init(&h);
    zuh_headers_add_str(&h, "Transfer-Encoding", "  ChUnKeD\t");
    ZUH_CHECK_EQ_INT(decide(&h, 200, 0, &f), ZUH_OK);
    ZUH_CHECK_EQ_INT(f.kind, ZUH_FRAME_CHUNKED);
    zuh_headers_free(&h);

    ZUH_CASE("row: TE present but not chunked => REJECT");
    {
        const char *bad[] = { "gzip", "gzip, chunked", "chunked, gzip",
                              "identity", "chunked;q=1", "" };
        size_t i;
        for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            zuh_headers_init(&h);
            zuh_headers_add_str(&h, "Transfer-Encoding", bad[i]);
            ZUH_CHECK_EQ_INT(decide(&h, 200, 0, &f), ZUH_ERR_PARSE);
            zuh_headers_free(&h);
        }
    }

    ZUH_CASE("row: CL + TE together => REJECT, with no preference for either");
    zuh_headers_init(&h);
    zuh_headers_add_str(&h, "Content-Length", "5");
    zuh_headers_add_str(&h, "Transfer-Encoding", "chunked");
    ZUH_CHECK_EQ_INT(decide(&h, 200, 0, &f), ZUH_ERR_PARSE);
    zuh_headers_free(&h);

    ZUH_CASE("row: duplicate Content-Length with DIFFERING values => REJECT");
    zuh_headers_init(&h);
    zuh_headers_add_str(&h, "Content-Length", "5");
    zuh_headers_add_str(&h, "Content-Length", "6");
    ZUH_CHECK_EQ_INT(decide(&h, 200, 0, &f), ZUH_ERR_PARSE);
    zuh_headers_free(&h);

    ZUH_CASE("row: duplicate Content-Length with IDENTICAL values => still REJECT");
    zuh_headers_init(&h);
    zuh_headers_add_str(&h, "Content-Length", "5");
    zuh_headers_add_str(&h, "Content-Length", "5");
    ZUH_CHECK_EQ_INT(decide(&h, 200, 0, &f), ZUH_ERR_PARSE);
    zuh_headers_free(&h);

    ZUH_CASE("row: duplicate Transfer-Encoding => REJECT");
    zuh_headers_init(&h);
    zuh_headers_add_str(&h, "Transfer-Encoding", "chunked");
    zuh_headers_add_str(&h, "Transfer-Encoding", "chunked");
    ZUH_CHECK_EQ_INT(decide(&h, 200, 0, &f), ZUH_ERR_PARSE);
    zuh_headers_free(&h);

    ZUH_CASE("row: a malformed or overflowing Content-Length => REJECT");
    {
        const char *bad[] = { "5, 5", "+5", "-1", "0x10", "5x", "", " ",
                              "18446744073709551616", "1 1" };
        size_t i;
        for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            zuh_headers_init(&h);
            zuh_headers_add_str(&h, "Content-Length", bad[i]);
            ZUH_CHECK_EQ_INT(decide(&h, 200, 0, &f), ZUH_ERR_PARSE);
            zuh_headers_free(&h);
        }
    }

    ZUH_CASE("row: a single valid Content-Length => length framing");
    zuh_headers_init(&h);
    zuh_headers_add_str(&h, "Content-Length", " 1234 ");   /* OWS is trimmed */
    ZUH_CHECK_EQ_INT(decide(&h, 200, 0, &f), ZUH_OK);
    ZUH_CHECK_EQ_INT(f.kind, ZUH_FRAME_LENGTH);
    ZUH_CHECK_EQ_INT(f.length, 1234);
    zuh_headers_free(&h);

    ZUH_CASE("row: no framing headers => read to close, NOT poolable (§26.3)");
    zuh_headers_init(&h);
    ZUH_CHECK_EQ_INT(decide(&h, 200, 0, &f), ZUH_OK);
    ZUH_CHECK_EQ_INT(f.kind, ZUH_FRAME_UNTIL_CLOSE);
    ZUH_CHECK(!f.poolable);
    zuh_headers_free(&h);

    ZUH_CASE("row: HEAD has no body even with Content-Length");
    zuh_headers_init(&h);
    zuh_headers_add_str(&h, "Content-Length", "1234");
    ZUH_CHECK_EQ_INT(decide(&h, 200, 1, &f), ZUH_OK);
    ZUH_CHECK_EQ_INT(f.kind, ZUH_FRAME_NONE);
    ZUH_CHECK_EQ_INT(f.length, 0);
    ZUH_CHECK(f.poolable);
    zuh_headers_free(&h);

    ZUH_CASE("row: 204, 304 and 1xx never have a body");
    {
        int codes[] = { 100, 101, 199, 204, 304 };
        size_t i;
        for (i = 0; i < sizeof codes / sizeof codes[0]; i++) {
            zuh_headers_init(&h);
            zuh_headers_add_str(&h, "Content-Length", "99");
            ZUH_CHECK_EQ_INT(decide(&h, codes[i], 0, &f), ZUH_OK);
            ZUH_CHECK_EQ_INT(f.kind, ZUH_FRAME_NONE);
            zuh_headers_free(&h);
        }
    }

    /* A bodyless status must not become a way to smuggle past the checks. */
    ZUH_CASE("a bodyless status still validates its framing headers first");
    zuh_headers_init(&h);
    zuh_headers_add_str(&h, "Content-Length", "5");
    zuh_headers_add_str(&h, "Content-Length", "6");
    ZUH_CHECK_EQ_INT(decide(&h, 204, 0, &f), ZUH_ERR_PARSE);
    zuh_headers_free(&h);

    zuh_headers_init(&h);
    zuh_headers_add_str(&h, "Content-Length", "5");
    zuh_headers_add_str(&h, "Transfer-Encoding", "chunked");
    ZUH_CHECK_EQ_INT(decide(&h, 304, 0, &f), ZUH_ERR_PARSE);
    zuh_headers_free(&h);

    zuh_headers_init(&h);
    zuh_headers_add_str(&h, "Content-Length", "5, 5");
    ZUH_CHECK_EQ_INT(decide(&h, 204, 1, &f), ZUH_ERR_PARSE);
    zuh_headers_free(&h);

    ZUH_CASE("an out-of-range status is rejected");
    zuh_headers_init(&h);
    ZUH_CHECK_EQ_INT(decide(&h, 99,  0, &f), ZUH_ERR_PARSE);
    ZUH_CHECK_EQ_INT(decide(&h, 600, 0, &f), ZUH_ERR_PARSE);
    ZUH_CHECK_EQ_INT(decide(&h, 0,   0, &f), ZUH_ERR_PARSE);
    ZUH_CHECK_EQ_INT(decide(&h, -1,  0, &f), ZUH_ERR_PARSE);
    zuh_headers_free(&h);

    ZUH_CASE("Content-Length: 0 is a valid empty body, not 'no framing'");
    zuh_headers_init(&h);
    zuh_headers_add_str(&h, "Content-Length", "0");
    ZUH_CHECK_EQ_INT(decide(&h, 200, 0, &f), ZUH_OK);
    ZUH_CHECK_EQ_INT(f.kind, ZUH_FRAME_LENGTH);
    ZUH_CHECK_EQ_INT(f.length, 0);
    ZUH_CHECK(f.poolable);
    zuh_headers_free(&h);

    ZUH_CASE("no leaks across the suite");
    {
        zuh_alloc_stats st;
        zuh_alloc_stats_get(&st);
        ZUH_CHECK_EQ_INT(st.live_blocks, 0);
    }
}

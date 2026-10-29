#include "zuh_test.h"
#include "zuh_alloc.h"
#include <string.h>

void suite_alloc(void);

void suite_alloc(void) {
    size_t out;

    ZUH_CASE("zu_size_add detects overflow");
    ZUH_CHECK(zuh_size_add(1, 2, &out) && out == 3);
    ZUH_CHECK(zuh_size_add(SIZE_MAX, 0, &out) && out == SIZE_MAX);
    ZUH_CHECK(!zuh_size_add(SIZE_MAX, 1, &out));
    ZUH_CHECK(!zuh_size_add(SIZE_MAX / 2 + 1, SIZE_MAX / 2 + 1, &out));

    ZUH_CASE("zu_size_mul detects overflow");
    ZUH_CHECK(zuh_size_mul(0, SIZE_MAX, &out) && out == 0);
    ZUH_CHECK(zuh_size_mul(SIZE_MAX, 0, &out) && out == 0);
    ZUH_CHECK(zuh_size_mul(6, 7, &out) && out == 42);
    ZUH_CHECK(!zuh_size_mul(SIZE_MAX, 2, &out));
    ZUH_CHECK(!zuh_size_mul(SIZE_MAX / 3 + 2, 3, &out));

    ZUH_CASE("overflowing allocation requests are refused, not wrapped");
    ZUH_CHECK(zuh_alloc(SIZE_MAX) == NULL);
    ZUH_CHECK(zuh_calloc(SIZE_MAX, 2) == NULL);
    ZUH_CHECK(zuh_calloc(SIZE_MAX / 4 + 1, 8) == NULL);

    ZUH_CASE("allocation accounting balances");
    {
        zuh_alloc_stats st;
        void *a, *b;
        zuh_alloc_stats_reset();
        a = zuh_alloc(100);
        b = zuh_calloc(10, 10);
        ZUH_CHECK(a && b);
        zuh_alloc_stats_get(&st);
        ZUH_CHECK_EQ_INT(st.live_blocks, 2);
        ZUH_CHECK_EQ_INT(st.live_bytes, 200);
        zuh_free(a); zuh_free(b);
        zuh_alloc_stats_get(&st);
        ZUH_CHECK_EQ_INT(st.live_blocks, 0);
        ZUH_CHECK_EQ_INT(st.live_bytes, 0);
        ZUH_CHECK_EQ_INT(st.total_allocs, st.total_frees);
    }

    ZUH_CASE("zu_calloc zeroes");
    {
        unsigned char *p = (unsigned char *)zuh_calloc(64, 1);
        int i, zero = 1;
        for (i = 0; i < 64; i++) if (p[i]) zero = 0;
        ZUH_CHECK(zero);
        zuh_free(p);
    }

    ZUH_CASE("realloc preserves contents and accounting");
    {
        zuh_alloc_stats st;
        char *p;
        zuh_alloc_stats_reset();
        p = (char *)zuh_alloc(8);
        memcpy(p, "abcdefg", 8);
        p = (char *)zuh_realloc(p, 4096);
        ZUH_CHECK(p && strcmp(p, "abcdefg") == 0);
        zuh_alloc_stats_get(&st);
        ZUH_CHECK_EQ_INT(st.live_bytes, 4096);
        zuh_free(p);
        zuh_alloc_stats_get(&st);
        ZUH_CHECK_EQ_INT(st.live_bytes, 0);
    }

    ZUH_CASE("injected OOM is survivable and leaves the original block intact");
    {
        char *p = (char *)zuh_alloc(16);
        char *q;
        memcpy(p, "keepme", 7);
        zuh_alloc_fail_after(0);
        q = (char *)zuh_realloc(p, 1024);
        ZUH_CHECK(q == NULL);
        zuh_alloc_fail_after(-1);
        ZUH_CHECK(strcmp(p, "keepme") == 0);   /* realloc failure must not free */
        zuh_free(p);
        /* the allocator is usable again once injection is disabled */
        {
            void *r = zuh_alloc(1);
            ZUH_CHECK(r != NULL);
            zuh_free(r);
        }
    }

    ZUH_CASE("zu_free(NULL) is a no-op");
    zuh_free(NULL);

    /* Check BEFORE resetting. Resetting first would mask any leak this suite
     * created — which is exactly how the leak at test_alloc.c:82 survived
     * local runs and was caught only by valgrind/LSan on Linux. */
    ZUH_CASE("suite leaves nothing allocated");
    {
        zuh_alloc_stats st;
        zuh_alloc_stats_get(&st);
        ZUH_CHECK_EQ_INT(st.live_blocks, 0);
        ZUH_CHECK_EQ_INT(st.total_allocs, st.total_frees);
    }
    zuh_alloc_stats_reset();
}

#include "zu_test.h"
#include "zu_alloc.h"
#include <string.h>

void suite_alloc(void);

void suite_alloc(void) {
    size_t out;

    ZU_CASE("zu_size_add detects overflow");
    ZU_CHECK(zu_size_add(1, 2, &out) && out == 3);
    ZU_CHECK(zu_size_add(SIZE_MAX, 0, &out) && out == SIZE_MAX);
    ZU_CHECK(!zu_size_add(SIZE_MAX, 1, &out));
    ZU_CHECK(!zu_size_add(SIZE_MAX / 2 + 1, SIZE_MAX / 2 + 1, &out));

    ZU_CASE("zu_size_mul detects overflow");
    ZU_CHECK(zu_size_mul(0, SIZE_MAX, &out) && out == 0);
    ZU_CHECK(zu_size_mul(SIZE_MAX, 0, &out) && out == 0);
    ZU_CHECK(zu_size_mul(6, 7, &out) && out == 42);
    ZU_CHECK(!zu_size_mul(SIZE_MAX, 2, &out));
    ZU_CHECK(!zu_size_mul(SIZE_MAX / 3 + 2, 3, &out));

    ZU_CASE("overflowing allocation requests are refused, not wrapped");
    ZU_CHECK(zu_alloc(SIZE_MAX) == NULL);
    ZU_CHECK(zu_calloc(SIZE_MAX, 2) == NULL);
    ZU_CHECK(zu_calloc(SIZE_MAX / 4 + 1, 8) == NULL);

    ZU_CASE("allocation accounting balances");
    {
        zu_alloc_stats st;
        void *a, *b;
        zu_alloc_stats_reset();
        a = zu_alloc(100);
        b = zu_calloc(10, 10);
        ZU_CHECK(a && b);
        zu_alloc_stats_get(&st);
        ZU_CHECK_EQ_INT(st.live_blocks, 2);
        ZU_CHECK_EQ_INT(st.live_bytes, 200);
        zu_free(a); zu_free(b);
        zu_alloc_stats_get(&st);
        ZU_CHECK_EQ_INT(st.live_blocks, 0);
        ZU_CHECK_EQ_INT(st.live_bytes, 0);
        ZU_CHECK_EQ_INT(st.total_allocs, st.total_frees);
    }

    ZU_CASE("zu_calloc zeroes");
    {
        unsigned char *p = (unsigned char *)zu_calloc(64, 1);
        int i, zero = 1;
        for (i = 0; i < 64; i++) if (p[i]) zero = 0;
        ZU_CHECK(zero);
        zu_free(p);
    }

    ZU_CASE("realloc preserves contents and accounting");
    {
        zu_alloc_stats st;
        char *p;
        zu_alloc_stats_reset();
        p = (char *)zu_alloc(8);
        memcpy(p, "abcdefg", 8);
        p = (char *)zu_realloc(p, 4096);
        ZU_CHECK(p && strcmp(p, "abcdefg") == 0);
        zu_alloc_stats_get(&st);
        ZU_CHECK_EQ_INT(st.live_bytes, 4096);
        zu_free(p);
        zu_alloc_stats_get(&st);
        ZU_CHECK_EQ_INT(st.live_bytes, 0);
    }

    ZU_CASE("injected OOM is survivable and leaves the original block intact");
    {
        char *p = (char *)zu_alloc(16);
        char *q;
        memcpy(p, "keepme", 7);
        zu_alloc_fail_after(0);
        q = (char *)zu_realloc(p, 1024);
        ZU_CHECK(q == NULL);
        zu_alloc_fail_after(-1);
        ZU_CHECK(strcmp(p, "keepme") == 0);   /* realloc failure must not free */
        zu_free(p);
        /* the allocator is usable again once injection is disabled */
        {
            void *r = zu_alloc(1);
            ZU_CHECK(r != NULL);
            zu_free(r);
        }
    }

    ZU_CASE("zu_free(NULL) is a no-op");
    zu_free(NULL);

    /* Check BEFORE resetting. Resetting first would mask any leak this suite
     * created — which is exactly how the leak at test_alloc.c:82 survived
     * local runs and was caught only by valgrind/LSan on Linux. */
    ZU_CASE("suite leaves nothing allocated");
    {
        zu_alloc_stats st;
        zu_alloc_stats_get(&st);
        ZU_CHECK_EQ_INT(st.live_blocks, 0);
        ZU_CHECK_EQ_INT(st.total_allocs, st.total_frees);
    }
    zu_alloc_stats_reset();
}

#include "zu_alloc.h"
#include <stdlib.h>
#include <string.h>

int zu_size_add(size_t a, size_t b, size_t *out) {
    if (a > SIZE_MAX - b) return 0;
    *out = a + b;
    return 1;
}

int zu_size_mul(size_t a, size_t b, size_t *out) {
    if (a != 0 && b > SIZE_MAX / a) return 0;
    *out = a * b;
    return 1;
}

/* Every block carries its size in a header so the test harness can report
 * live bytes and catch leaks. The union forces worst-case alignment; C99 has
 * no max_align_t, so name the widest types explicitly. */
typedef union {
    long double ld;
    void       *p;
    long long   ll;
    size_t      sz;
} zu_align;

#define ZU_HDR sizeof(zu_align)

static zu_alloc_stats g_stats;
static long           g_fail_after = -1;

static int should_fail(void) {
    if (g_fail_after < 0) return 0;
    if (g_fail_after == 0) return 1;
    g_fail_after--;
    return 0;
}

static void note_alloc(size_t n) {
    g_stats.live_blocks++;
    g_stats.live_bytes += n;
    g_stats.total_allocs++;
    if (g_stats.live_bytes > g_stats.peak_bytes) g_stats.peak_bytes = g_stats.live_bytes;
}

void *zu_alloc(size_t n) {
    size_t total;
    void *raw;
    if (!zu_size_add(n, ZU_HDR, &total)) return NULL;
    if (should_fail()) return NULL;
    raw = malloc(total);
    if (!raw) return NULL;
    *(size_t *)raw = n;
    note_alloc(n);
    return (char *)raw + ZU_HDR;
}

void *zu_calloc(size_t count, size_t size) {
    size_t n;
    void *p;
    if (!zu_size_mul(count, size, &n)) return NULL;
    p = zu_alloc(n);
    if (p) memset(p, 0, n);
    return p;
}

void *zu_realloc(void *p, size_t n) {
    char *raw;
    size_t old, total;
    void *fresh;

    if (!p) return zu_alloc(n);

    raw = (char *)p - ZU_HDR;
    old = *(size_t *)raw;

    if (!zu_size_add(n, ZU_HDR, &total)) return NULL;
    if (should_fail()) return NULL;

    fresh = realloc(raw, total);
    if (!fresh) return NULL;                /* original block still valid */

    *(size_t *)fresh = n;
    g_stats.live_bytes -= old;
    g_stats.live_bytes += n;
    if (g_stats.live_bytes > g_stats.peak_bytes) g_stats.peak_bytes = g_stats.live_bytes;
    return (char *)fresh + ZU_HDR;
}

void zu_free(void *p) {
    char *raw;
    if (!p) return;
    raw = (char *)p - ZU_HDR;
    g_stats.live_bytes -= *(size_t *)raw;
    g_stats.live_blocks--;
    g_stats.total_frees++;
    free(raw);
}

void zu_alloc_stats_get(zu_alloc_stats *out) { *out = g_stats; }
void zu_alloc_stats_reset(void) { memset(&g_stats, 0, sizeof g_stats); g_fail_after = -1; }
void zu_alloc_fail_after(long n) { g_fail_after = n; }

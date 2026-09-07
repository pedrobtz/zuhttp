/* zuhttp — allocation with overflow checks and test instrumentation.
 *
 * Design §41 (memory management), §40 ("checked integer arithmetic",
 * "no unbounded stack allocation based on network input").
 *
 * Every size computed from network input must go through zu_size_add /
 * zu_size_mul. A silent wrap here is a heap overflow later.
 */
#ifndef ZUHTTP_ALLOC_H
#define ZUHTTP_ALLOC_H

#include "zu_platform.h"

/* Checked arithmetic. Return 1 on success, 0 on overflow (*out untouched). */
int zu_size_add(size_t a, size_t b, size_t *out);
int zu_size_mul(size_t a, size_t b, size_t *out);

/* Allocation. Return NULL on failure or on an overflowing size request.
 * zu_alloc(0) returns a non-NULL pointer to a zero-length block. */
void *zu_alloc(size_t n);
void *zu_calloc(size_t count, size_t size);
void *zu_realloc(void *p, size_t n);
void  zu_free(void *p);

/* --- test instrumentation (§43 fuzzing, §50 leak checks) --- */

typedef struct {
    size_t live_blocks;
    size_t live_bytes;
    size_t total_allocs;
    size_t total_frees;
    size_t peak_bytes;
} zu_alloc_stats;

void zu_alloc_stats_get(zu_alloc_stats *out);
void zu_alloc_stats_reset(void);

/* Make the (n+1)-th subsequent allocation fail, to exercise OOM paths.
 * n < 0 disables. Not thread-safe; tests are single-threaded. */
void zu_alloc_fail_after(long n);

#endif /* ZUHTTP_ALLOC_H */

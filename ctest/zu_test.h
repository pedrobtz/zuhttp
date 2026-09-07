/* Minimal assertion harness. No dependencies, so the same objects that the R
 * package builds also link into a bare test binary and, later, a fuzz target
 * (design §11, §43). */
#ifndef ZU_TEST_H
#define ZU_TEST_H
#include <stdio.h>
#include <string.h>

extern int zu_test_fails;
extern int zu_test_checks;
extern const char *zu_test_current;

#define ZU_CASE(name) \
    do { zu_test_current = name; } while (0)

#define ZU_CHECK(cond) do {                                                   \
    zu_test_checks++;                                                         \
    if (!(cond)) {                                                            \
        zu_test_fails++;                                                      \
        printf("  FAIL %s\n       %s:%d: %s\n", zu_test_current, __FILE__, __LINE__, #cond); \
    }                                                                         \
} while (0)

#define ZU_CHECK_EQ_INT(a, b) do {                                            \
    long long _a = (long long)(a), _b = (long long)(b);                       \
    zu_test_checks++;                                                         \
    if (_a != _b) {                                                           \
        zu_test_fails++;                                                      \
        printf("  FAIL %s\n       %s:%d: %s == %s  (%lld vs %lld)\n",         \
               zu_test_current, __FILE__, __LINE__, #a, #b, _a, _b);          \
    }                                                                         \
} while (0)

#define ZU_CHECK_MEM(ptr, str, n) do {                                        \
    zu_test_checks++;                                                         \
    if (memcmp((ptr), (str), (n)) != 0) {                                     \
        zu_test_fails++;                                                      \
        printf("  FAIL %s\n       %s:%d: bytes differ from \"%s\"\n",         \
               zu_test_current, __FILE__, __LINE__, (const char *)(str));     \
    }                                                                         \
} while (0)

/* stdout is block-buffered when it is a pipe, so without the flush a hang
 * shows NOTHING in CI — the suite name that would identify it is still
 * sitting in the buffer. That cost an hour of stuck jobs before it was
 * noticed. */
#define ZU_SUITE(fn) do {            \
    printf("%s\n", #fn);             \
    fflush(stdout);                  \
    fn();                            \
    fflush(stdout);                  \
} while (0)

#endif

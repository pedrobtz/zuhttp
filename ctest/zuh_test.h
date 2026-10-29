/* Minimal assertion harness. No dependencies, so the same objects that the R
 * package builds also link into a bare test binary and, later, a fuzz target
 * (design §11, §43). */
#ifndef ZUH_TEST_H
#define ZUH_TEST_H
#include <stdio.h>
#include <string.h>
#include <stdlib.h>   /* getenv, for ZU_TEST_TRACE */

extern int zuh_test_fails;
extern int zuh_test_checks;
extern const char *zuh_test_current;

/* Setting ZU_TEST_TRACE=1 prints and flushes every case name. Without it a
 * hang is invisible: the suite name alone narrows the search to a whole file,
 * which is how a blocking test in suite_net cost two CI rounds to locate. CI
 * sets it. */
#define ZUH_CASE(name) do {                                   \
    zuh_test_current = name;                                  \
    if (getenv("ZU_TEST_TRACE")) {                           \
        printf("  . %s\n", name);                            \
        fflush(stdout);                                      \
    }                                                        \
} while (0)

#define ZUH_CHECK(cond) do {                                                   \
    zuh_test_checks++;                                                         \
    if (!(cond)) {                                                            \
        zuh_test_fails++;                                                      \
        printf("  FAIL %s\n       %s:%d: %s\n", zuh_test_current, __FILE__, __LINE__, #cond); \
        fflush(stdout);                                                       \
    }                                                                         \
} while (0)

#define ZUH_CHECK_EQ_INT(a, b) do {                                            \
    long long _a = (long long)(a), _b = (long long)(b);                       \
    zuh_test_checks++;                                                         \
    if (_a != _b) {                                                           \
        zuh_test_fails++;                                                      \
        printf("  FAIL %s\n       %s:%d: %s == %s  (%lld vs %lld)\n",         \
               zuh_test_current, __FILE__, __LINE__, #a, #b, _a, _b);          \
        fflush(stdout);                                                       \
    }                                                                         \
} while (0)

#define ZUH_CHECK_MEM(ptr, str, n) do {                                        \
    zuh_test_checks++;                                                         \
    if (memcmp((ptr), (str), (n)) != 0) {                                     \
        zuh_test_fails++;                                                      \
        printf("  FAIL %s\n       %s:%d: bytes differ from \"%s\"\n",         \
               zuh_test_current, __FILE__, __LINE__, (const char *)(str));     \
        fflush(stdout);                                                       \
    }                                                                         \
} while (0)

/* stdout is block-buffered when it is a pipe, so without the flush a hang
 * shows NOTHING in CI — the suite name that would identify it is still
 * sitting in the buffer. That cost an hour of stuck jobs before it was
 * noticed. */
#define ZUH_SUITE(fn) do {            \
    printf("%s\n", #fn);             \
    fflush(stdout);                  \
    fn();                            \
    fflush(stdout);                  \
} while (0)

#endif

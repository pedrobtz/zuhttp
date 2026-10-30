#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#    define _POSIX_C_SOURCE 200112L
#endif
#include "zuh_test.h"
#include "zuh_alloc.h"
#include <string.h>
#ifndef _WIN32
#    include <signal.h>
#    include <unistd.h>
#endif

int zuh_test_fails = 0;
int zuh_test_checks = 0;
const char *zuh_test_current = "(none)";

void suite_alloc(void);
void suite_buffer(void);
void suite_error(void);
void suite_time(void);
void suite_stream(void);
void suite_headers(void);
void suite_request(void);
void suite_framing(void);
void suite_response(void);
void suite_uri(void);
void suite_redirect(void);
void suite_inflate(void);
void suite_net(void);
void suite_pool(void);
void suite_proxy(void);
void suite_redact(void);
void suite_body(void);
void suite_trace(void);
void suite_engine_mock(void);
extern int zuh_test_clock_stuck;

#ifndef _WIN32
/* A clock stuck at a constant fails suite_time's two guards and then hangs
 * suite_net, whose deadlines can never expire: the signal used to be a CI job
 * timeout hours later, with the failure count never printed. The watchdog
 * turns that into an immediate, named failure. Only async-signal-safe calls
 * here; the whole suite takes seconds, so the bound is generous. */
#define ZUH_TEST_WATCHDOG_S 300
static void watchdog(int sig) {
    static const char a[] = "\nWATCHDOG: the C suite ran past its time limit in case: ";
    static const char b[] = "\n(a stuck clock makes every deadline wait forever; see suite_time)\n";
    (void)sig;
    (void)!write(2, a, sizeof a - 1);
    (void)!write(2, zuh_test_current, strlen(zuh_test_current));
    (void)!write(2, b, sizeof b - 1);
    _exit(3);
}
#endif

int main(void) {
    zuh_alloc_stats st;

#ifndef _WIN32
    signal(SIGALRM, watchdog);
    alarm(ZUH_TEST_WATCHDOG_S);
#endif

    printf("zuhttp C core tests (S2 foundations + S3 wire)\n\n");
    ZUH_SUITE(suite_alloc);
    ZUH_SUITE(suite_error);
    ZUH_SUITE(suite_buffer);
    ZUH_SUITE(suite_time);
    ZUH_SUITE(suite_stream);
    ZUH_SUITE(suite_headers);
    ZUH_SUITE(suite_request);
    ZUH_SUITE(suite_framing);
    ZUH_SUITE(suite_response);
    ZUH_SUITE(suite_uri);
    ZUH_SUITE(suite_redirect);
    ZUH_SUITE(suite_inflate);
    if (zuh_test_clock_stuck) {
        /* Counted, not silently skipped: the two clock failures above are the
         * finding, and this says what they cost. */
        printf("suite_net\n  FAIL not run: the clock is stuck, so its deadlines could never fire\n");
        zuh_test_fails++;
    } else {
        ZUH_SUITE(suite_net);
    }
    ZUH_SUITE(suite_pool);
    ZUH_SUITE(suite_proxy);
    ZUH_SUITE(suite_redact);
    ZUH_SUITE(suite_body);
    ZUH_SUITE(suite_trace);
    ZUH_SUITE(suite_engine_mock);

    zuh_alloc_stats_get(&st);
    printf("\n%d checks, %d failures\n", zuh_test_checks, zuh_test_fails);
    printf("allocations: %lu made, %lu freed, %lu live, peak %lu bytes\n",
           (unsigned long)st.total_allocs, (unsigned long)st.total_frees,
           (unsigned long)st.live_blocks, (unsigned long)st.peak_bytes);

    if (st.live_blocks != 0) {
        printf("LEAK: %lu blocks still live\n", (unsigned long)st.live_blocks);
        return 1;
    }
    return zuh_test_fails == 0 ? 0 : 1;
}

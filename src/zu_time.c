/* glibc hides CLOCK_MONOTONIC behind __USE_POSIX199309, which -std=c99 does
 * NOT set: -std=c99 defines __STRICT_ANSI__, which suppresses the default
 * feature set. Without this macro the monotonic branch below compiles away on
 * Linux and every deadline in the library silently stops working.
 *
 * Same defect as the getaddrinfo one fixed in 2230b11 for zu_net.c; that fix
 * did not reach this file. MUST precede every system header. */
#if !defined(_WIN32)
#  if defined(__APPLE__)
#    define _DARWIN_C_SOURCE
#  else
#    define _POSIX_C_SOURCE 200112L
#  endif
#endif

#include "zu_time.h"

/* Platform shims are confined to this file (§10, §28). */
#if defined(ZU_WINDOWS)
#  include <windows.h>
zu_millis zu_now_ms(void) {
    /* Monotonic since boot, unaffected by system clock changes. */
    return (zu_millis)GetTickCount64();
}
#else
#  include <time.h>
#  if defined(__APPLE__)
#    include <mach/mach_time.h>
#  endif
zu_millis zu_now_ms(void) {
#  if defined(CLOCK_MONOTONIC)
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
        return (zu_millis)ts.tv_sec * 1000 + (zu_millis)(ts.tv_nsec / 1000000);
#  endif
#  if defined(__APPLE__)
    {
        static mach_timebase_info_data_t tb;
        if (tb.denom == 0) mach_timebase_info(&tb);
        return (zu_millis)((mach_absolute_time() * tb.numer / tb.denom) / 1000000ull);
    }
#  else
    /* Deliberately a COMPILE error, not a runtime fallback.
     *
     * This used to `return 0`, with a comment noting that "caller's deadlines
     * degrade to never". That is not a degradation, it is a total failure of
     * §24: every timeout in the library stops firing and the first operation
     * that waits for one hangs forever. It cost six commits to find, because
     * a constant clock still satisfies "monotonic" and so passed suite_time.
     *
     * A platform with no monotonic clock must fail to build, loudly. */
#    error "no monotonic clock: zuhttp deadlines (design 24) cannot work here"
#  endif
}
#endif

#define ZU_FOREVER ((zu_millis)0x7FFFFFFF)

zu_deadline zu_deadline_never(void) {
    zu_deadline d; d.at = 0; d.infinite = 1; return d;
}

zu_deadline zu_deadline_at(zu_millis at) {
    zu_deadline d; d.at = at; d.infinite = 0; return d;
}

zu_deadline zu_deadline_in(zu_millis ms) {
    if (ms < 0) return zu_deadline_never();
    return zu_deadline_at(zu_now_ms() + ms);
}

zu_millis zu_deadline_remaining(zu_deadline d) {
    if (d.infinite) return ZU_FOREVER;
    return d.at - zu_now_ms();
}

int zu_deadline_expired(zu_deadline d) {
    if (d.infinite) return 0;
    return zu_deadline_remaining(d) <= 0;
}

zu_deadline zu_deadline_min(zu_deadline a, zu_deadline b) {
    if (a.infinite) return b;
    if (b.infinite) return a;
    return a.at <= b.at ? a : b;
}

zu_deadline zu_deadline_phase(zu_deadline total, zu_millis phase_ms) {
    /* §24.2: whichever fires first wins. */
    return zu_deadline_min(total, zu_deadline_in(phase_ms));
}

int zu_deadline_poll_ms(zu_deadline d, int tick_ms) {
    zu_millis rem;
    if (tick_ms <= 0) tick_ms = 100;
    rem = zu_deadline_remaining(d);
    if (rem <= 0) return 0;
    /* Never block longer than one tick: §25.1 requires returning to an
     * R-safe checkpoint at a bounded cadence regardless of the deadline. */
    if (rem > (zu_millis)tick_ms) return tick_ms;
    return (int)rem;
}

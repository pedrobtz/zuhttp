/* glibc hides CLOCK_MONOTONIC behind __USE_POSIX199309, which -std=c99 does
 * NOT set: -std=c99 defines __STRICT_ANSI__, which suppresses the default
 * feature set. Without this macro the monotonic branch below compiles away on
 * Linux and every deadline in the library silently stops working.
 *
 * Same defect as the getaddrinfo one fixed in 2230b11 for zuh_net.c; that fix
 * did not reach this file. MUST precede every system header. */
#if !defined(_WIN32)
#  if defined(__APPLE__)
#    define _DARWIN_C_SOURCE
#  else
#    define _POSIX_C_SOURCE 200112L
#  endif
#endif

#include "zuh_time.h"

/* Platform shims are confined to this file (§10, §28). */
#if defined(ZUH_WINDOWS)
#  include <windows.h>
zuh_millis zuh_now_ms(void) {
    /* Monotonic since boot, unaffected by system clock changes. */
    return (zuh_millis)GetTickCount64();
}
#else
#  include <time.h>
#  if defined(__APPLE__)
#    include <mach/mach_time.h>
#  endif
zuh_millis zuh_now_ms(void) {
#  if defined(CLOCK_MONOTONIC)
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
        return (zuh_millis)ts.tv_sec * 1000 + (zuh_millis)(ts.tv_nsec / 1000000);
#  endif
#  if defined(__APPLE__)
    {
        static mach_timebase_info_data_t tb;
        if (tb.denom == 0) mach_timebase_info(&tb);
        return (zuh_millis)((mach_absolute_time() * tb.numer / tb.denom) / 1000000ull);
    }
#  elif defined(CLOCK_MONOTONIC)
    /* Declared, but clock_gettime() failed at run time. That does not happen
     * in practice. Wall time is not monotonic and §24.4 would rather not use
     * it, but it ADVANCES — and a constant would silently disable every
     * deadline in the library, which is the failure this whole file now
     * guards against. Advancing and imperfect beats stopped. */
    return (zuh_millis)time(NULL) * 1000;
#  else
    /* Deliberately a COMPILE error, and note the condition: this fires only
     * when there is genuinely no monotonic source, NOT on every non-Apple
     * platform. An earlier version of this guard sat in the #else of the
     * __APPLE__ test and broke every Linux build.
     *
     * The code this replaced was `return 0`, commented "caller's deadlines
     * degrade to never". That is not a degradation: every timeout stops
     * firing and the first operation that waits for one hangs forever. A
     * platform with no monotonic clock must fail to build, loudly. */
#    error "no monotonic clock: zuhttp deadlines (design 24) cannot work here"
#  endif
}
#endif

#define ZUH_FOREVER ((zuh_millis)0x7FFFFFFF)

zuh_deadline zuh_deadline_never(void) {
    zuh_deadline d; d.at = 0; d.infinite = 1; return d;
}

zuh_deadline zuh_deadline_at(zuh_millis at) {
    zuh_deadline d; d.at = at; d.infinite = 0; return d;
}

zuh_deadline zuh_deadline_in(zuh_millis ms) {
    if (ms < 0) return zuh_deadline_never();
    return zuh_deadline_at(zuh_now_ms() + ms);
}

zuh_millis zuh_deadline_remaining(zuh_deadline d) {
    if (d.infinite) return ZUH_FOREVER;
    return d.at - zuh_now_ms();
}

int zuh_deadline_expired(zuh_deadline d) {
    if (d.infinite) return 0;
    return zuh_deadline_remaining(d) <= 0;
}

zuh_deadline zuh_deadline_min(zuh_deadline a, zuh_deadline b) {
    if (a.infinite) return b;
    if (b.infinite) return a;
    return a.at <= b.at ? a : b;
}

zuh_deadline zuh_deadline_phase(zuh_deadline total, zuh_millis phase_ms) {
    /* §24.2: whichever fires first wins. */
    return zuh_deadline_min(total, zuh_deadline_in(phase_ms));
}

int zuh_deadline_poll_ms(zuh_deadline d, int tick_ms) {
    zuh_millis rem;
    if (tick_ms <= 0) tick_ms = 100;
    rem = zuh_deadline_remaining(d);
    if (rem <= 0) return 0;
    /* Never block longer than one tick: §25.1 requires returning to an
     * R-safe checkpoint at a bounded cadence regardless of the deadline. */
    if (rem > (zuh_millis)tick_ms) return tick_ms;
    return (int)rem;
}

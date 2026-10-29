#include "zuh_test.h"
#include "zuh_time.h"

void suite_time(void);

void suite_time(void) {
    /* A clock stuck at a constant satisfies "monotonic" — non-decreasing is
     * true of a constant — so the monotonicity checks below cannot catch the
     * failure that actually happened: CLOCK_MONOTONIC compiled away on Linux
     * and zuh_now_ms() returned 0 forever, so no deadline ever expired.
     *
     * These two assertions are what would have caught it on the first run. */
    ZUH_CASE("the clock is not stuck at a constant");
    {
        zuh_millis first = zuh_now_ms();
        zuh_millis now = first;
        long spins = 0;
        /* CLOCK_MONOTONIC is time since boot, so 0 means the stub, not a
         * machine that booted under a millisecond ago. */
        ZUH_CHECK(first != 0);
        while (now == first && spins < 200000000L) { now = zuh_now_ms(); spins++; }
        ZUH_CHECK(now != first);
    }

    ZUH_CASE("a short deadline actually expires");
    {
        zuh_deadline d = zuh_deadline_in(5);
        long spins = 0;
        while (!zuh_deadline_expired(d) && spins < 200000000L) spins++;
        /* If this fails, every timeout in the library is inoperative. */
        ZUH_CHECK(zuh_deadline_expired(d));
    }

    ZUH_CASE("the clock advances monotonically");
    {
        zuh_millis a = zuh_now_ms(), b;
        volatile unsigned long spin = 0;
        while (spin < 2000000UL) spin++;
        b = zuh_now_ms();
        ZUH_CHECK(b >= a);
    }

    ZUH_CASE("an infinite deadline never expires");
    {
        zuh_deadline d = zuh_deadline_never();
        ZUH_CHECK(!zuh_deadline_expired(d));
        ZUH_CHECK(zuh_deadline_remaining(d) > 0);
        ZUH_CHECK(zuh_deadline_in(-1).infinite);
    }

    ZUH_CASE("a past deadline is expired");
    {
        zuh_deadline d = zuh_deadline_at(zuh_now_ms() - 1000);
        ZUH_CHECK(zuh_deadline_expired(d));
        ZUH_CHECK(zuh_deadline_remaining(d) <= 0);
        ZUH_CHECK_EQ_INT(zuh_deadline_poll_ms(d, 100), 0);
    }

    ZUH_CASE("§24.2: effective deadline is the minimum of total and phase");
    {
        zuh_deadline total = zuh_deadline_in(1000);
        zuh_deadline eff_short = zuh_deadline_phase(total, 50);
        zuh_deadline eff_long  = zuh_deadline_phase(total, 5000);

        /* short phase wins over a distant total */
        ZUH_CHECK(zuh_deadline_remaining(eff_short) <= 50);
        /* total wins over a distant phase — the whole point of the rule */
        ZUH_CHECK(zuh_deadline_remaining(eff_long) <= 1000);
        ZUH_CHECK(zuh_deadline_remaining(eff_long) > 900);
    }

    ZUH_CASE("an unbounded phase leaves the total in charge");
    {
        zuh_deadline total = zuh_deadline_in(500);
        zuh_deadline eff = zuh_deadline_phase(total, -1);
        ZUH_CHECK(!eff.infinite);
        ZUH_CHECK(zuh_deadline_remaining(eff) <= 500);
    }

    ZUH_CASE("min() with an infinite operand yields the finite one");
    {
        zuh_deadline fin = zuh_deadline_in(100);
        ZUH_CHECK(!zuh_deadline_min(fin, zuh_deadline_never()).infinite);
        ZUH_CHECK(!zuh_deadline_min(zuh_deadline_never(), fin).infinite);
        ZUH_CHECK(zuh_deadline_min(zuh_deadline_never(), zuh_deadline_never()).infinite);
    }

    ZUH_CASE("§25.1: poll never blocks longer than one interrupt tick");
    {
        ZUH_CHECK_EQ_INT(zuh_deadline_poll_ms(zuh_deadline_never(), 100), 100);
        ZUH_CHECK_EQ_INT(zuh_deadline_poll_ms(zuh_deadline_in(100000), 100), 100);
        ZUH_CHECK(zuh_deadline_poll_ms(zuh_deadline_in(20), 100) <= 20);
    }
}

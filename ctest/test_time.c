#include "zu_test.h"
#include "zu_time.h"

void suite_time(void);

void suite_time(void) {
    /* A clock stuck at a constant satisfies "monotonic" — non-decreasing is
     * true of a constant — so the monotonicity checks below cannot catch the
     * failure that actually happened: CLOCK_MONOTONIC compiled away on Linux
     * and zu_now_ms() returned 0 forever, so no deadline ever expired.
     *
     * These two assertions are what would have caught it on the first run. */
    ZU_CASE("the clock is not stuck at a constant");
    {
        zu_millis first = zu_now_ms();
        zu_millis now = first;
        long spins = 0;
        /* CLOCK_MONOTONIC is time since boot, so 0 means the stub, not a
         * machine that booted under a millisecond ago. */
        ZU_CHECK(first != 0);
        while (now == first && spins < 200000000L) { now = zu_now_ms(); spins++; }
        ZU_CHECK(now != first);
    }

    ZU_CASE("a short deadline actually expires");
    {
        zu_deadline d = zu_deadline_in(5);
        long spins = 0;
        while (!zu_deadline_expired(d) && spins < 200000000L) spins++;
        /* If this fails, every timeout in the library is inoperative. */
        ZU_CHECK(zu_deadline_expired(d));
    }

    ZU_CASE("the clock advances monotonically");
    {
        zu_millis a = zu_now_ms(), b;
        volatile unsigned long spin = 0;
        while (spin < 2000000UL) spin++;
        b = zu_now_ms();
        ZU_CHECK(b >= a);
    }

    ZU_CASE("an infinite deadline never expires");
    {
        zu_deadline d = zu_deadline_never();
        ZU_CHECK(!zu_deadline_expired(d));
        ZU_CHECK(zu_deadline_remaining(d) > 0);
        ZU_CHECK(zu_deadline_in(-1).infinite);
    }

    ZU_CASE("a past deadline is expired");
    {
        zu_deadline d = zu_deadline_at(zu_now_ms() - 1000);
        ZU_CHECK(zu_deadline_expired(d));
        ZU_CHECK(zu_deadline_remaining(d) <= 0);
        ZU_CHECK_EQ_INT(zu_deadline_poll_ms(d, 100), 0);
    }

    ZU_CASE("§24.2: effective deadline is the minimum of total and phase");
    {
        zu_deadline total = zu_deadline_in(1000);
        zu_deadline eff_short = zu_deadline_phase(total, 50);
        zu_deadline eff_long  = zu_deadline_phase(total, 5000);

        /* short phase wins over a distant total */
        ZU_CHECK(zu_deadline_remaining(eff_short) <= 50);
        /* total wins over a distant phase — the whole point of the rule */
        ZU_CHECK(zu_deadline_remaining(eff_long) <= 1000);
        ZU_CHECK(zu_deadline_remaining(eff_long) > 900);
    }

    ZU_CASE("an unbounded phase leaves the total in charge");
    {
        zu_deadline total = zu_deadline_in(500);
        zu_deadline eff = zu_deadline_phase(total, -1);
        ZU_CHECK(!eff.infinite);
        ZU_CHECK(zu_deadline_remaining(eff) <= 500);
    }

    ZU_CASE("min() with an infinite operand yields the finite one");
    {
        zu_deadline fin = zu_deadline_in(100);
        ZU_CHECK(!zu_deadline_min(fin, zu_deadline_never()).infinite);
        ZU_CHECK(!zu_deadline_min(zu_deadline_never(), fin).infinite);
        ZU_CHECK(zu_deadline_min(zu_deadline_never(), zu_deadline_never()).infinite);
    }

    ZU_CASE("§25.1: poll never blocks longer than one interrupt tick");
    {
        ZU_CHECK_EQ_INT(zu_deadline_poll_ms(zu_deadline_never(), 100), 100);
        ZU_CHECK_EQ_INT(zu_deadline_poll_ms(zu_deadline_in(100000), 100), 100);
        ZU_CHECK(zu_deadline_poll_ms(zu_deadline_in(20), 100) <= 20);
    }
}

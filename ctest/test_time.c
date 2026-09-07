#include "zu_test.h"
#include "zu_time.h"

void suite_time(void);

void suite_time(void) {
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

#include "zu_test.h"
#include "zu_trace.h"
#include <string.h>

void suite_trace(void);

/* Is every byte accounted for by the character it belongs to? A sequence cut
 * short runs into the NUL, where the continuation-byte test fails. */
static int utf8_wellformed(const char *s) {
    const unsigned char *p = (const unsigned char *)s;
    while (*p) {
        size_t need, i;
        if (*p < 0x80)                  need = 0;
        else if ((*p & 0xE0) == 0xC0)   need = 1;
        else if ((*p & 0xF0) == 0xE0)   need = 2;
        else if ((*p & 0xF8) == 0xF0)   need = 3;
        else return 0;                            /* a stray continuation */
        p++;
        for (i = 0; i < need; i++, p++)
            if ((*p & 0xC0) != 0x80) return 0;
    }
    return 1;
}

/* The §35.3 log, which is an egress (§42.2) and a fixed-width one.
 *
 * Both properties have bitten. The detail field reached R as undecodable
 * bytes once already, from a pointer into freed headers; and the same field
 * shipped a request's `?access_token=` to anyone who turned tracing on. The
 * cases below are the two mechanisms that must hold: a detail that does not
 * fit is cut at a character boundary and says it was cut, and a URL is
 * redacted on the way in.
 */
void suite_trace(void) {
    ZU_CASE("a detail that fits is copied whole");
    {
        zu_trace t;
        zu_trace_init(&t);
        zu_trace_add(&t, ZU_EV_REQUEST_SENT, "GET", 0);
        ZU_CHECK_EQ_INT(t.n, 1);
        ZU_CHECK(strcmp(t.ev[0].detail, "GET") == 0);
    }

    ZU_CASE("a detail too long is truncated AND says so");
    {
        /* A silently shortened URL reads as a complete one, which is the
         * failure this marker exists to prevent. */
        char big[ZU_TRACE_DETAIL * 2];
        zu_trace t;
        size_t len;
        memset(big, 'a', sizeof big - 1);
        big[sizeof big - 1] = '\0';
        zu_trace_init(&t);
        zu_trace_add(&t, ZU_EV_REQUEST_START, big, 0);
        len = strlen(t.ev[0].detail);
        ZU_CHECK(len < ZU_TRACE_DETAIL);
        ZU_CHECK(len == ZU_TRACE_DETAIL - 1);
        ZU_CHECK(strcmp(t.ev[0].detail + len - 3, ZU_TRACE_TRUNC) == 0);
    }

    ZU_CASE("truncation never splits a UTF-8 character");
    {
        /* The regression this guards: init.c hands `detail` straight to
         * mkChar(), so a cut through a multi-byte character puts a string
         * into R that R cannot decode — exactly what the dangling pointer
         * did once.
         *
         * The shifts matter. The cut lands at a fixed offset, and a first
         * attempt at this case used only 3-byte characters — which that
         * offset happened to divide exactly, so it passed with the
         * boundary logic deleted. Sweeping an ASCII prefix of 0..3 bytes
         * moves the cut through every alignment, so at least one iteration
         * must land inside a character whatever ZU_TRACE_DETAIL becomes. */
        int shift;
        for (shift = 0; shift < 4; shift++) {
            char big[ZU_TRACE_DETAIL * 2];
            zu_trace t;
            size_t i = 0, len;

            while ((int)i < shift) big[i++] = 'x';
            while (i + 3 < sizeof big - 1) {          /* U+20AC EURO SIGN */
                big[i++] = (char)0xE2; big[i++] = (char)0x82; big[i++] = (char)0xAC;
            }
            big[i] = '\0';

            zu_trace_init(&t);
            zu_trace_add(&t, ZU_EV_REQUEST_START, big, 0);
            len = strlen(t.ev[0].detail);
            ZU_CHECK(len > 0);
            ZU_CHECK(len < ZU_TRACE_DETAIL);
            ZU_CHECK(utf8_wellformed(t.ev[0].detail));
            /* ...and it still says it was cut. */
            ZU_CHECK(strcmp(t.ev[0].detail + len - 3, ZU_TRACE_TRUNC) == 0);
        }
    }

    ZU_CASE("a traced URL has its userinfo and secrets redacted (§42.2)");
    {
        zu_trace t;
        zu_trace_init(&t);
        zu_trace_add_url(&t, ZU_EV_REQUEST_START, NULL,
                         "https://user:pw@h/x?api_key=SECRET&page=2", 0);
        ZU_CHECK_EQ_INT(t.n, 1);
        /* Not merely "different from the input": the specific secrets must be
         * gone and the useful parts must survive, or a redactor that returned
         * the empty string would pass. */
        ZU_CHECK(strstr(t.ev[0].detail, "pw") == NULL);
        ZU_CHECK(strstr(t.ev[0].detail, "SECRET") == NULL);
        ZU_CHECK(strstr(t.ev[0].detail, "page=2") != NULL);
        ZU_CHECK(strstr(t.ev[0].detail, "h/x") != NULL);
    }

    ZU_CASE("a NULL policy still applies the §42.1 defaults");
    {
        /* An un-set policy must mean "the defaults", not "no redaction":
         * every caller that forgets to pass one would otherwise leak. */
        zu_trace t;
        zu_trace_init(&t);
        zu_trace_add_url(&t, ZU_EV_REDIRECT_FOLLOWED, NULL,
                         "https://h/x?access_token=SECRET", 1);
        ZU_CHECK(strstr(t.ev[0].detail, "SECRET") == NULL);
    }

    ZU_CASE("the caller's extra parameter names are honoured");
    {
        static const char *const extra[] = { "next", NULL };
        zu_redact_policy p;
        zu_trace t;
        zu_redact_policy_init(&p);
        p.extra_params = extra;
        zu_trace_init(&t);
        zu_trace_add_url(&t, ZU_EV_REQUEST_START, &p, "https://h/x?next=SECRET", 0);
        ZU_CHECK(strstr(t.ev[0].detail, "SECRET") == NULL);
    }

    ZU_CASE("a NULL URL is an empty detail, not a crash");
    {
        zu_trace t;
        zu_trace_init(&t);
        zu_trace_add_url(&t, ZU_EV_REQUEST_START, NULL, NULL, 0);
        ZU_CHECK_EQ_INT(t.n, 1);
        ZU_CHECK_EQ_INT((int)strlen(t.ev[0].detail), 0);
    }

    ZU_CASE("tracing off does no work at all");
    {
        /* §35.4's claim. zu_trace_add_url() allocates, so a NULL trace has to
         * return before it does, not after. */
        zu_trace_add_url(NULL, ZU_EV_REQUEST_START, NULL, "https://h/x", 0);
        zu_trace_add(NULL, ZU_EV_REQUEST_START, "x", 0);
        ZU_CHECK(1);
    }
}

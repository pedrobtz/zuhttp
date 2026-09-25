#include "zu_test.h"
#include "zu_error.h"
#include "zu_tls.h"
#include <string.h>

void suite_error(void);

void suite_error(void) {
    zu_error e;

    ZU_CASE("set records code, phase and a formatted message");
    zu_error_clear(&e);
    zu_error_set(&e, ZU_ERR_TIMEOUT, ZU_PHASE_READ, "read timed out after %d ms", 30000);
    ZU_CHECK_EQ_INT(e.code, ZU_ERR_TIMEOUT);
    ZU_CHECK_EQ_INT(e.phase, ZU_PHASE_READ);
    ZU_CHECK(strcmp(e.message, "read timed out after 30000 ms") == 0);
    ZU_CHECK(strcmp(zu_phase_name(e.phase), "read") == 0);

    ZU_CASE("backend detail is attached separately (§34.2)");
    zu_error_set_backend(&e, "openssl", 20);
    ZU_CHECK(strcmp(e.backend, "openssl") == 0);
    ZU_CHECK_EQ_INT(e.backend_code, 20);

    ZU_CASE("an over-long message is truncated, not overflowed");
    {
        char big[1024];
        memset(big, 'x', sizeof big - 1);
        big[sizeof big - 1] = '\0';
        zu_error_set(&e, ZU_ERR_PARSE, ZU_PHASE_READ, "%s", big);
        ZU_CHECK(strlen(e.message) == ZU_ERR_MSG_MAX - 1);
    }

    ZU_CASE("every code maps to a distinct, non-empty R condition class");
    {
        int i, j, ok = 1;
        for (i = 0; i < ZU_CODE_COUNT; i++) {
            const char *ci = zu_code_class((zu_code)i);
            if (!ci || !*ci) { ok = 0; break; }
            for (j = i + 1; j < ZU_CODE_COUNT; j++)
                if (strcmp(ci, zu_code_class((zu_code)j)) == 0) { ok = 0; break; }
        }
        ZU_CHECK(ok);
    }

    ZU_CASE("class names match the §34.1 hierarchy");
    ZU_CHECK(strcmp(zu_code_class(ZU_ERR_TLS_CERT), "zu_tls_certificate_error") == 0);
    ZU_CHECK(strcmp(zu_code_class(ZU_ERR_TOO_MANY_REDIRECTS), "zu_too_many_redirects") == 0);
    ZU_CHECK(strcmp(zu_code_class(ZU_ERR_BODY_NOT_REPLAYABLE), "zu_body_not_replayable") == 0);
    ZU_CHECK(strcmp(zu_code_class(ZU_ERR_FORK), "zu_fork_error") == 0);

    ZU_CASE("an out-of-range code degrades to the base class");
    ZU_CHECK(strcmp(zu_code_class((zu_code)9999), "zu_error") == 0);

    ZU_CASE("§33.2: trust failures are not retryable, transport failures are");
    ZU_CHECK(!zu_code_retryable(ZU_ERR_TLS_CERT));
    ZU_CHECK(!zu_code_retryable(ZU_ERR_TLS_HOSTNAME));
    ZU_CHECK(!zu_code_retryable(ZU_ERR_PARSE));
    ZU_CHECK(!zu_code_retryable(ZU_ERR_BODY_NOT_REPLAYABLE));
    ZU_CHECK(zu_code_retryable(ZU_ERR_CONNECT));
    ZU_CHECK(zu_code_retryable(ZU_ERR_DNS));

    ZU_CASE("D-56: a backend refusal is its own class, a child of zu_tls_error");
    {
        const char *chain[4];
        int n = zu_code_class_chain(ZU_ERR_TLS_UNSUPPORTED, chain, 4);
        ZU_CHECK_EQ_INT(n, 3);
        ZU_CHECK(n == 3 && strcmp(chain[0], "zu_tls_unsupported_error") == 0);
        ZU_CHECK(n == 3 && strcmp(chain[1], "zu_tls_error") == 0);
        /* #12: never the mismatch class, and not retryable. */
        ZU_CHECK(strcmp(zu_code_class(ZU_ERR_TLS_UNSUPPORTED),
                        zu_code_class(ZU_ERR_TLS_PIN)) != 0);
        ZU_CHECK(!zu_code_retryable(ZU_ERR_TLS_UNSUPPORTED));
    }

    ZU_CASE("D-56: zu_tls_config_check refuses each setting its cap does not cover");
    {
        static const char *pins[] = { "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" };
        const unsigned all = ZU_TLS_CAP_PINS | ZU_TLS_CAP_TLS13 | ZU_TLS_CAP_CA_FILE |
                             ZU_TLS_CAP_CA_EXTRA | ZU_TLS_CAP_REVOCATION;
        const unsigned bits[5] = { ZU_TLS_CAP_PINS, ZU_TLS_CAP_TLS13, ZU_TLS_CAP_CA_FILE,
                                   ZU_TLS_CAP_CA_EXTRA, ZU_TLS_CAP_REVOCATION };
        int k;
        for (k = 0; k < 5; k++) {
            zu_tls_config c;
            zu_tls_config_init(&c);
            switch (k) {
                case 0: c.pins = pins; c.n_pins = 1;             break;
                case 1: c.min_version = 13;                      break;
                case 2: c.source = ZU_TRUST_FILE; c.ca_file = "x.pem"; break;
                case 3: c.ca_extra_file = "x.pem";               break;
                default: c.revocation = 1;                       break;
            }
            /* Refused without its bit, even with every other bit set... */
            zu_error_clear(&e);
            ZU_CHECK_EQ_INT(zu_tls_config_check(&c, all & ~bits[k], "testbe", &e),
                            ZU_ERR_TLS_UNSUPPORTED);
            ZU_CHECK_EQ_INT(e.code, ZU_ERR_TLS_UNSUPPORTED);
            ZU_CHECK_EQ_INT(e.phase, ZU_PHASE_TLS);
            ZU_CHECK(strstr(e.message, "testbe") != NULL);
            /* ...and accepted with only its bit, so each bit guards exactly
             * one setting rather than all of them failing together. */
            zu_error_clear(&e);
            ZU_CHECK_EQ_INT(zu_tls_config_check(&c, bits[k], "testbe", &e), ZU_OK);
            ZU_CHECK_EQ_INT(e.code, ZU_OK);
        }
    }

    ZU_CASE("D-56: the default configuration needs no capability at all");
    {
        zu_tls_config c;
        zu_tls_config_init(&c);
        ZU_CHECK_EQ_INT(zu_tls_config_check(&c, 0u, "testbe", &e), ZU_OK);
        ZU_CHECK_EQ_INT(zu_tls_config_check(NULL, 0u, "testbe", &e), ZU_OK);
        /* TLS 1.2 is the floor every backend reaches (§14.1). */
        c.min_version = 12;
        ZU_CHECK_EQ_INT(zu_tls_config_check(&c, 0u, "testbe", &e), ZU_OK);
    }
}

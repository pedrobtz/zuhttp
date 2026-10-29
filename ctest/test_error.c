#include "zuh_test.h"
#include "zuh_error.h"
#include "zuh_tls.h"
#include <string.h>

void suite_error(void);

void suite_error(void) {
    zuh_error e;

    ZUH_CASE("set records code, phase and a formatted message");
    zuh_error_clear(&e);
    zuh_error_set(&e, ZUH_ERR_TIMEOUT, ZUH_PHASE_READ, "read timed out after %d ms", 30000);
    ZUH_CHECK_EQ_INT(e.code, ZUH_ERR_TIMEOUT);
    ZUH_CHECK_EQ_INT(e.phase, ZUH_PHASE_READ);
    ZUH_CHECK(strcmp(e.message, "read timed out after 30000 ms") == 0);
    ZUH_CHECK(strcmp(zuh_phase_name(e.phase), "read") == 0);

    ZUH_CASE("backend detail is attached separately (§34.2)");
    zuh_error_set_backend(&e, "openssl", 20);
    ZUH_CHECK(strcmp(e.backend, "openssl") == 0);
    ZUH_CHECK_EQ_INT(e.backend_code, 20);

    ZUH_CASE("an over-long message is truncated, not overflowed");
    {
        char big[1024];
        memset(big, 'x', sizeof big - 1);
        big[sizeof big - 1] = '\0';
        zuh_error_set(&e, ZUH_ERR_PARSE, ZUH_PHASE_READ, "%s", big);
        ZUH_CHECK(strlen(e.message) == ZUH_ERR_MSG_MAX - 1);
    }

    ZUH_CASE("every code maps to a distinct, non-empty R condition class");
    {
        int i, j, ok = 1;
        for (i = 0; i < ZUH_CODE_COUNT; i++) {
            const char *ci = zuh_code_class((zuh_code)i);
            if (!ci || !*ci) { ok = 0; break; }
            for (j = i + 1; j < ZUH_CODE_COUNT; j++)
                if (strcmp(ci, zuh_code_class((zuh_code)j)) == 0) { ok = 0; break; }
        }
        ZUH_CHECK(ok);
    }

    ZUH_CASE("class names match the §34.1 hierarchy");
    ZUH_CHECK(strcmp(zuh_code_class(ZUH_ERR_TLS_CERT), "zu_tls_certificate_error") == 0);
    ZUH_CHECK(strcmp(zuh_code_class(ZUH_ERR_TOO_MANY_REDIRECTS), "zu_too_many_redirects") == 0);
    ZUH_CHECK(strcmp(zuh_code_class(ZUH_ERR_BODY_NOT_REPLAYABLE), "zu_body_not_replayable") == 0);
    ZUH_CHECK(strcmp(zuh_code_class(ZUH_ERR_FORK), "zu_fork_error") == 0);

    ZUH_CASE("an out-of-range code degrades to the base class");
    ZUH_CHECK(strcmp(zuh_code_class((zuh_code)9999), "zu_error") == 0);

    ZUH_CASE("§33.2: trust failures are not retryable, transport failures are");
    ZUH_CHECK(!zuh_code_retryable(ZUH_ERR_TLS_CERT));
    ZUH_CHECK(!zuh_code_retryable(ZUH_ERR_TLS_HOSTNAME));
    ZUH_CHECK(!zuh_code_retryable(ZUH_ERR_PARSE));
    ZUH_CHECK(!zuh_code_retryable(ZUH_ERR_BODY_NOT_REPLAYABLE));
    ZUH_CHECK(zuh_code_retryable(ZUH_ERR_CONNECT));
    ZUH_CHECK(zuh_code_retryable(ZUH_ERR_DNS));

    ZUH_CASE("D-56: a backend refusal is its own class, a child of zu_tls_error");
    {
        const char *chain[ZUH_CLASS_CHAIN_MAX];
        int n = zuh_code_class_chain(ZUH_ERR_TLS_UNSUPPORTED, chain, ZUH_CLASS_CHAIN_MAX);
        ZUH_CHECK_EQ_INT(n, 4);
        ZUH_CHECK(n == 4 && strcmp(chain[0], "zu_tls_unsupported_error") == 0);
        ZUH_CHECK(n == 4 && strcmp(chain[1], "zu_tls_error") == 0);
        /* #12: never the mismatch class, and not retryable. */
        ZUH_CHECK(strcmp(zuh_code_class(ZUH_ERR_TLS_UNSUPPORTED),
                        zuh_code_class(ZUH_ERR_TLS_PIN)) != 0);
        ZUH_CHECK(!zuh_code_retryable(ZUH_ERR_TLS_UNSUPPORTED));
    }

    ZUH_CASE("D-56: zu_tls_config_check refuses each setting its cap does not cover");
    {
        static const char *pins[] = { "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" };
        const unsigned all = ZUH_TLS_CAP_PINS | ZUH_TLS_CAP_TLS13 | ZUH_TLS_CAP_CA_FILE |
                             ZUH_TLS_CAP_CA_EXTRA | ZUH_TLS_CAP_REVOCATION;
        const unsigned bits[5] = { ZUH_TLS_CAP_PINS, ZUH_TLS_CAP_TLS13, ZUH_TLS_CAP_CA_FILE,
                                   ZUH_TLS_CAP_CA_EXTRA, ZUH_TLS_CAP_REVOCATION };
        int k;
        for (k = 0; k < 5; k++) {
            zuh_tls_config c;
            zuh_tls_config_init(&c);
            switch (k) {
                case 0: c.pins = pins; c.n_pins = 1;             break;
                case 1: c.min_version = 13;                      break;
                case 2: c.source = ZUH_TRUST_FILE; c.ca_file = "x.pem"; break;
                case 3: c.ca_extra_file = "x.pem";               break;
                default: c.revocation = 1;                       break;
            }
            /* Refused without its bit, even with every other bit set... */
            zuh_error_clear(&e);
            ZUH_CHECK_EQ_INT(zuh_tls_config_check(&c, all & ~bits[k], "testbe", &e),
                            ZUH_ERR_TLS_UNSUPPORTED);
            ZUH_CHECK_EQ_INT(e.code, ZUH_ERR_TLS_UNSUPPORTED);
            ZUH_CHECK_EQ_INT(e.phase, ZUH_PHASE_TLS);
            ZUH_CHECK(strstr(e.message, "testbe") != NULL);
            /* ...and accepted with only its bit, so each bit guards exactly
             * one setting rather than all of them failing together. */
            zuh_error_clear(&e);
            ZUH_CHECK_EQ_INT(zuh_tls_config_check(&c, bits[k], "testbe", &e), ZUH_OK);
            ZUH_CHECK_EQ_INT(e.code, ZUH_OK);
        }
    }

    ZUH_CASE("D-56: the default configuration needs no capability at all");
    {
        zuh_tls_config c;
        zuh_tls_config_init(&c);
        ZUH_CHECK_EQ_INT(zuh_tls_config_check(&c, 0u, "testbe", &e), ZUH_OK);
        ZUH_CHECK_EQ_INT(zuh_tls_config_check(NULL, 0u, "testbe", &e), ZUH_OK);
        /* TLS 1.2 is the floor every backend reaches (§14.1). */
        c.min_version = 12;
        ZUH_CHECK_EQ_INT(zuh_tls_config_check(&c, 0u, "testbe", &e), ZUH_OK);
    }
}

#include "zu_test.h"
#include "zu_error.h"
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
}

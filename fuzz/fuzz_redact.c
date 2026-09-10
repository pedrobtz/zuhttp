/* Target 8 — secret redaction (§42, §43).
 *
 * zu_redact_url deliberately does NOT use the URI parser: it must work on a
 * URL that failed to parse, because that is the URL an error message is
 * about. That means a hand-rolled scanner over attacker-controlled bytes,
 * which is exactly what belongs here.
 *
 * The assertion is the security property, not just "no crash": whatever the
 * input, no userinfo may survive into the output. */
#include "zu_redact.h"
#include "zu_buffer.h"
#include "zu_alloc.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    zu_redact_policy p;
    zu_buffer out;
    unsigned char *exact;

    if (size < 1 || size > 16 * 1024) return 0;

    zu_redact_policy_init(&p);

    /* Exact-size allocation: a read past the end is a heap overflow here. */
    exact = (unsigned char *)malloc(size);
    if (!exact) return 0;
    memcpy(exact, data, size);

    if (zu_buf_init(&out, 64, 1 << 20)) {
        if (zu_redact_url(&p, (const char *)exact, size, &out)) {
            const char *s = NULL;
            if (zu_buf_cstr(&out, &s) && s) {
                /* §42.1: userinfo is removed outright, so the output's
                 * authority must contain no '@'.
                 *
                 * The authority is located with the SAME anchored-scheme rule
                 * the redactor uses. Using strstr(s, "://") here was wrong and
                 * the regress-not-a-url seed proved it: in
                 * "not a url at all :// with u:p@h" there is no authority at
                 * all, and that text is correctly left untouched. */
                size_t i, slen = strlen(s);
                const char *sep = NULL;
                if (slen > 0 && ((s[0] >= 'a' && s[0] <= 'z') ||
                                 (s[0] >= 'A' && s[0] <= 'Z'))) {
                    for (i = 1; i + 2 < slen; i++) {
                        char ch = s[i];
                        if (ch == ':' && s[i + 1] == '/' && s[i + 2] == '/') {
                            sep = s + i;
                            break;
                        }
                        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                              (ch >= '0' && ch <= '9') || ch == '+' || ch == '-' ||
                              ch == '.'))
                            break;
                    }
                }
                if (sep) {
                    const char *a = sep + 3, *e = a;
                    while (*e && *e != '/' && *e != '?' && *e != '#') e++;
                    if (memchr(a, '@', (size_t)(e - a))) abort();
                }
            }
        }
        zu_buf_free(&out);
    }

    if (zu_buf_init(&out, 64, 1 << 20)) {
        (void)zu_redact_form_body(&p, (const char *)exact, size, &out);
        zu_buf_free(&out);
    }

    free(exact);
    return 0;
}

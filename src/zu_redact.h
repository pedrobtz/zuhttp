/* zuhttp — secret redaction (design §42).
 *
 * §42 opens with the rule that shapes this file: redaction must be ONE policy
 * applied at every egress, not a feature of the record/replay transport. The
 * policy therefore lives here, in C, and every formatter — condition
 * messages, traces, printing, recordings — calls it. A second implementation
 * in R would be a second thing to forget to update.
 *
 * §42.3: redaction is applied by the FORMATTING layer. Nothing here mutates a
 * request. A redacted request must still be executable, so storing
 * "<redacted>" into one would produce a client that fails authentication in
 * confusing ways.
 */
#ifndef ZUHTTP_REDACT_H
#define ZUHTTP_REDACT_H

#include "zu_platform.h"
#include "zu_buffer.h"

/* What a redacted value renders as. Never a truncated prefix: a prefix is
 * enough to confirm a guess (§42.1). */
#define ZU_REDACTED "<redacted>"

/* The §42.1 defaults, plus whatever the caller adds. NULL entries end a list;
 * either list may be NULL. Matching is case-insensitive. */
typedef struct {
    const char *const *extra_headers;  /* additional header names */
    const char *const *extra_params;   /* additional query parameter names */
} zu_redact_policy;

void zu_redact_policy_init(zu_redact_policy *p);

/* Is this header's VALUE a secret? Name-only decision, so it is cheap enough
 * to call on every header of every trace line. */
int zu_redact_is_secret_header(const zu_redact_policy *p,
                               const char *name, size_t nlen);

/* Is this query parameter's value a secret? */
int zu_redact_is_secret_param(const zu_redact_policy *p,
                              const char *name, size_t nlen);

/* Redact a URL: userinfo removed entirely, and the value of any secret query
 * parameter replaced. The result is still a valid, readable URL — it is what
 * zu_resp_url() and every error message show (§42.2).
 *
 * Works on the raw text rather than on a parsed zu_uri, because a URL that
 * FAILED to parse is exactly the one an error message is about, and it must
 * be redacted too. Returns 1 on success. */
int zu_redact_url(const zu_redact_policy *p, const char *url, size_t len,
                  zu_buffer *out);

/* Redact an application/x-www-form-urlencoded body (§42.1): the value of any
 * secret parameter is replaced, everything else is preserved. */
int zu_redact_form_body(const zu_redact_policy *p, const char *body, size_t len,
                        zu_buffer *out);

#endif /* ZUHTTP_REDACT_H */

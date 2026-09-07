/* Secret redaction — design §42. */
#include "zu_test.h"
#include "zu_redact.h"
#include "zu_error.h"
#include "zu_alloc.h"
#include <string.h>

void suite_redact(void);

static const char *red_url(zu_buffer *b, const zu_redact_policy *p, const char *u) {
    const char *s = NULL;
    if (!zu_buf_init(b, 64, 1 << 20)) return NULL;
    if (!zu_redact_url(p, u, strlen(u), b)) return NULL;
    if (!zu_buf_cstr(b, &s)) return NULL;
    return s;
}
static int streq(const char *a, const char *b) { return a && b && strcmp(a, b) == 0; }

void suite_redact(void) {
    zu_redact_policy p;
    zu_buffer b;
    const char *s;

    zu_redact_policy_init(&p);

    ZU_CASE("the §42.1 default header list");
    {
        const char *yes[] = { "Authorization", "authorization", "AUTHORIZATION",
                              "Proxy-Authorization", "Cookie", "Set-Cookie",
                              "X-Api-Key", "x-auth-token" };
        const char *no[]  = { "Accept", "Content-Type", "X-Request-Id",
                              "Authorizationx", "uthorization", "" };
        size_t i;
        for (i = 0; i < sizeof yes / sizeof *yes; i++)
            ZU_CHECK_EQ_INT(zu_redact_is_secret_header(&p, yes[i], strlen(yes[i])), 1);
        for (i = 0; i < sizeof no / sizeof *no; i++)
            ZU_CHECK_EQ_INT(zu_redact_is_secret_header(&p, no[i], strlen(no[i])), 0);
    }

    ZU_CASE("the §42.1 default parameter list");
    {
        const char *yes[] = { "access_token", "api_key", "signature", "sig", "SIG" };
        const char *no[]  = { "page", "signature2", "si", "" };
        size_t i;
        for (i = 0; i < sizeof yes / sizeof *yes; i++)
            ZU_CHECK_EQ_INT(zu_redact_is_secret_param(&p, yes[i], strlen(yes[i])), 1);
        for (i = 0; i < sizeof no / sizeof *no; i++)
            ZU_CHECK_EQ_INT(zu_redact_is_secret_param(&p, no[i], strlen(no[i])), 0);
    }

    ZU_CASE("a caller may add names but cannot remove a default");
    {
        static const char *const extra_h[] = { "X-Corp-Secret", NULL };
        zu_redact_policy q;
        zu_redact_policy_init(&q);
        q.extra_headers = extra_h;
        ZU_CHECK_EQ_INT(zu_redact_is_secret_header(&q, "X-Corp-Secret", 13), 1);
        ZU_CHECK_EQ_INT(zu_redact_is_secret_header(&q, "Authorization", 13), 1);
    }

    ZU_CASE("userinfo is removed entirely, not masked");
    s = red_url(&b, &p, "https://user:pw@api.example.com/v1/x");
    ZU_CHECK(streq(s, "https://api.example.com/v1/x"));
    /* Even the username goes: it identifies an account on its own (§42.1). */
    ZU_CHECK(strstr(s, "user") == NULL);
    ZU_CHECK(strstr(s, "pw") == NULL);
    zu_buf_free(&b);

    ZU_CASE("a username with no password is still removed");
    s = red_url(&b, &p, "https://someone@api.example.com/x");
    ZU_CHECK(streq(s, "https://api.example.com/x"));
    zu_buf_free(&b);

    ZU_CASE("the LAST @ delimits userinfo");
    /* A '@' can appear percent-decoded inside the userinfo, so splitting on
     * the first one would leave part of the credential behind. */
    s = red_url(&b, &p, "https://us@er:p@ss@api.example.com/x");
    ZU_CHECK(streq(s, "https://api.example.com/x"));
    ZU_CHECK(strstr(s, "p@ss") == NULL);
    zu_buf_free(&b);

    ZU_CASE("a secret query parameter is replaced, others preserved");
    s = red_url(&b, &p, "https://h/v1?page=2&api_key=SECRET&sort=asc");
    ZU_CHECK(streq(s, "https://h/v1?page=2&api_key=<redacted>&sort=asc"));
    zu_buf_free(&b);

    ZU_CASE("the replacement is never a truncated prefix (§42.1)");
    s = red_url(&b, &p, "https://h/?access_token=abcdefghijklmnop");
    ZU_CHECK(strstr(s, "abc") == NULL);
    ZU_CHECK(strstr(s, "<redacted>") != NULL);
    zu_buf_free(&b);

    ZU_CASE("separators are preserved as written");
    s = red_url(&b, &p, "https://h/?a=1;sig=X;b=2");
    ZU_CHECK(streq(s, "https://h/?a=1;sig=<redacted>;b=2"));
    zu_buf_free(&b);
    s = red_url(&b, &p, "https://h/?a=1&&sig=X&");
    ZU_CHECK(streq(s, "https://h/?a=1&&sig=<redacted>&"));
    zu_buf_free(&b);

    ZU_CASE("a fragment survives redaction");
    s = red_url(&b, &p, "https://h/x?api_key=S#frag");
    ZU_CHECK(streq(s, "https://h/x?api_key=<redacted>#frag"));
    zu_buf_free(&b);

    ZU_CASE("both userinfo and a secret parameter in one URL");
    s = red_url(&b, &p, "https://u:p@h:8443/x?sig=S&ok=1");
    ZU_CHECK(streq(s, "https://h:8443/x?sig=<redacted>&ok=1"));
    zu_buf_free(&b);

    ZU_CASE("a URL that does not parse is still redacted (§42, error messages)");
    /* This is the case that matters most: the malformed URL is precisely the
     * one an error message is about, so redaction cannot depend on parsing. */
    s = red_url(&b, &p, "https://user:pw@h:99999999/][?api_key=S");
    ZU_CHECK(strstr(s, "pw") == NULL);
    ZU_CHECK(strstr(s, "user") == NULL);
    ZU_CHECK(strstr(s, "<redacted>") != NULL);
    zu_buf_free(&b);

    ZU_CASE("the scheme is anchored, so arbitrary text is never mangled");
    /* Scanning for "://" anywhere treated this as scheme + authority and
     * DELETED " with u:p@" from the middle. Silently removing text from a
     * diagnostic is worse than not redacting it. */
    s = red_url(&b, &p, "not a url at all :// with u:p@h");
    ZU_CHECK(streq(s, "not a url at all :// with u:p@h"));
    zu_buf_free(&b);
    s = red_url(&b, &p, "1http://u:p@h/");   /* a scheme cannot start with a digit */
    ZU_CHECK(streq(s, "1http://u:p@h/"));
    zu_buf_free(&b);

    ZU_CASE("a credential nested in a query VALUE is a documented gap");
    /* Anchoring the scheme means a URL inside a query parameter is not
     * descended into. The mitigation is the parameter list: name the
     * parameter and its whole value is replaced. Asserted so the behaviour is
     * visible rather than discovered later. */
    s = red_url(&b, &p, "https://h/cb?next=http://u:pw@evil.example/");
    ZU_CHECK(strstr(s, "u:pw") != NULL);          /* not redacted, by design */
    zu_buf_free(&b);
    {
        static const char *const extra_p[] = { "next", NULL };
        zu_redact_policy q;
        zu_redact_policy_init(&q);
        q.extra_params = extra_p;
        s = red_url(&b, &q, "https://h/cb?next=http://u:pw@evil.example/");
        ZU_CHECK(strstr(s, "u:pw") == NULL);      /* mitigated by naming it */
        ZU_CHECK(strstr(s, "<redacted>") != NULL);
        zu_buf_free(&b);
    }

    ZU_CASE("a bare path or garbage passes through without crashing");
    s = red_url(&b, &p, "/just/a/path?api_key=S");
    ZU_CHECK(streq(s, "/just/a/path?api_key=<redacted>"));
    zu_buf_free(&b);
    s = red_url(&b, &p, "");
    ZU_CHECK(streq(s, ""));
    zu_buf_free(&b);
    s = red_url(&b, &p, "@@@");
    ZU_CHECK(streq(s, "@@@"));
    zu_buf_free(&b);

    ZU_CASE("a parameter with no '=' is not treated as a secret");
    s = red_url(&b, &p, "https://h/?api_key&x=1");
    ZU_CHECK(streq(s, "https://h/?api_key&x=1"));
    zu_buf_free(&b);

    ZU_CASE("form bodies use the same policy");
    ZU_CHECK(zu_buf_init(&b, 64, 1 << 20));
    {
        static const char body[] = "user=alice&api_key=SECRET&scope=read";
        const char *out = NULL;
        ZU_CHECK(zu_redact_form_body(&p, body, sizeof body - 1, &b));
        ZU_CHECK(zu_buf_cstr(&b, &out));
        ZU_CHECK(streq(out, "user=alice&api_key=<redacted>&scope=read"));
    }
    zu_buf_free(&b);

    /* ---- §34.1 class chain ---- */

    ZU_CASE("the class chain walks the §34.1 tree");
    {
        const char *chain[ZU_CLASS_CHAIN_MAX];
        int n = zu_code_class_chain(ZU_ERR_TLS_CERT, chain, ZU_CLASS_CHAIN_MAX);
        ZU_CHECK_EQ_INT(n, 3);
        ZU_CHECK(streq(chain[0], "zu_tls_certificate_error"));
        ZU_CHECK(streq(chain[1], "zu_tls_error"));
        ZU_CHECK(streq(chain[2], "zu_error"));

        n = zu_code_class_chain(ZU_ERR_PROXY_AUTH, chain, ZU_CLASS_CHAIN_MAX);
        ZU_CHECK_EQ_INT(n, 3);
        ZU_CHECK(streq(chain[1], "zu_proxy_error"));

        n = zu_code_class_chain(ZU_ERR_INTERRUPTED, chain, ZU_CLASS_CHAIN_MAX);
        ZU_CHECK_EQ_INT(n, 3);
        ZU_CHECK(streq(chain[1], "zu_cancelled_error"));

        n = zu_code_class_chain(ZU_ERR_TOO_MANY_REDIRECTS, chain, ZU_CLASS_CHAIN_MAX);
        ZU_CHECK(streq(chain[1], "zu_redirect_error"));

        /* A direct child of zu_error has a two-element chain. */
        n = zu_code_class_chain(ZU_ERR_DNS, chain, ZU_CLASS_CHAIN_MAX);
        ZU_CHECK_EQ_INT(n, 2);
        ZU_CHECK(streq(chain[0], "zu_dns_error"));
        ZU_CHECK(streq(chain[1], "zu_error"));
    }

    ZU_CASE("every error code produces a usable chain ending in zu_error");
    {
        int code;
        for (code = 1; code < (int)ZU_CODE_COUNT; code++) {
            const char *chain[ZU_CLASS_CHAIN_MAX];
            int n = zu_code_class_chain((zu_code)code, chain, ZU_CLASS_CHAIN_MAX);
            ZU_CHECK(n >= 2);
            ZU_CHECK(streq(chain[n - 1], "zu_error"));
            ZU_CHECK(streq(chain[0], zu_code_class((zu_code)code)));
        }
    }

    ZU_CASE("ZU_OK and out-of-range codes yield no chain");
    {
        const char *chain[ZU_CLASS_CHAIN_MAX];
        ZU_CHECK_EQ_INT(zu_code_class_chain(ZU_OK, chain, ZU_CLASS_CHAIN_MAX), 0);
        ZU_CHECK_EQ_INT(zu_code_class_chain((zu_code)999, chain, ZU_CLASS_CHAIN_MAX), 0);
        ZU_CHECK_EQ_INT(zu_code_class_chain(ZU_ERR_DNS, chain, 0), 0);
    }

    ZU_CASE("no leaks across the suite");
    {
        zu_alloc_stats end;
        zu_alloc_stats_get(&end);
        ZU_CHECK_EQ_INT(end.live_blocks, 0);
    }
}

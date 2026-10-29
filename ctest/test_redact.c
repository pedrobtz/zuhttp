/* Secret redaction — design §42. */
#include "zuh_test.h"
#include "zuh_redact.h"
#include "zuh_error.h"
#include "zuh_alloc.h"
#include <string.h>

void suite_redact(void);

static const char *red_url(zuh_buffer *b, const zuh_redact_policy *p, const char *u) {
    const char *s = NULL;
    if (!zuh_buf_init(b, 64, 1 << 20)) return NULL;
    if (!zuh_redact_url(p, u, strlen(u), b)) return NULL;
    if (!zuh_buf_cstr(b, &s)) return NULL;
    return s;
}
static int streq(const char *a, const char *b) { return a && b && strcmp(a, b) == 0; }

void suite_redact(void) {
    zuh_redact_policy p;
    zuh_buffer b;
    const char *s;

    zuh_redact_policy_init(&p);

    ZUH_CASE("the §42.1 default header list");
    {
        const char *yes[] = { "Authorization", "authorization", "AUTHORIZATION",
                              "Proxy-Authorization", "Cookie", "Set-Cookie",
                              "X-Api-Key", "x-auth-token" };
        const char *no[]  = { "Accept", "Content-Type", "X-Request-Id",
                              "Authorizationx", "uthorization", "" };
        size_t i;
        for (i = 0; i < sizeof yes / sizeof *yes; i++)
            ZUH_CHECK_EQ_INT(zuh_redact_is_secret_header(&p, yes[i], strlen(yes[i])), 1);
        for (i = 0; i < sizeof no / sizeof *no; i++)
            ZUH_CHECK_EQ_INT(zuh_redact_is_secret_header(&p, no[i], strlen(no[i])), 0);
    }

    ZUH_CASE("the §42.1 default parameter list");
    {
        const char *yes[] = { "access_token", "api_key", "signature", "sig", "SIG" };
        const char *no[]  = { "page", "signature2", "si", "" };
        size_t i;
        for (i = 0; i < sizeof yes / sizeof *yes; i++)
            ZUH_CHECK_EQ_INT(zuh_redact_is_secret_param(&p, yes[i], strlen(yes[i])), 1);
        for (i = 0; i < sizeof no / sizeof *no; i++)
            ZUH_CHECK_EQ_INT(zuh_redact_is_secret_param(&p, no[i], strlen(no[i])), 0);
    }

    ZUH_CASE("a caller may add names but cannot remove a default");
    {
        static const char *const extra_h[] = { "X-Corp-Secret", NULL };
        zuh_redact_policy q;
        zuh_redact_policy_init(&q);
        q.extra_headers = extra_h;
        ZUH_CHECK_EQ_INT(zuh_redact_is_secret_header(&q, "X-Corp-Secret", 13), 1);
        ZUH_CHECK_EQ_INT(zuh_redact_is_secret_header(&q, "Authorization", 13), 1);
    }

    ZUH_CASE("userinfo is removed entirely, not masked");
    s = red_url(&b, &p, "https://user:pw@api.example.com/v1/x");
    ZUH_CHECK(streq(s, "https://api.example.com/v1/x"));
    /* Even the username goes: it identifies an account on its own (§42.1). */
    ZUH_CHECK(strstr(s, "user") == NULL);
    ZUH_CHECK(strstr(s, "pw") == NULL);
    zuh_buf_free(&b);

    ZUH_CASE("a username with no password is still removed");
    s = red_url(&b, &p, "https://someone@api.example.com/x");
    ZUH_CHECK(streq(s, "https://api.example.com/x"));
    zuh_buf_free(&b);

    ZUH_CASE("the LAST @ delimits userinfo");
    /* A '@' can appear percent-decoded inside the userinfo, so splitting on
     * the first one would leave part of the credential behind. */
    s = red_url(&b, &p, "https://us@er:p@ss@api.example.com/x");
    ZUH_CHECK(streq(s, "https://api.example.com/x"));
    ZUH_CHECK(strstr(s, "p@ss") == NULL);
    zuh_buf_free(&b);

    ZUH_CASE("a secret query parameter is replaced, others preserved");
    s = red_url(&b, &p, "https://h/v1?page=2&api_key=SECRET&sort=asc");
    ZUH_CHECK(streq(s, "https://h/v1?page=2&api_key=<redacted>&sort=asc"));
    zuh_buf_free(&b);

    ZUH_CASE("the replacement is never a truncated prefix (§42.1)");
    s = red_url(&b, &p, "https://h/?access_token=abcdefghijklmnop");
    ZUH_CHECK(strstr(s, "abc") == NULL);
    ZUH_CHECK(strstr(s, "<redacted>") != NULL);
    zuh_buf_free(&b);

    ZUH_CASE("separators are preserved as written");
    s = red_url(&b, &p, "https://h/?a=1;sig=X;b=2");
    ZUH_CHECK(streq(s, "https://h/?a=1;sig=<redacted>;b=2"));
    zuh_buf_free(&b);
    s = red_url(&b, &p, "https://h/?a=1&&sig=X&");
    ZUH_CHECK(streq(s, "https://h/?a=1&&sig=<redacted>&"));
    zuh_buf_free(&b);

    ZUH_CASE("a fragment survives redaction");
    s = red_url(&b, &p, "https://h/x?api_key=S#frag");
    ZUH_CHECK(streq(s, "https://h/x?api_key=<redacted>#frag"));
    zuh_buf_free(&b);

    ZUH_CASE("both userinfo and a secret parameter in one URL");
    s = red_url(&b, &p, "https://u:p@h:8443/x?sig=S&ok=1");
    ZUH_CHECK(streq(s, "https://h:8443/x?sig=<redacted>&ok=1"));
    zuh_buf_free(&b);

    ZUH_CASE("a URL that does not parse is still redacted (§42, error messages)");
    /* This is the case that matters most: the malformed URL is precisely the
     * one an error message is about, so redaction cannot depend on parsing. */
    s = red_url(&b, &p, "https://user:pw@h:99999999/][?api_key=S");
    ZUH_CHECK(strstr(s, "pw") == NULL);
    ZUH_CHECK(strstr(s, "user") == NULL);
    ZUH_CHECK(strstr(s, "<redacted>") != NULL);
    zuh_buf_free(&b);

    ZUH_CASE("the scheme is anchored, so arbitrary text is never mangled");
    /* Scanning for "://" anywhere treated this as scheme + authority and
     * DELETED " with u:p@" from the middle. Silently removing text from a
     * diagnostic is worse than not redacting it. */
    s = red_url(&b, &p, "not a url at all :// with u:p@h");
    ZUH_CHECK(streq(s, "not a url at all :// with u:p@h"));
    zuh_buf_free(&b);
    s = red_url(&b, &p, "1http://u:p@h/");   /* a scheme cannot start with a digit */
    ZUH_CHECK(streq(s, "1http://u:p@h/"));
    zuh_buf_free(&b);

    ZUH_CASE("a credential nested in a query VALUE is a documented gap");
    /* Anchoring the scheme means a URL inside a query parameter is not
     * descended into. The mitigation is the parameter list: name the
     * parameter and its whole value is replaced. Asserted so the behaviour is
     * visible rather than discovered later. */
    s = red_url(&b, &p, "https://h/cb?next=http://u:pw@evil.example/");
    ZUH_CHECK(strstr(s, "u:pw") != NULL);          /* not redacted, by design */
    zuh_buf_free(&b);
    {
        static const char *const extra_p[] = { "next", NULL };
        zuh_redact_policy q;
        zuh_redact_policy_init(&q);
        q.extra_params = extra_p;
        s = red_url(&b, &q, "https://h/cb?next=http://u:pw@evil.example/");
        ZUH_CHECK(strstr(s, "u:pw") == NULL);      /* mitigated by naming it */
        ZUH_CHECK(strstr(s, "<redacted>") != NULL);
        zuh_buf_free(&b);
    }

    ZUH_CASE("a bare path or garbage passes through without crashing");
    s = red_url(&b, &p, "/just/a/path?api_key=S");
    ZUH_CHECK(streq(s, "/just/a/path?api_key=<redacted>"));
    zuh_buf_free(&b);
    s = red_url(&b, &p, "");
    ZUH_CHECK(streq(s, ""));
    zuh_buf_free(&b);
    s = red_url(&b, &p, "@@@");
    ZUH_CHECK(streq(s, "@@@"));
    zuh_buf_free(&b);

    ZUH_CASE("a parameter with no '=' is not treated as a secret");
    s = red_url(&b, &p, "https://h/?api_key&x=1");
    ZUH_CHECK(streq(s, "https://h/?api_key&x=1"));
    zuh_buf_free(&b);

    ZUH_CASE("a percent-encoded secret name is still a secret name (§42.1)");
    {
        /* Matching compared raw bytes, so "%74oken" — token, spelled with an
         * escape any server decodes — passed through with its value. The
         * name is decoded to classify it and written back as it was. */
        static const char *const extra[] = { "session_key", NULL };
        zuh_redact_policy px;
        zuh_redact_policy_init(&px);
        px.extra_params = extra;
        s = red_url(&b, &p, "https://h/?%74oken=S&%61PI_KEY=S&x%3D=1&%zz=2&tok%=3");
        ZUH_CHECK(streq(s, "https://h/?%74oken=<redacted>&%61PI_KEY=<redacted>&x%3D=1&%zz=2&tok%=3"));
        zuh_buf_free(&b);
        s = red_url(&b, &px, "https://h/?session%5fkey=S&%73ession_key=S");
        ZUH_CHECK(streq(s, "https://h/?session%5fkey=<redacted>&%73ession_key=<redacted>"));
        zuh_buf_free(&b);
        ZUH_CHECK(zuh_buf_init(&b, 64, 1 << 20));
        {
            static const char body[] = "%70assword=S&user=a";
            const char *out = NULL;
            ZUH_CHECK(zuh_redact_form_body(&p, body, sizeof body - 1, &b));
            ZUH_CHECK(zuh_buf_cstr(&b, &out));
            ZUH_CHECK(streq(out, "%70assword=<redacted>&user=a"));
        }
        zuh_buf_free(&b);
    }

    ZUH_CASE("form bodies use the same policy");
    ZUH_CHECK(zuh_buf_init(&b, 64, 1 << 20));
    {
        static const char body[] = "user=alice&api_key=SECRET&scope=read";
        const char *out = NULL;
        ZUH_CHECK(zuh_redact_form_body(&p, body, sizeof body - 1, &b));
        ZUH_CHECK(zuh_buf_cstr(&b, &out));
        ZUH_CHECK(streq(out, "user=alice&api_key=<redacted>&scope=read"));
    }
    zuh_buf_free(&b);

    /* ---- §42.1 default parameter names, extended in S14 (D-39) ---- */
    ZUH_CASE("every default secret parameter name is redacted");
    {
        static const char *const names[] = {
            "access_token", "api_key", "apikey", "signature", "sig",
            "client_secret", "password", "passwd", "pwd", "secret",
            "token", "refresh_token", "id_token", "private_key",
            "auth_token", "session_token", NULL
        };
        int i;
        for (i = 0; names[i]; i++) {
            ZUH_CHECK(zuh_redact_is_secret_param(&p, names[i], strlen(names[i])));
            /* Case must not matter: a server that accepts API_KEY accepts it
             * as a credential too. */
            ZUH_CHECK(zuh_redact_is_secret_param(&p, "API_KEY", 7));
        }
    }

    /* The property that makes bare "token" and "secret" safe to include: the
     * comparison is exact, so a pagination cursor or a public identifier that
     * merely CONTAINS a secret name stays readable. Without this, adding
     * "token" would have redacted every page_token in every trace. */
    ZUH_CASE("a name that merely contains a secret name is not redacted");
    {
        static const char *const fine[] = {
            "page_token", "next_token", "tokens", "token_type",
            "password_hint", "secretary", "signature_version",
            "api_key_id", "not_a_secret", NULL
        };
        int i;
        for (i = 0; fine[i]; i++)
            ZUH_CHECK(!zuh_redact_is_secret_param(&p, fine[i], strlen(fine[i])));
    }

    ZUH_CASE("the new names redact in a form body, not just in a URL");
    ZUH_CHECK(zuh_buf_init(&b, 64, 1 << 20));
    {
        static const char body[] =
            "grant_type=client_credentials&client_secret=SHH&password=P&page_token=t2";
        const char *out = NULL;
        ZUH_CHECK(zuh_redact_form_body(&p, body, sizeof body - 1, &b));
        ZUH_CHECK(zuh_buf_cstr(&b, &out));
        ZUH_CHECK(streq(out,
            "grant_type=client_credentials&client_secret=<redacted>"
            "&password=<redacted>&page_token=t2"));
    }
    zuh_buf_free(&b);

    /* ---- §34.1 class chain ---- */

    ZUH_CASE("the class chain walks the §34.1 tree");
    {
        const char *chain[ZUH_CLASS_CHAIN_MAX];
        int n = zuh_code_class_chain(ZUH_ERR_TLS_CERT, chain, ZUH_CLASS_CHAIN_MAX);
        ZUH_CHECK_EQ_INT(n, 4);
        ZUH_CHECK(streq(chain[0], "zu_tls_certificate_error"));
        ZUH_CHECK(streq(chain[1], "zu_tls_error"));
        ZUH_CHECK(streq(chain[2], "zu_error"));
        ZUH_CHECK(streq(chain[3], "zuhttp_error"));   /* D-65 */

        n = zuh_code_class_chain(ZUH_ERR_PROXY_AUTH, chain, ZUH_CLASS_CHAIN_MAX);
        ZUH_CHECK_EQ_INT(n, 4);
        ZUH_CHECK(streq(chain[1], "zu_proxy_error"));

        n = zuh_code_class_chain(ZUH_ERR_INTERRUPTED, chain, ZUH_CLASS_CHAIN_MAX);
        ZUH_CHECK_EQ_INT(n, 4);
        ZUH_CHECK(streq(chain[1], "zu_cancelled_error"));

        n = zuh_code_class_chain(ZUH_ERR_TOO_MANY_REDIRECTS, chain, ZUH_CLASS_CHAIN_MAX);
        ZUH_CHECK(streq(chain[1], "zu_redirect_error"));

        /* A direct child of zu_error has a three-element chain. */
        n = zuh_code_class_chain(ZUH_ERR_DNS, chain, ZUH_CLASS_CHAIN_MAX);
        ZUH_CHECK_EQ_INT(n, 3);
        ZUH_CHECK(streq(chain[0], "zu_dns_error"));
        ZUH_CHECK(streq(chain[1], "zu_error"));
        ZUH_CHECK(streq(chain[2], "zuhttp_error"));
    }

    ZUH_CASE("every chain ends zu_error, zuhttp_error (D-65)");
    {
        int code;
        for (code = 1; code < (int)ZUH_CODE_COUNT; code++) {
            const char *chain[ZUH_CLASS_CHAIN_MAX];
            int n = zuh_code_class_chain((zuh_code)code, chain, ZUH_CLASS_CHAIN_MAX);
            ZUH_CHECK(n >= 3);
            ZUH_CHECK(streq(chain[n - 2], "zu_error"));
            ZUH_CHECK(streq(chain[n - 1], "zuhttp_error"));
            ZUH_CHECK(streq(chain[0], zuh_code_class((zuh_code)code)));
        }
    }

    ZUH_CASE("ZU_OK and out-of-range codes yield no chain");
    {
        const char *chain[ZUH_CLASS_CHAIN_MAX];
        ZUH_CHECK_EQ_INT(zuh_code_class_chain(ZUH_OK, chain, ZUH_CLASS_CHAIN_MAX), 0);
        ZUH_CHECK_EQ_INT(zuh_code_class_chain((zuh_code)999, chain, ZUH_CLASS_CHAIN_MAX), 0);
        ZUH_CHECK_EQ_INT(zuh_code_class_chain(ZUH_ERR_DNS, chain, 0), 0);
    }

    ZUH_CASE("no leaks across the suite");
    {
        zuh_alloc_stats end;
        zuh_alloc_stats_get(&end);
        ZUH_CHECK_EQ_INT(end.live_blocks, 0);
    }
}

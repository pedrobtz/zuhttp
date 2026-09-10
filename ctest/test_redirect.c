#include "zu_test.h"
#include "zu_redirect.h"
#include "zu_alloc.h"
#include <string.h>

void suite_redirect(void);

/* Hand-built URIs: this suite is deliberately independent of D-11. */
static void mk(zu_uri *u, const char *scheme, const char *host, uint16_t port,
               const char *path) {
    zu_uri_init(u);
    u->scheme = (char *)zu_alloc(strlen(scheme) + 1); strcpy(u->scheme, scheme);
    u->host   = (char *)zu_alloc(strlen(host) + 1);   strcpy(u->host, host);
    u->path_query = (char *)zu_alloc(strlen(path) + 1); strcpy(u->path_query, path);
    u->port = port;
    u->is_https = strcmp(scheme, "https") == 0;
}

void suite_redirect(void) {
    zu_redirect_policy p;
    zu_redirect_decision d;
    zu_error e;
    zu_uri a, b;

    zu_redirect_policy_init(&p);

    ZU_CASE("§19.1: 301/302 rewrite POST to GET and drop the body");
    {
        int codes[] = {301, 302};
        size_t i;
        for (i = 0; i < 2; i++) {
            mk(&a, "https", "x.com", 443, "/1"); mk(&b, "https", "x.com", 443, "/2");
            zu_error_clear(&e);
            ZU_CHECK_EQ_INT(zu_redirect_decide(&p, codes[i], "POST", &a, &b, 0, &d, &e), ZU_OK);
            ZU_CHECK(d.rewrite_to_get);
            ZU_CHECK(d.drop_body);
            ZU_CHECK(!d.needs_rewindable);
            zu_uri_free(&a); zu_uri_free(&b);
        }
    }

    ZU_CASE("§19.1: 301/302 leave GET and other methods unchanged");
    mk(&a, "https", "x.com", 443, "/1"); mk(&b, "https", "x.com", 443, "/2");
    zu_error_clear(&e);
    ZU_CHECK_EQ_INT(zu_redirect_decide(&p, 301, "GET", &a, &b, 0, &d, &e), ZU_OK);
    ZU_CHECK(!d.rewrite_to_get);
    ZU_CHECK(!d.drop_body);
    ZU_CHECK_EQ_INT(zu_redirect_decide(&p, 302, "PUT", &a, &b, 0, &d, &e), ZU_OK);
    ZU_CHECK(!d.rewrite_to_get);
    zu_uri_free(&a); zu_uri_free(&b);

    ZU_CASE("§19.1: 303 rewrites everything to GET and ALWAYS drops the body");
    mk(&a, "https", "x.com", 443, "/1"); mk(&b, "https", "x.com", 443, "/2");
    zu_error_clear(&e);
    ZU_CHECK_EQ_INT(zu_redirect_decide(&p, 303, "PUT", &a, &b, 0, &d, &e), ZU_OK);
    ZU_CHECK(d.rewrite_to_get);
    ZU_CHECK(d.drop_body);
    ZU_CHECK_EQ_INT(zu_redirect_decide(&p, 303, "POST", &a, &b, 0, &d, &e), ZU_OK);
    ZU_CHECK(d.rewrite_to_get && d.drop_body);
    zu_uri_free(&a); zu_uri_free(&b);

    ZU_CASE("§19.1: 303 keeps HEAD as HEAD");
    mk(&a, "https", "x.com", 443, "/1"); mk(&b, "https", "x.com", 443, "/2");
    zu_error_clear(&e);
    ZU_CHECK_EQ_INT(zu_redirect_decide(&p, 303, "HEAD", &a, &b, 0, &d, &e), ZU_OK);
    ZU_CHECK(!d.rewrite_to_get);
    ZU_CHECK(d.drop_body);
    zu_uri_free(&a); zu_uri_free(&b);

    ZU_CASE("§19.1: 307/308 preserve method and body, and need rewindability");
    {
        int codes[] = {307, 308};
        size_t i;
        for (i = 0; i < 2; i++) {
            mk(&a, "https", "x.com", 443, "/1"); mk(&b, "https", "x.com", 443, "/2");
            zu_error_clear(&e);
            ZU_CHECK_EQ_INT(zu_redirect_decide(&p, codes[i], "POST", &a, &b, 0, &d, &e), ZU_OK);
            ZU_CHECK(!d.rewrite_to_get);
            ZU_CHECK(!d.drop_body);
            ZU_CHECK(d.needs_rewindable);   /* §28.2 */
            zu_uri_free(&a); zu_uri_free(&b);
        }
    }

    ZU_CASE("non-redirect statuses produce no action");
    mk(&a, "https", "x.com", 443, "/"); mk(&b, "https", "x.com", 443, "/");
    zu_error_clear(&e);
    ZU_CHECK_EQ_INT(zu_redirect_decide(&p, 200, "GET", &a, &b, 0, &d, &e), ZU_OK);
    ZU_CHECK_EQ_INT(d.action, ZU_REDIRECT_NONE);
    ZU_CHECK_EQ_INT(zu_redirect_decide(&p, 304, "GET", &a, &b, 0, &d, &e), ZU_OK);
    ZU_CHECK_EQ_INT(d.action, ZU_REDIRECT_NONE);
    zu_uri_free(&a); zu_uri_free(&b);

    /* §19.2 — the point of the rule is that HOST alone is not the test. */
    ZU_CASE("§19.2: same origin keeps credentials");
    mk(&a, "https", "api.x.com", 443, "/1"); mk(&b, "https", "api.x.com", 443, "/2");
    zu_error_clear(&e);
    zu_redirect_decide(&p, 302, "GET", &a, &b, 0, &d, &e);
    ZU_CHECK(!d.strip_credentials);
    zu_uri_free(&a); zu_uri_free(&b);

    ZU_CASE("§19.2: a different HOST strips, even on the same registrable domain");
    mk(&a, "https", "api.x.com", 443, "/1"); mk(&b, "https", "other.x.com", 443, "/2");
    zu_error_clear(&e);
    zu_redirect_decide(&p, 302, "GET", &a, &b, 0, &d, &e);
    ZU_CHECK(d.strip_credentials);
    zu_uri_free(&a); zu_uri_free(&b);

    ZU_CASE("§19.2: a different PORT strips");
    mk(&a, "https", "x.com", 443, "/1"); mk(&b, "https", "x.com", 8443, "/2");
    zu_error_clear(&e);
    zu_redirect_decide(&p, 302, "GET", &a, &b, 0, &d, &e);
    ZU_CHECK(d.strip_credentials);
    zu_uri_free(&a); zu_uri_free(&b);

    ZU_CASE("§19.2: a different SCHEME strips (upgrade case)");
    mk(&a, "http", "x.com", 80, "/1"); mk(&b, "https", "x.com", 443, "/2");
    zu_error_clear(&e);
    zu_redirect_decide(&p, 302, "GET", &a, &b, 0, &d, &e);
    ZU_CHECK(d.strip_credentials);
    zu_uri_free(&a); zu_uri_free(&b);

    ZU_CASE("an implicit default port equals the explicit one");
    mk(&a, "https", "x.com", 0, "/1"); mk(&b, "https", "x.com", 443, "/2");
    ZU_CHECK(zu_uri_same_origin(&a, &b));
    zu_uri_free(&a); zu_uri_free(&b);
    mk(&a, "http", "x.com", 0, "/1"); mk(&b, "http", "x.com", 80, "/2");
    ZU_CHECK(zu_uri_same_origin(&a, &b));
    zu_uri_free(&a); zu_uri_free(&b);

    ZU_CASE("§19.3: HTTPS to HTTP downgrade is an ERROR, not a silent stop");
    mk(&a, "https", "x.com", 443, "/1"); mk(&b, "http", "x.com", 80, "/2");
    zu_error_clear(&e);
    ZU_CHECK_EQ_INT(zu_redirect_decide(&p, 302, "GET", &a, &b, 0, &d, &e), ZU_ERR_REDIRECT);
    zu_uri_free(&a); zu_uri_free(&b);

    ZU_CASE("§19.3: the downgrade is allowed when explicitly enabled");
    {
        zu_redirect_policy lax;
        zu_redirect_policy_init(&lax);
        lax.allow_downgrade = 1;
        mk(&a, "https", "x.com", 443, "/1"); mk(&b, "http", "x.com", 80, "/2");
        zu_error_clear(&e);
        ZU_CHECK_EQ_INT(zu_redirect_decide(&lax, 302, "GET", &a, &b, 0, &d, &e), ZU_OK);
        ZU_CHECK(d.strip_credentials);   /* still cross-origin */
        zu_uri_free(&a); zu_uri_free(&b);
    }

    ZU_CASE("§19.4: the hop limit is chain-wide");
    mk(&a, "https", "x.com", 443, "/1"); mk(&b, "https", "x.com", 443, "/2");
    zu_error_clear(&e);
    ZU_CHECK_EQ_INT(zu_redirect_decide(&p, 302, "GET", &a, &b, 9, &d, &e), ZU_OK);
    ZU_CHECK_EQ_INT(zu_redirect_decide(&p, 302, "GET", &a, &b, 10, &d, &e),
                    ZU_ERR_TOO_MANY_REDIRECTS);
    zu_uri_free(&a); zu_uri_free(&b);

    ZU_CASE("§19.2: stripping removes every credential-bearing field");
    {
        zu_headers h;
        zu_headers_init(&h);
        zu_headers_add_str(&h, "Authorization", "Bearer t");
        zu_headers_add_str(&h, "Cookie", "a=1");
        zu_headers_add_str(&h, "Cookie", "b=2");
        zu_headers_add_str(&h, "Proxy-Authorization", "Basic x");
        zu_headers_add_str(&h, "Accept", "*/*");
        ZU_CHECK_EQ_INT(zu_redirect_strip_credentials(&h), 4);
        ZU_CHECK_EQ_INT(h.n, 1);
        ZU_CHECK(zu_headers_has(&h, "Accept"));
        ZU_CHECK(!zu_headers_has(&h, "authorization"));
        zu_headers_free(&h);
    }

    ZU_CASE("§19.4: loop detection on (method, absolute URL)");
    {
        zu_redirect_trail t;
        zu_redirect_trail_init(&t);
        mk(&a, "https", "x.com", 443, "/a");
        mk(&b, "https", "x.com", 443, "/b");
        ZU_CHECK(zu_redirect_trail_add(&t, "GET", &a));
        ZU_CHECK(zu_redirect_trail_add(&t, "GET", &b));
        ZU_CHECK(!zu_redirect_trail_add(&t, "GET", &a));   /* loop */
        ZU_CHECK(zu_redirect_trail_add(&t, "POST", &a));   /* method differs */
        zu_redirect_trail_free(&t);
        zu_uri_free(&a); zu_uri_free(&b);
    }

    ZU_CASE("§42: an origin string never leaks userinfo");
    {
        char buf[128];
        mk(&a, "https", "x.com", 443, "/");
        a.userinfo = (char *)zu_alloc(16); strcpy(a.userinfo, "user:secret");
        ZU_CHECK(zu_uri_origin_string(&a, buf, sizeof buf));
        ZU_CHECK(strstr(buf, "secret") == NULL);
        ZU_CHECK(strcmp(buf, "https://x.com") == 0);
        zu_uri_free(&a);
    }

    ZU_CASE("no leaks across the suite");
    {
        zu_alloc_stats st;
        zu_alloc_stats_get(&st);
        ZU_CHECK_EQ_INT(st.live_blocks, 0);
    }
}

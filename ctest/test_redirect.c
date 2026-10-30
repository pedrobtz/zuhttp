#include "zuh_test.h"
#include "zuh_redirect.h"
#include "zuh_alloc.h"
#include <string.h>

void suite_redirect(void);

/* Hand-built URIs: this suite is deliberately independent of D-11. */
static void mk(zuh_uri *u, const char *scheme, const char *host, uint16_t port,
               const char *path) {
    zuh_uri_init(u);
    u->scheme = (char *)zuh_alloc(strlen(scheme) + 1); strcpy(u->scheme, scheme);
    u->host   = (char *)zuh_alloc(strlen(host) + 1);   strcpy(u->host, host);
    u->path_query = (char *)zuh_alloc(strlen(path) + 1); strcpy(u->path_query, path);
    u->port = port;
    u->is_https = strcmp(scheme, "https") == 0;
}

void suite_redirect(void) {
    zuh_redirect_policy p;
    zuh_redirect_decision d;
    zuh_error e;
    zuh_uri a, b;

    zuh_redirect_policy_init(&p);

    ZUH_CASE("§19.1: 301/302 rewrite POST to GET and drop the body");
    {
        int codes[] = {301, 302};
        size_t i;
        for (i = 0; i < 2; i++) {
            mk(&a, "https", "x.com", 443, "/1"); mk(&b, "https", "x.com", 443, "/2");
            zuh_error_clear(&e);
            ZUH_CHECK_EQ_INT(zuh_redirect_decide(&p, codes[i], "POST", &a, &b, 0, &d, &e), ZUH_OK);
            ZUH_CHECK(d.rewrite_to_get);
            ZUH_CHECK(d.drop_body);
            ZUH_CHECK(!d.needs_rewindable);
            zuh_uri_free(&a); zuh_uri_free(&b);
        }
    }

    ZUH_CASE("§19.1: 301/302 leave GET and other methods unchanged");
    mk(&a, "https", "x.com", 443, "/1"); mk(&b, "https", "x.com", 443, "/2");
    zuh_error_clear(&e);
    ZUH_CHECK_EQ_INT(zuh_redirect_decide(&p, 301, "GET", &a, &b, 0, &d, &e), ZUH_OK);
    ZUH_CHECK(!d.rewrite_to_get);
    ZUH_CHECK(!d.drop_body);
    ZUH_CHECK_EQ_INT(zuh_redirect_decide(&p, 302, "PUT", &a, &b, 0, &d, &e), ZUH_OK);
    ZUH_CHECK(!d.rewrite_to_get);
    zuh_uri_free(&a); zuh_uri_free(&b);

    ZUH_CASE("§19.1: 303 rewrites everything to GET and ALWAYS drops the body");
    mk(&a, "https", "x.com", 443, "/1"); mk(&b, "https", "x.com", 443, "/2");
    zuh_error_clear(&e);
    ZUH_CHECK_EQ_INT(zuh_redirect_decide(&p, 303, "PUT", &a, &b, 0, &d, &e), ZUH_OK);
    ZUH_CHECK(d.rewrite_to_get);
    ZUH_CHECK(d.drop_body);
    ZUH_CHECK_EQ_INT(zuh_redirect_decide(&p, 303, "POST", &a, &b, 0, &d, &e), ZUH_OK);
    ZUH_CHECK(d.rewrite_to_get && d.drop_body);
    zuh_uri_free(&a); zuh_uri_free(&b);

    ZUH_CASE("§19.1: 303 keeps HEAD as HEAD");
    mk(&a, "https", "x.com", 443, "/1"); mk(&b, "https", "x.com", 443, "/2");
    zuh_error_clear(&e);
    ZUH_CHECK_EQ_INT(zuh_redirect_decide(&p, 303, "HEAD", &a, &b, 0, &d, &e), ZUH_OK);
    ZUH_CHECK(!d.rewrite_to_get);
    ZUH_CHECK(d.drop_body);
    zuh_uri_free(&a); zuh_uri_free(&b);

    ZUH_CASE("§19.1: 307/308 preserve method and body, and need rewindability");
    {
        int codes[] = {307, 308};
        size_t i;
        for (i = 0; i < 2; i++) {
            mk(&a, "https", "x.com", 443, "/1"); mk(&b, "https", "x.com", 443, "/2");
            zuh_error_clear(&e);
            ZUH_CHECK_EQ_INT(zuh_redirect_decide(&p, codes[i], "POST", &a, &b, 0, &d, &e), ZUH_OK);
            ZUH_CHECK(!d.rewrite_to_get);
            ZUH_CHECK(!d.drop_body);
            ZUH_CHECK(d.needs_rewindable);   /* §28.2 */
            zuh_uri_free(&a); zuh_uri_free(&b);
        }
    }

    ZUH_CASE("non-redirect statuses produce no action");
    mk(&a, "https", "x.com", 443, "/"); mk(&b, "https", "x.com", 443, "/");
    zuh_error_clear(&e);
    ZUH_CHECK_EQ_INT(zuh_redirect_decide(&p, 200, "GET", &a, &b, 0, &d, &e), ZUH_OK);
    ZUH_CHECK_EQ_INT(d.action, ZUH_REDIRECT_NONE);
    ZUH_CHECK_EQ_INT(zuh_redirect_decide(&p, 304, "GET", &a, &b, 0, &d, &e), ZUH_OK);
    ZUH_CHECK_EQ_INT(d.action, ZUH_REDIRECT_NONE);
    zuh_uri_free(&a); zuh_uri_free(&b);

    /* §19.2 — the point of the rule is that HOST alone is not the test. */
    ZUH_CASE("§19.2: same origin keeps credentials");
    mk(&a, "https", "api.x.com", 443, "/1"); mk(&b, "https", "api.x.com", 443, "/2");
    zuh_error_clear(&e);
    zuh_redirect_decide(&p, 302, "GET", &a, &b, 0, &d, &e);
    ZUH_CHECK(!d.strip_credentials);
    zuh_uri_free(&a); zuh_uri_free(&b);

    ZUH_CASE("§19.2: a different HOST strips, even on the same registrable domain");
    mk(&a, "https", "api.x.com", 443, "/1"); mk(&b, "https", "other.x.com", 443, "/2");
    zuh_error_clear(&e);
    zuh_redirect_decide(&p, 302, "GET", &a, &b, 0, &d, &e);
    ZUH_CHECK(d.strip_credentials);
    zuh_uri_free(&a); zuh_uri_free(&b);

    ZUH_CASE("§19.2: a different PORT strips");
    mk(&a, "https", "x.com", 443, "/1"); mk(&b, "https", "x.com", 8443, "/2");
    zuh_error_clear(&e);
    zuh_redirect_decide(&p, 302, "GET", &a, &b, 0, &d, &e);
    ZUH_CHECK(d.strip_credentials);
    zuh_uri_free(&a); zuh_uri_free(&b);

    ZUH_CASE("§19.2: a different SCHEME strips (upgrade case)");
    mk(&a, "http", "x.com", 80, "/1"); mk(&b, "https", "x.com", 443, "/2");
    zuh_error_clear(&e);
    zuh_redirect_decide(&p, 302, "GET", &a, &b, 0, &d, &e);
    ZUH_CHECK(d.strip_credentials);
    zuh_uri_free(&a); zuh_uri_free(&b);

    ZUH_CASE("an implicit default port equals the explicit one");
    mk(&a, "https", "x.com", 0, "/1"); mk(&b, "https", "x.com", 443, "/2");
    ZUH_CHECK(zuh_uri_same_origin(&a, &b));
    zuh_uri_free(&a); zuh_uri_free(&b);
    mk(&a, "http", "x.com", 0, "/1"); mk(&b, "http", "x.com", 80, "/2");
    ZUH_CHECK(zuh_uri_same_origin(&a, &b));
    zuh_uri_free(&a); zuh_uri_free(&b);

    ZUH_CASE("§19.3: HTTPS to HTTP downgrade is an ERROR, not a silent stop");
    mk(&a, "https", "x.com", 443, "/1"); mk(&b, "http", "x.com", 80, "/2");
    zuh_error_clear(&e);
    ZUH_CHECK_EQ_INT(zuh_redirect_decide(&p, 302, "GET", &a, &b, 0, &d, &e), ZUH_ERR_REDIRECT);
    zuh_uri_free(&a); zuh_uri_free(&b);

    ZUH_CASE("§19.3: the downgrade is allowed when explicitly enabled");
    {
        zuh_redirect_policy lax;
        zuh_redirect_policy_init(&lax);
        lax.allow_downgrade = 1;
        mk(&a, "https", "x.com", 443, "/1"); mk(&b, "http", "x.com", 80, "/2");
        zuh_error_clear(&e);
        ZUH_CHECK_EQ_INT(zuh_redirect_decide(&lax, 302, "GET", &a, &b, 0, &d, &e), ZUH_OK);
        ZUH_CHECK(d.strip_credentials);   /* still cross-origin */
        zuh_uri_free(&a); zuh_uri_free(&b);
    }

    ZUH_CASE("§19.4: the hop limit is chain-wide");
    mk(&a, "https", "x.com", 443, "/1"); mk(&b, "https", "x.com", 443, "/2");
    zuh_error_clear(&e);
    ZUH_CHECK_EQ_INT(zuh_redirect_decide(&p, 302, "GET", &a, &b, 9, &d, &e), ZUH_OK);
    ZUH_CHECK_EQ_INT(zuh_redirect_decide(&p, 302, "GET", &a, &b, 10, &d, &e),
                    ZUH_ERR_TOO_MANY_REDIRECTS);
    zuh_uri_free(&a); zuh_uri_free(&b);

    ZUH_CASE("§19.2: stripping removes every credential-bearing field");
    {
        zuh_headers h;
        zuh_headers_init(&h);
        zuh_headers_add_str(&h, "Authorization", "Bearer t");
        zuh_headers_add_str(&h, "Cookie", "a=1");
        zuh_headers_add_str(&h, "Cookie", "b=2");
        zuh_headers_add_str(&h, "Proxy-Authorization", "Basic x");
        zuh_headers_add_str(&h, "Accept", "*/*");
        ZUH_CHECK_EQ_INT(zuh_redirect_strip_credentials(&h, NULL), 4);
        ZUH_CHECK_EQ_INT(h.n, 1);
        ZUH_CHECK(zuh_headers_has(&h, "Accept"));
        ZUH_CHECK(!zuh_headers_has(&h, "authorization"));
        zuh_headers_free(&h);
    }

    ZUH_CASE("§19.4: loop detection on (method, absolute URL)");
    {
        zuh_redirect_trail t;
        zuh_redirect_trail_init(&t);
        mk(&a, "https", "x.com", 443, "/a");
        mk(&b, "https", "x.com", 443, "/b");
        ZUH_CHECK_EQ_INT(zuh_redirect_trail_add(&t, "GET", &a), ZUH_OK);
        ZUH_CHECK_EQ_INT(zuh_redirect_trail_add(&t, "GET", &b), ZUH_OK);
        ZUH_CHECK_EQ_INT(zuh_redirect_trail_add(&t, "GET", &a), ZUH_ERR_REDIRECT);  /* loop */
        ZUH_CHECK_EQ_INT(zuh_redirect_trail_add(&t, "POST", &a), ZUH_OK);   /* method differs */
        zuh_redirect_trail_free(&t);
        zuh_uri_free(&a); zuh_uri_free(&b);
    }

    ZUH_CASE("§42: an origin string never leaks userinfo");
    {
        char buf[128];
        mk(&a, "https", "x.com", 443, "/");
        a.userinfo = (char *)zuh_alloc(16); strcpy(a.userinfo, "user:secret");
        ZUH_CHECK(zuh_uri_origin_string(&a, buf, sizeof buf));
        ZUH_CHECK(strstr(buf, "secret") == NULL);
        ZUH_CHECK(strcmp(buf, "https://x.com") == 0);
        zuh_uri_free(&a);
    }

    ZUH_CASE("no leaks across the suite");
    {
        zuh_alloc_stats st;
        zuh_alloc_stats_get(&st);
        ZUH_CHECK_EQ_INT(st.live_blocks, 0);
    }
}

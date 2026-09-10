/* URI parsing and relative resolution — design §8.2 (D-11), §19.6.
 *
 * Two thirds of this suite is about inputs that a GRAMMAR accepts but an HTTP
 * client must not: a port that does not fit in uint16_t, an empty DNS label,
 * an embedded NUL. uriparser is RFC 3986 and correctly accepts those; the
 * policy layer in zu_uri.c is what rejects them, so that is what is tested.
 */
#include "zu_test.h"
#include "zu_uri.h"
#include "zu_alloc.h"
#include <string.h>

void suite_uri(void);

static zu_code P(zu_uri *u, const char *s) {
    return zu_uri_parse(u, s, s + strlen(s));
}
static zu_code R(zu_uri *u, const zu_uri *base, const char *ref) {
    return zu_uri_resolve(u, base, ref, ref + strlen(ref));
}
static int streq(const char *a, const char *b) {
    return a && b && strcmp(a, b) == 0;
}

void suite_uri(void) {
    zu_uri u, base, r;
    char origin[128];

    ZU_CASE("absolute https URL decomposes");
    ZU_CHECK_EQ_INT(P(&u, "https://example.com/a/b?q=1#frag"), ZU_OK);
    ZU_CHECK(streq(u.scheme, "https"));
    ZU_CHECK(streq(u.host, "example.com"));
    ZU_CHECK(streq(u.path_query, "/a/b?q=1"));   /* fragment dropped, RFC 7230 §5.3 */
    ZU_CHECK_EQ_INT(u.port, 443);
    ZU_CHECK_EQ_INT(u.port_explicit, 0);
    ZU_CHECK_EQ_INT(u.is_https, 1);
    ZU_CHECK(u.userinfo == NULL);
    zu_uri_free(&u);

    ZU_CASE("scheme and host are lowercased, path is NOT");
    ZU_CHECK_EQ_INT(P(&u, "HTTPS://EXAMPLE.COM/Path/Case?Q=V"), ZU_OK);
    ZU_CHECK(streq(u.scheme, "https"));
    ZU_CHECK(streq(u.host, "example.com"));
    /* Rewriting the target could change what the origin server resolves. */
    ZU_CHECK(streq(u.path_query, "/Path/Case?Q=V"));
    zu_uri_free(&u);

    ZU_CASE("empty path becomes /");
    ZU_CHECK_EQ_INT(P(&u, "http://example.com"), ZU_OK);
    ZU_CHECK(streq(u.path_query, "/"));
    ZU_CHECK_EQ_INT(u.port, 80);
    zu_uri_free(&u);

    ZU_CASE("percent-encoding in the path is preserved verbatim");
    ZU_CHECK_EQ_INT(P(&u, "http://h/a%2Fb/c%20d?x=%41"), ZU_OK);
    ZU_CHECK(streq(u.path_query, "/a%2Fb/c%20d?x=%41"));
    zu_uri_free(&u);

    /* ---- origin confusion: this governs credential stripping (§19.2) ---- */

    ZU_CASE("userinfo is moved out and the real host wins");
    ZU_CHECK_EQ_INT(P(&u, "https://good.com@evil.com/x"), ZU_OK);
    ZU_CHECK(streq(u.host, "evil.com"));
    ZU_CHECK(streq(u.userinfo, "good.com"));
    zu_uri_free(&u);

    ZU_CASE("user:pw@host splits correctly");
    ZU_CHECK_EQ_INT(P(&u, "https://user:pw@example.com/"), ZU_OK);
    ZU_CHECK(streq(u.host, "example.com"));
    ZU_CHECK(streq(u.userinfo, "user:pw"));
    zu_uri_free(&u);

    ZU_CASE("a fragment cannot smuggle an authority");
    ZU_CHECK_EQ_INT(P(&u, "https://evil.com#@good.com/"), ZU_OK);
    ZU_CHECK(streq(u.host, "evil.com"));
    zu_uri_free(&u);

    ZU_CASE("origin string never leaks userinfo (§42)");
    ZU_CHECK_EQ_INT(P(&u, "https://user:secret@example.com:8443/x"), ZU_OK);
    ZU_CHECK(zu_uri_origin_string(&u, origin, sizeof origin));
    ZU_CHECK(streq(origin, "https://example.com:8443"));
    ZU_CHECK(strstr(origin, "secret") == NULL);
    zu_uri_free(&u);

    /* ---- ports: RFC 3986 says DIGIT*, uint16_t disagrees ---- */

    ZU_CASE("explicit port is recorded as explicit");
    ZU_CHECK_EQ_INT(P(&u, "http://example.com:8080/"), ZU_OK);
    ZU_CHECK_EQ_INT(u.port, 8080);
    ZU_CHECK_EQ_INT(u.port_explicit, 1);
    zu_uri_free(&u);

    ZU_CASE("port 65536 is rejected, not truncated to 0");
    ZU_CHECK_EQ_INT(P(&u, "http://example.com:65536/"), ZU_ERR_URL);
    ZU_CHECK_EQ_INT(P(&u, "http://example.com:99999999999/"), ZU_ERR_URL);
    ZU_CHECK_EQ_INT(u.port, 0);

    ZU_CASE("port 65535 is the boundary and is accepted");
    ZU_CHECK_EQ_INT(P(&u, "http://example.com:65535/"), ZU_OK);
    ZU_CHECK_EQ_INT(u.port, 65535);
    zu_uri_free(&u);

    ZU_CASE("leading zeros in a port are numeric, so :0443 == :443");
    ZU_CHECK_EQ_INT(P(&u, "https://example.com:0443/"), ZU_OK);
    ZU_CHECK_EQ_INT(u.port, 443);
    zu_uri_free(&u);

    ZU_CASE("an empty port means the scheme default");
    ZU_CHECK_EQ_INT(P(&u, "http://example.com:/"), ZU_OK);
    ZU_CHECK_EQ_INT(u.port, 80);
    ZU_CHECK_EQ_INT(u.port_explicit, 0);
    zu_uri_free(&u);

    ZU_CASE("port 0 is not a connectable port");
    ZU_CHECK_EQ_INT(P(&u, "http://example.com:0/"), ZU_ERR_URL);

    /* ---- hosts ---- */

    ZU_CASE("IPv6 literal is stored without brackets");
    ZU_CHECK_EQ_INT(P(&u, "https://[::1]:8443/x"), ZU_OK);
    ZU_CHECK(streq(u.host, "::1"));
    ZU_CHECK_EQ_INT(u.port, 8443);
    zu_uri_free(&u);

    ZU_CASE("IPv4 literal parses");
    ZU_CHECK_EQ_INT(P(&u, "http://192.168.0.1/x"), ZU_OK);
    ZU_CHECK(streq(u.host, "192.168.0.1"));
    zu_uri_free(&u);

    ZU_CASE("one trailing root dot is stripped so origins compare equal");
    ZU_CHECK_EQ_INT(P(&u, "https://example.com./x"), ZU_OK);
    ZU_CHECK(streq(u.host, "example.com"));
    ZU_CHECK_EQ_INT(P(&base, "https://example.com/x"), ZU_OK);
    ZU_CHECK_EQ_INT(zu_uri_same_origin(&u, &base), 1);
    zu_uri_free(&u); zu_uri_free(&base);

    ZU_CASE("an IPvFuture literal is rejected (found by the S18 fuzzer)");
    /* RFC 3986 §3.2.2: IP-literal = IPv6address / IPvFuture, where
     * IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" ).
     * These are valid URIs and uriparser accepts them, but zuhttp cannot
     * connect to one, and accepting it puts ';' '*' and ':' into the host
     * that then reaches getaddrinfo() and the Host header. */
    ZU_CHECK_EQ_INT(P(&u, "http://[v7.xyz]/"), ZU_ERR_URL);
    ZU_CHECK_EQ_INT(P(&u, "http://[veee.0;;;;***UU;;;;;;;;;;;;;:]/"), ZU_ERR_URL);
    ZU_CHECK_EQ_INT(P(&u, "http://[vF.a:b:c]/"), ZU_ERR_URL);
    /* ...while a real IPv6 literal still works. */
    ZU_CHECK_EQ_INT(P(&u, "http://[::1]/"), ZU_OK);
    ZU_CHECK(streq(u.host, "::1"));
    zu_uri_free(&u);

    ZU_CASE("an empty DNS label is rejected");
    ZU_CHECK_EQ_INT(P(&u, "https://example.com../x"), ZU_ERR_URL);
    ZU_CHECK_EQ_INT(P(&u, "https://.example.com/x"), ZU_ERR_URL);
    ZU_CHECK_EQ_INT(P(&u, "https://./x"), ZU_ERR_URL);

    ZU_CASE("whitespace and backslash in the authority are rejected");
    ZU_CHECK_EQ_INT(P(&u, "http://exa mple.com/"), ZU_ERR_URL);
    ZU_CHECK_EQ_INT(P(&u, "http://example.com\t/"), ZU_ERR_URL);
    ZU_CHECK_EQ_INT(P(&u, "http://example.com\n/"), ZU_ERR_URL);
    ZU_CHECK_EQ_INT(P(&u, "https://good.com\\@evil.com/"), ZU_ERR_URL);

    ZU_CASE("non-HTTP schemes are rejected");
    ZU_CHECK_EQ_INT(P(&u, "ftp://example.com/x"), ZU_ERR_URL);
    ZU_CHECK_EQ_INT(P(&u, "file:///etc/passwd"), ZU_ERR_URL);
    ZU_CHECK_EQ_INT(P(&u, "mailto:a@b.com"), ZU_ERR_URL);
    ZU_CHECK_EQ_INT(P(&u, "javascript:alert(1)"), ZU_ERR_URL);

    ZU_CASE("a relative reference is not an absolute URL");
    ZU_CHECK_EQ_INT(P(&u, "/just/a/path"), ZU_ERR_URL);
    ZU_CHECK_EQ_INT(P(&u, "example.com/x"), ZU_ERR_URL);
    ZU_CHECK_EQ_INT(P(&u, ""), ZU_ERR_URL);

    ZU_CASE("an embedded NUL is rejected");
    {
        static const char withnul[] = "http://example.com/a\0b";
        ZU_CHECK_EQ_INT(zu_uri_parse(&u, withnul, withnul + sizeof withnul - 1),
                        ZU_ERR_URL);
    }

    ZU_CASE("input need not be NUL-terminated");
    {
        /* A Location header is a range into the response buffer. Anything
         * that reads past `last` shows up here under ASan. */
        char raw[16];
        memcpy(raw, "http://h/xJUNKJU", 16);
        ZU_CHECK_EQ_INT(zu_uri_parse(&u, raw, raw + 10), ZU_OK);
        ZU_CHECK(streq(u.host, "h"));
        ZU_CHECK(streq(u.path_query, "/x"));
        zu_uri_free(&u);
    }

    /* ---- relative resolution, §19.6 ---- */

    ZU_CHECK_EQ_INT(P(&base, "http://a/b/c/d;p?q"), ZU_OK);

    ZU_CASE("RFC 3986 §5.4.1 normal examples");
    ZU_CHECK_EQ_INT(R(&r, &base, "g"), ZU_OK);
    ZU_CHECK(streq(r.path_query, "/b/c/g")); zu_uri_free(&r);
    ZU_CHECK_EQ_INT(R(&r, &base, "./g"), ZU_OK);
    ZU_CHECK(streq(r.path_query, "/b/c/g")); zu_uri_free(&r);
    ZU_CHECK_EQ_INT(R(&r, &base, "g/"), ZU_OK);
    ZU_CHECK(streq(r.path_query, "/b/c/g/")); zu_uri_free(&r);
    ZU_CHECK_EQ_INT(R(&r, &base, "/g"), ZU_OK);
    ZU_CHECK(streq(r.path_query, "/g")); zu_uri_free(&r);
    ZU_CHECK_EQ_INT(R(&r, &base, "?y"), ZU_OK);
    ZU_CHECK(streq(r.path_query, "/b/c/d;p?y")); zu_uri_free(&r);
    ZU_CHECK_EQ_INT(R(&r, &base, "g?y"), ZU_OK);
    ZU_CHECK(streq(r.path_query, "/b/c/g?y")); zu_uri_free(&r);
    ZU_CHECK_EQ_INT(R(&r, &base, "../g"), ZU_OK);
    ZU_CHECK(streq(r.path_query, "/b/g")); zu_uri_free(&r);
    ZU_CHECK_EQ_INT(R(&r, &base, "../../g"), ZU_OK);
    ZU_CHECK(streq(r.path_query, "/g")); zu_uri_free(&r);

    ZU_CASE("RFC 3986 §5.4.2 — .. cannot climb above root");
    ZU_CHECK_EQ_INT(R(&r, &base, "../../../g"), ZU_OK);
    ZU_CHECK(streq(r.path_query, "/g"));
    ZU_CHECK(streq(r.host, "a"));
    zu_uri_free(&r);
    ZU_CHECK_EQ_INT(R(&r, &base, "../../../../g"), ZU_OK);
    ZU_CHECK(streq(r.path_query, "/g"));
    zu_uri_free(&r);

    ZU_CASE("an absolute Location ignores the base entirely");
    ZU_CHECK_EQ_INT(R(&r, &base, "https://other.example:8443/z"), ZU_OK);
    ZU_CHECK(streq(r.host, "other.example"));
    ZU_CHECK(streq(r.scheme, "https"));
    ZU_CHECK_EQ_INT(r.port, 8443);
    ZU_CHECK(streq(r.path_query, "/z"));
    ZU_CHECK_EQ_INT(zu_uri_same_origin(&r, &base), 0);
    zu_uri_free(&r);

    ZU_CASE("a protocol-relative Location keeps the base scheme");
    ZU_CHECK_EQ_INT(R(&r, &base, "//other.example/z"), ZU_OK);
    ZU_CHECK(streq(r.scheme, "http"));
    ZU_CHECK(streq(r.host, "other.example"));
    zu_uri_free(&r);

    ZU_CASE("resolution applies the same policy as parsing");
    ZU_CHECK_EQ_INT(R(&r, &base, "ftp://x/y"), ZU_ERR_URL);
    ZU_CHECK_EQ_INT(R(&r, &base, "//h:65536/y"), ZU_ERR_URL);

    zu_uri_free(&base);

    ZU_CASE("resolution does not carry the base userinfo into the result");
    ZU_CHECK_EQ_INT(P(&base, "https://user:pw@example.com/a/b"), ZU_OK);
    ZU_CHECK(streq(base.userinfo, "user:pw"));
    ZU_CHECK_EQ_INT(R(&r, &base, "../c"), ZU_OK);
    ZU_CHECK(streq(r.host, "example.com"));
    ZU_CHECK(streq(r.path_query, "/c"));
    /* §19.2 decides whether credentials survive; it works on the struct, so
     * resolution must not smuggle them through the text round-trip. */
    ZU_CHECK(r.userinfo == NULL);
    zu_uri_free(&r);
    zu_uri_free(&base);

    ZU_CASE("an IPv6 base survives the resolve round-trip");
    ZU_CHECK_EQ_INT(P(&base, "https://[2001:db8::1]:8443/a/b"), ZU_OK);
    ZU_CHECK_EQ_INT(R(&r, &base, "../c"), ZU_OK);
    ZU_CHECK(streq(r.host, "2001:db8::1"));
    ZU_CHECK_EQ_INT(r.port, 8443);
    ZU_CHECK(streq(r.path_query, "/c"));
    zu_uri_free(&r);
    zu_uri_free(&base);

    /* ---- allocator integration ---- */

    ZU_CASE("uriparser allocates through zu_alloc and leaks nothing on OOM");
    {
        zu_alloc_stats before, after;
        long n;
        zu_alloc_stats_get(&before);
        for (n = 0; n < 40; n++) {
            zu_uri tmp;
            zu_alloc_fail_after(n);
            if (P(&tmp, "https://user@example.com:8443/a/b?q=1") == ZU_OK)
                zu_uri_free(&tmp);
            zu_alloc_fail_after(-1);
        }
        zu_alloc_stats_get(&after);
        /* If the parser had used bare malloc, live_blocks would not move at
         * all and this test would be vacuous — so assert it DID allocate. */
        ZU_CHECK(after.total_allocs > before.total_allocs);
        ZU_CHECK_EQ_INT(after.live_blocks, before.live_blocks);
    }
}

/* URI parsing and relative resolution — design §8.2 (D-11), §19.6.
 *
 * Two thirds of this suite is about inputs that a GRAMMAR accepts but an HTTP
 * client must not: a port that does not fit in uint16_t, an empty DNS label,
 * an embedded NUL. uriparser is RFC 3986 and correctly accepts those; the
 * policy layer in zuh_uri.c is what rejects them, so that is what is tested.
 */
#include "zuh_test.h"
#include "zuh_uri.h"
#include "zuh_alloc.h"
#include <string.h>

void suite_uri(void);

static zuh_code P(zuh_uri *u, const char *s) {
    return zuh_uri_parse(u, s, s + strlen(s));
}
static zuh_code R(zuh_uri *u, const zuh_uri *base, const char *ref) {
    return zuh_uri_resolve(u, base, ref, ref + strlen(ref));
}
static int streq(const char *a, const char *b) {
    return a && b && strcmp(a, b) == 0;
}

void suite_uri(void) {
    zuh_uri u, base, r;
    char origin[128];

    ZUH_CASE("absolute https URL decomposes");
    ZUH_CHECK_EQ_INT(P(&u, "https://example.com/a/b?q=1#frag"), ZUH_OK);
    ZUH_CHECK(streq(u.scheme, "https"));
    ZUH_CHECK(streq(u.host, "example.com"));
    ZUH_CHECK(streq(u.path_query, "/a/b?q=1"));   /* fragment dropped, RFC 7230 §5.3 */
    ZUH_CHECK_EQ_INT(u.port, 443);
    ZUH_CHECK_EQ_INT(u.port_explicit, 0);
    ZUH_CHECK_EQ_INT(u.is_https, 1);
    ZUH_CHECK(u.userinfo == NULL);
    zuh_uri_free(&u);

    ZUH_CASE("scheme and host are lowercased, path is NOT");
    ZUH_CHECK_EQ_INT(P(&u, "HTTPS://EXAMPLE.COM/Path/Case?Q=V"), ZUH_OK);
    ZUH_CHECK(streq(u.scheme, "https"));
    ZUH_CHECK(streq(u.host, "example.com"));
    /* Rewriting the target could change what the origin server resolves. */
    ZUH_CHECK(streq(u.path_query, "/Path/Case?Q=V"));
    zuh_uri_free(&u);

    ZUH_CASE("empty path becomes /");
    ZUH_CHECK_EQ_INT(P(&u, "http://example.com"), ZUH_OK);
    ZUH_CHECK(streq(u.path_query, "/"));
    ZUH_CHECK_EQ_INT(u.port, 80);
    zuh_uri_free(&u);

    ZUH_CASE("percent-encoding in the path is preserved verbatim");
    ZUH_CHECK_EQ_INT(P(&u, "http://h/a%2Fb/c%20d?x=%41"), ZUH_OK);
    ZUH_CHECK(streq(u.path_query, "/a%2Fb/c%20d?x=%41"));
    zuh_uri_free(&u);

    /* ---- origin confusion: this governs credential stripping (§19.2) ---- */

    ZUH_CASE("userinfo is moved out and the real host wins");
    ZUH_CHECK_EQ_INT(P(&u, "https://good.com@evil.com/x"), ZUH_OK);
    ZUH_CHECK(streq(u.host, "evil.com"));
    ZUH_CHECK(streq(u.userinfo, "good.com"));
    zuh_uri_free(&u);

    ZUH_CASE("user:pw@host splits correctly");
    ZUH_CHECK_EQ_INT(P(&u, "https://user:pw@example.com/"), ZUH_OK);
    ZUH_CHECK(streq(u.host, "example.com"));
    ZUH_CHECK(streq(u.userinfo, "user:pw"));
    zuh_uri_free(&u);

    ZUH_CASE("a fragment cannot smuggle an authority");
    ZUH_CHECK_EQ_INT(P(&u, "https://evil.com#@good.com/"), ZUH_OK);
    ZUH_CHECK(streq(u.host, "evil.com"));
    zuh_uri_free(&u);

    ZUH_CASE("origin string never leaks userinfo (§42)");
    ZUH_CHECK_EQ_INT(P(&u, "https://user:secret@example.com:8443/x"), ZUH_OK);
    ZUH_CHECK(zuh_uri_origin_string(&u, origin, sizeof origin));
    ZUH_CHECK(streq(origin, "https://example.com:8443"));
    ZUH_CHECK(strstr(origin, "secret") == NULL);
    zuh_uri_free(&u);

    /* ---- ports: RFC 3986 says DIGIT*, uint16_t disagrees ---- */

    ZUH_CASE("explicit port is recorded as explicit");
    ZUH_CHECK_EQ_INT(P(&u, "http://example.com:8080/"), ZUH_OK);
    ZUH_CHECK_EQ_INT(u.port, 8080);
    ZUH_CHECK_EQ_INT(u.port_explicit, 1);
    zuh_uri_free(&u);

    ZUH_CASE("port 65536 is rejected, not truncated to 0");
    ZUH_CHECK_EQ_INT(P(&u, "http://example.com:65536/"), ZUH_ERR_URL);
    ZUH_CHECK_EQ_INT(P(&u, "http://example.com:99999999999/"), ZUH_ERR_URL);
    ZUH_CHECK_EQ_INT(u.port, 0);

    ZUH_CASE("port 65535 is the boundary and is accepted");
    ZUH_CHECK_EQ_INT(P(&u, "http://example.com:65535/"), ZUH_OK);
    ZUH_CHECK_EQ_INT(u.port, 65535);
    zuh_uri_free(&u);

    ZUH_CASE("leading zeros in a port are numeric, so :0443 == :443");
    ZUH_CHECK_EQ_INT(P(&u, "https://example.com:0443/"), ZUH_OK);
    ZUH_CHECK_EQ_INT(u.port, 443);
    zuh_uri_free(&u);

    ZUH_CASE("an empty port means the scheme default");
    ZUH_CHECK_EQ_INT(P(&u, "http://example.com:/"), ZUH_OK);
    ZUH_CHECK_EQ_INT(u.port, 80);
    ZUH_CHECK_EQ_INT(u.port_explicit, 0);
    zuh_uri_free(&u);

    ZUH_CASE("port 0 is not a connectable port");
    ZUH_CHECK_EQ_INT(P(&u, "http://example.com:0/"), ZUH_ERR_URL);

    /* ---- hosts ---- */

    ZUH_CASE("IPv6 literal is stored without brackets");
    ZUH_CHECK_EQ_INT(P(&u, "https://[::1]:8443/x"), ZUH_OK);
    ZUH_CHECK(streq(u.host, "::1"));
    ZUH_CHECK_EQ_INT(u.port, 8443);
    zuh_uri_free(&u);

    ZUH_CASE("IPv4 literal parses");
    ZUH_CHECK_EQ_INT(P(&u, "http://192.168.0.1/x"), ZUH_OK);
    ZUH_CHECK(streq(u.host, "192.168.0.1"));
    zuh_uri_free(&u);

    ZUH_CASE("one trailing root dot is stripped so origins compare equal");
    ZUH_CHECK_EQ_INT(P(&u, "https://example.com./x"), ZUH_OK);
    ZUH_CHECK(streq(u.host, "example.com"));
    ZUH_CHECK_EQ_INT(P(&base, "https://example.com/x"), ZUH_OK);
    ZUH_CHECK_EQ_INT(zuh_uri_same_origin(&u, &base), 1);
    zuh_uri_free(&u); zuh_uri_free(&base);

    ZUH_CASE("an IPvFuture literal is rejected (found by the S18 fuzzer)");
    /* RFC 3986 §3.2.2: IP-literal = IPv6address / IPvFuture, where
     * IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" ).
     * These are valid URIs and uriparser accepts them, but zuhttp cannot
     * connect to one, and accepting it puts ';' '*' and ':' into the host
     * that then reaches getaddrinfo() and the Host header. */
    ZUH_CHECK_EQ_INT(P(&u, "http://[v7.xyz]/"), ZUH_ERR_URL);
    ZUH_CHECK_EQ_INT(P(&u, "http://[veee.0;;;;***UU;;;;;;;;;;;;;:]/"), ZUH_ERR_URL);
    ZUH_CHECK_EQ_INT(P(&u, "http://[vF.a:b:c]/"), ZUH_ERR_URL);
    /* ...while a real IPv6 literal still works. */
    ZUH_CHECK_EQ_INT(P(&u, "http://[::1]/"), ZUH_OK);
    ZUH_CHECK(streq(u.host, "::1"));
    zuh_uri_free(&u);

    ZUH_CASE("an empty DNS label is rejected");
    ZUH_CHECK_EQ_INT(P(&u, "https://example.com../x"), ZUH_ERR_URL);
    ZUH_CHECK_EQ_INT(P(&u, "https://.example.com/x"), ZUH_ERR_URL);
    ZUH_CHECK_EQ_INT(P(&u, "https://./x"), ZUH_ERR_URL);

    ZUH_CASE("whitespace and backslash in the authority are rejected");
    ZUH_CHECK_EQ_INT(P(&u, "http://exa mple.com/"), ZUH_ERR_URL);
    ZUH_CHECK_EQ_INT(P(&u, "http://example.com\t/"), ZUH_ERR_URL);
    ZUH_CHECK_EQ_INT(P(&u, "http://example.com\n/"), ZUH_ERR_URL);
    ZUH_CHECK_EQ_INT(P(&u, "https://good.com\\@evil.com/"), ZUH_ERR_URL);

    ZUH_CASE("non-HTTP schemes are rejected");
    ZUH_CHECK_EQ_INT(P(&u, "ftp://example.com/x"), ZUH_ERR_URL);
    ZUH_CHECK_EQ_INT(P(&u, "file:///etc/passwd"), ZUH_ERR_URL);
    ZUH_CHECK_EQ_INT(P(&u, "mailto:a@b.com"), ZUH_ERR_URL);
    ZUH_CHECK_EQ_INT(P(&u, "javascript:alert(1)"), ZUH_ERR_URL);

    ZUH_CASE("a relative reference is not an absolute URL");
    ZUH_CHECK_EQ_INT(P(&u, "/just/a/path"), ZUH_ERR_URL);
    ZUH_CHECK_EQ_INT(P(&u, "example.com/x"), ZUH_ERR_URL);
    ZUH_CHECK_EQ_INT(P(&u, ""), ZUH_ERR_URL);

    ZUH_CASE("an embedded NUL is rejected");
    {
        static const char withnul[] = "http://example.com/a\0b";
        ZUH_CHECK_EQ_INT(zuh_uri_parse(&u, withnul, withnul + sizeof withnul - 1),
                        ZUH_ERR_URL);
    }

    ZUH_CASE("input need not be NUL-terminated");
    {
        /* A Location header is a range into the response buffer. Anything
         * that reads past `last` shows up here under ASan. */
        char raw[16];
        memcpy(raw, "http://h/xJUNKJU", 16);
        ZUH_CHECK_EQ_INT(zuh_uri_parse(&u, raw, raw + 10), ZUH_OK);
        ZUH_CHECK(streq(u.host, "h"));
        ZUH_CHECK(streq(u.path_query, "/x"));
        zuh_uri_free(&u);
    }

    /* ---- relative resolution, §19.6 ---- */

    ZUH_CHECK_EQ_INT(P(&base, "http://a/b/c/d;p?q"), ZUH_OK);

    ZUH_CASE("RFC 3986 §5.4.1 normal examples");
    ZUH_CHECK_EQ_INT(R(&r, &base, "g"), ZUH_OK);
    ZUH_CHECK(streq(r.path_query, "/b/c/g")); zuh_uri_free(&r);
    ZUH_CHECK_EQ_INT(R(&r, &base, "./g"), ZUH_OK);
    ZUH_CHECK(streq(r.path_query, "/b/c/g")); zuh_uri_free(&r);
    ZUH_CHECK_EQ_INT(R(&r, &base, "g/"), ZUH_OK);
    ZUH_CHECK(streq(r.path_query, "/b/c/g/")); zuh_uri_free(&r);
    ZUH_CHECK_EQ_INT(R(&r, &base, "/g"), ZUH_OK);
    ZUH_CHECK(streq(r.path_query, "/g")); zuh_uri_free(&r);
    ZUH_CHECK_EQ_INT(R(&r, &base, "?y"), ZUH_OK);
    ZUH_CHECK(streq(r.path_query, "/b/c/d;p?y")); zuh_uri_free(&r);
    ZUH_CHECK_EQ_INT(R(&r, &base, "g?y"), ZUH_OK);
    ZUH_CHECK(streq(r.path_query, "/b/c/g?y")); zuh_uri_free(&r);
    ZUH_CHECK_EQ_INT(R(&r, &base, "../g"), ZUH_OK);
    ZUH_CHECK(streq(r.path_query, "/b/g")); zuh_uri_free(&r);
    ZUH_CHECK_EQ_INT(R(&r, &base, "../../g"), ZUH_OK);
    ZUH_CHECK(streq(r.path_query, "/g")); zuh_uri_free(&r);

    ZUH_CASE("RFC 3986 §5.4.2 — .. cannot climb above root");
    ZUH_CHECK_EQ_INT(R(&r, &base, "../../../g"), ZUH_OK);
    ZUH_CHECK(streq(r.path_query, "/g"));
    ZUH_CHECK(streq(r.host, "a"));
    zuh_uri_free(&r);
    ZUH_CHECK_EQ_INT(R(&r, &base, "../../../../g"), ZUH_OK);
    ZUH_CHECK(streq(r.path_query, "/g"));
    zuh_uri_free(&r);

    ZUH_CASE("an absolute Location ignores the base entirely");
    ZUH_CHECK_EQ_INT(R(&r, &base, "https://other.example:8443/z"), ZUH_OK);
    ZUH_CHECK(streq(r.host, "other.example"));
    ZUH_CHECK(streq(r.scheme, "https"));
    ZUH_CHECK_EQ_INT(r.port, 8443);
    ZUH_CHECK(streq(r.path_query, "/z"));
    ZUH_CHECK_EQ_INT(zuh_uri_same_origin(&r, &base), 0);
    zuh_uri_free(&r);

    ZUH_CASE("a protocol-relative Location keeps the base scheme");
    ZUH_CHECK_EQ_INT(R(&r, &base, "//other.example/z"), ZUH_OK);
    ZUH_CHECK(streq(r.scheme, "http"));
    ZUH_CHECK(streq(r.host, "other.example"));
    zuh_uri_free(&r);

    ZUH_CASE("resolution applies the same policy as parsing");
    ZUH_CHECK_EQ_INT(R(&r, &base, "ftp://x/y"), ZUH_ERR_URL);
    ZUH_CHECK_EQ_INT(R(&r, &base, "//h:65536/y"), ZUH_ERR_URL);

    zuh_uri_free(&base);

    ZUH_CASE("resolution does not carry the base userinfo into the result");
    ZUH_CHECK_EQ_INT(P(&base, "https://user:pw@example.com/a/b"), ZUH_OK);
    ZUH_CHECK(streq(base.userinfo, "user:pw"));
    ZUH_CHECK_EQ_INT(R(&r, &base, "../c"), ZUH_OK);
    ZUH_CHECK(streq(r.host, "example.com"));
    ZUH_CHECK(streq(r.path_query, "/c"));
    /* §19.2 decides whether credentials survive; it works on the struct, so
     * resolution must not smuggle them through the text round-trip. */
    ZUH_CHECK(r.userinfo == NULL);
    zuh_uri_free(&r);
    zuh_uri_free(&base);

    ZUH_CASE("an IPv6 base survives the resolve round-trip");
    ZUH_CHECK_EQ_INT(P(&base, "https://[2001:db8::1]:8443/a/b"), ZUH_OK);
    ZUH_CHECK_EQ_INT(R(&r, &base, "../c"), ZUH_OK);
    ZUH_CHECK(streq(r.host, "2001:db8::1"));
    ZUH_CHECK_EQ_INT(r.port, 8443);
    ZUH_CHECK(streq(r.path_query, "/c"));
    zuh_uri_free(&r);
    zuh_uri_free(&base);

    /* ---- allocator integration ---- */

    ZUH_CASE("uriparser allocates through zu_alloc and leaks nothing on OOM");
    {
        zuh_alloc_stats before, after;
        long n;
        zuh_alloc_stats_get(&before);
        for (n = 0; n < 40; n++) {
            zuh_uri tmp;
            zuh_alloc_fail_after(n);
            if (P(&tmp, "https://user@example.com:8443/a/b?q=1") == ZUH_OK)
                zuh_uri_free(&tmp);
            zuh_alloc_fail_after(-1);
        }
        zuh_alloc_stats_get(&after);
        /* If the parser had used bare malloc, live_blocks would not move at
         * all and this test would be vacuous — so assert it DID allocate. */
        ZUH_CHECK(after.total_allocs > before.total_allocs);
        ZUH_CHECK_EQ_INT(after.live_blocks, before.live_blocks);
    }
}

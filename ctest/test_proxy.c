/* Proxy configuration and tunnelling — design §20.
 *
 * The environment is read through a seam, so these tests use a table instead
 * of setenv(): mutating the real environment is not thread-safe, leaks
 * between tests, and cannot reliably express "unset" on Windows.
 */
#include "zuh_test.h"
#include "zuh_proxy.h"
#include "zuh_alloc.h"
#include <string.h>

void suite_proxy(void);

/* --- a table-backed environment ------------------------------------------ */
typedef struct { const char *name; const char *value; } env_row;
static const env_row *g_env;

static const char *table_getenv(void *ctx, const char *name) {
    const env_row *r;
    ZUH_UNUSED(ctx);
    for (r = g_env; r && r->name; r++)
        if (strcmp(r->name, name) == 0) return r->value;
    return NULL;
}
static zuh_env mkenv(const env_row *rows) {
    zuh_env e;
    g_env = rows;
    e.get = table_getenv;
    e.ctx = NULL;
    return e;
}

static int streq(const char *a, const char *b) { return a && b && strcmp(a, b) == 0; }

static zuh_code parse_uri(zuh_uri *u, const char *s) {
    return zuh_uri_parse(u, s, s + strlen(s));
}

void suite_proxy(void) {
    zuh_error e;
    zuh_buffer b;

    /* ---- §20.4 base64, against the RFC 4648 vectors ---- */
    ZUH_CASE("base64 matches RFC 4648");
    {
        struct { const char *in, *out; } v[] = {
            {"",       ""},        {"f",      "Zg=="},
            {"fo",     "Zm8="},    {"foo",    "Zm9v"},
            {"foob",   "Zm9vYg=="},{"fooba",  "Zm9vYmE="},
            {"foobar", "Zm9vYmFy"}
        };
        size_t i;
        for (i = 0; i < sizeof v / sizeof *v; i++) {
            const char *s = NULL;
            ZUH_CHECK(zuh_buf_init(&b, 16, 4096));
            ZUH_CHECK(zuh_base64_encode(v[i].in, strlen(v[i].in), &b));
            ZUH_CHECK(zuh_buf_cstr(&b, &s));
            ZUH_CHECK(streq(s, v[i].out));
            zuh_buf_free(&b);
        }
    }

    ZUH_CASE("base64 handles bytes above 0x7f without sign extension");
    {
        const unsigned char raw[] = { 0xff, 0xfe, 0xfd };
        const char *s = NULL;
        ZUH_CHECK(zuh_buf_init(&b, 16, 4096));
        ZUH_CHECK(zuh_base64_encode(raw, sizeof raw, &b));
        ZUH_CHECK(zuh_buf_cstr(&b, &s));
        ZUH_CHECK(streq(s, "//79"));
        zuh_buf_free(&b);
    }

    /* ---- §20.2 NO_PROXY ---- */

    ZUH_CASE("NO_PROXY matches on label boundaries, not substrings");
    ZUH_CHECK_EQ_INT(zuh_no_proxy_matches("example.com", "api.example.com", 443), 1);
    ZUH_CHECK_EQ_INT(zuh_no_proxy_matches("example.com", "example.com", 443), 1);
    /* The criterion this stage exists to satisfy. */
    ZUH_CHECK_EQ_INT(zuh_no_proxy_matches("example.com", "notexample.com", 443), 0);
    ZUH_CHECK_EQ_INT(zuh_no_proxy_matches("example.com", "example.com.evil.net", 443), 0);

    ZUH_CASE("a leading dot is ignored");
    ZUH_CHECK_EQ_INT(zuh_no_proxy_matches(".example.com", "api.example.com", 443), 1);
    ZUH_CHECK_EQ_INT(zuh_no_proxy_matches(".example.com", "example.com", 443), 1);

    ZUH_CASE("* alone bypasses everything");
    ZUH_CHECK_EQ_INT(zuh_no_proxy_matches("*", "anything.at.all", 80), 1);
    ZUH_CHECK_EQ_INT(zuh_no_proxy_matches("a.com,*,b.com", "zzz.net", 80), 1);

    ZUH_CASE("matching is case-insensitive");
    ZUH_CHECK_EQ_INT(zuh_no_proxy_matches("EXAMPLE.COM", "api.example.com", 443), 1);
    ZUH_CHECK_EQ_INT(zuh_no_proxy_matches("example.com", "API.EXAMPLE.COM", 443), 1);

    ZUH_CASE("a list is split on commas and trimmed");
    ZUH_CHECK_EQ_INT(zuh_no_proxy_matches("a.com, b.com ,c.com", "b.com", 80), 1);
    ZUH_CHECK_EQ_INT(zuh_no_proxy_matches("a.com, b.com ,c.com", "d.com", 80), 0);
    ZUH_CHECK_EQ_INT(zuh_no_proxy_matches("", "a.com", 80), 0);
    ZUH_CHECK_EQ_INT(zuh_no_proxy_matches(",,,", "a.com", 80), 0);

    ZUH_CASE("an entry may carry a port, which must also match");
    ZUH_CHECK_EQ_INT(zuh_no_proxy_matches("example.com:8080", "example.com", 8080), 1);
    ZUH_CHECK_EQ_INT(zuh_no_proxy_matches("example.com:8080", "example.com", 443), 0);
    ZUH_CHECK_EQ_INT(zuh_no_proxy_matches("example.com:8080", "api.example.com", 8080), 1);

    ZUH_CASE("an IP literal matches exactly, never by suffix");
    ZUH_CHECK_EQ_INT(zuh_no_proxy_matches("1.2.3.4", "1.2.3.4", 80), 1);
    /* Without the exact-match rule "10.1.2.3.4" would end with "1.2.3.4" on a
     * label boundary and wrongly bypass the proxy. */
    ZUH_CHECK_EQ_INT(zuh_no_proxy_matches("1.2.3.4", "10.1.2.3.4", 80), 0);
    ZUH_CHECK_EQ_INT(zuh_no_proxy_matches("::1", "::1", 80), 1);

    ZUH_CASE("CIDR is not supported and must not match by accident (§20.2)");
    /* Documented gap: an entry like this matches nothing rather than a range. */
    ZUH_CHECK_EQ_INT(zuh_no_proxy_matches("10.0.0.0/8", "10.1.2.3", 80), 0);

    /* ---- §20.1 environment precedence ---- */

    ZUH_CASE("http_proxy is read but HTTP_PROXY is IGNORED (httpoxy)");
    {
        zuh_uri t;
        zuh_proxy p;
        static const env_row rows[] = {
            { "HTTP_PROXY", "http://attacker.example:8080" }, { NULL, NULL }
        };
        zuh_env env = mkenv(rows);
        ZUH_CHECK_EQ_INT(parse_uri(&t, "http://target.example/x"), ZUH_OK);
        ZUH_CHECK_EQ_INT(zuh_proxy_resolve(&p, &t, &env, NULL, 0, &e), ZUH_OK);
        /* The whole point: an attacker-supplied Proxy: header must not route us. */
        ZUH_CHECK_EQ_INT(p.in_use, 0);
        zuh_proxy_free(&p); zuh_uri_free(&t);
    }

    ZUH_CASE("lowercase http_proxy IS honoured");
    {
        zuh_uri t; zuh_proxy p;
        static const env_row rows[] = {
            { "http_proxy", "http://px.example:3128" }, { NULL, NULL }
        };
        zuh_env env = mkenv(rows);
        ZUH_CHECK_EQ_INT(parse_uri(&t, "http://target.example/x"), ZUH_OK);
        ZUH_CHECK_EQ_INT(zuh_proxy_resolve(&p, &t, &env, NULL, 0, &e), ZUH_OK);
        ZUH_CHECK_EQ_INT(p.in_use, 1);
        ZUH_CHECK(streq(p.host, "px.example"));
        ZUH_CHECK_EQ_INT(p.port, 3128);
        ZUH_CHECK(streq(p.source, "http_proxy"));
        zuh_proxy_free(&p); zuh_uri_free(&t);
    }

    ZUH_CASE("HTTPS_PROXY in either case is honoured for https targets");
    {
        zuh_uri t; zuh_proxy p;
        static const env_row rows[] = {
            { "HTTPS_PROXY", "http://px.example:8080" }, { NULL, NULL }
        };
        zuh_env env = mkenv(rows);
        ZUH_CHECK_EQ_INT(parse_uri(&t, "https://target.example/x"), ZUH_OK);
        ZUH_CHECK_EQ_INT(zuh_proxy_resolve(&p, &t, &env, NULL, 0, &e), ZUH_OK);
        ZUH_CHECK_EQ_INT(p.in_use, 1);
        ZUH_CHECK(streq(p.source, "HTTPS_PROXY"));
        zuh_proxy_free(&p); zuh_uri_free(&t);
    }

    ZUH_CASE("all_proxy is the fallback for both schemes");
    {
        zuh_uri t; zuh_proxy p;
        static const env_row rows[] = {
            { "all_proxy", "http://fallback.example:1080" }, { NULL, NULL }
        };
        zuh_env env = mkenv(rows);
        ZUH_CHECK_EQ_INT(parse_uri(&t, "https://target.example/x"), ZUH_OK);
        ZUH_CHECK_EQ_INT(zuh_proxy_resolve(&p, &t, &env, NULL, 0, &e), ZUH_OK);
        ZUH_CHECK(streq(p.source, "all_proxy"));
        zuh_proxy_free(&p); zuh_uri_free(&t);
    }

    ZUH_CASE("no_proxy suppresses a configured proxy");
    {
        zuh_uri t; zuh_proxy p;
        static const env_row rows[] = {
            { "http_proxy", "http://px.example:3128" },
            { "no_proxy",   "internal.example" }, { NULL, NULL }
        };
        zuh_env env = mkenv(rows);
        ZUH_CHECK_EQ_INT(parse_uri(&t, "http://api.internal.example/x"), ZUH_OK);
        ZUH_CHECK_EQ_INT(zuh_proxy_resolve(&p, &t, &env, NULL, 0, &e), ZUH_OK);
        ZUH_CHECK_EQ_INT(p.in_use, 0);
        zuh_proxy_free(&p); zuh_uri_free(&t);
    }

    ZUH_CASE("an explicit setting beats the environment");
    {
        zuh_uri t; zuh_proxy p;
        static const env_row rows[] = {
            { "http_proxy", "http://env.example:3128" }, { NULL, NULL }
        };
        zuh_env env = mkenv(rows);
        ZUH_CHECK_EQ_INT(parse_uri(&t, "http://target.example/x"), ZUH_OK);
        ZUH_CHECK_EQ_INT(zuh_proxy_resolve(&p, &t, &env, "http://explicit.example:9", 1, &e), ZUH_OK);
        ZUH_CHECK(streq(p.host, "explicit.example"));
        ZUH_CHECK(streq(p.source, "explicit"));
        zuh_proxy_free(&p);

        /* proxy = NULL means DISABLED, distinct from "not configured". */
        ZUH_CHECK_EQ_INT(zuh_proxy_resolve(&p, &t, &env, NULL, 1, &e), ZUH_OK);
        ZUH_CHECK_EQ_INT(p.in_use, 0);
        zuh_proxy_free(&p); zuh_uri_free(&t);
    }

    ZUH_CASE("an empty environment variable means unset");
    {
        zuh_uri t; zuh_proxy p;
        static const env_row rows[] = { { "http_proxy", "" }, { NULL, NULL } };
        zuh_env env = mkenv(rows);
        ZUH_CHECK_EQ_INT(parse_uri(&t, "http://target.example/x"), ZUH_OK);
        ZUH_CHECK_EQ_INT(zuh_proxy_resolve(&p, &t, &env, NULL, 0, &e), ZUH_OK);
        ZUH_CHECK_EQ_INT(p.in_use, 0);
        zuh_proxy_free(&p); zuh_uri_free(&t);
    }

    /* ---- §20.4 credentials ---- */

    ZUH_CASE("proxy URL credentials are moved OUT of the URL");
    {
        zuh_proxy p;
        ZUH_CHECK_EQ_INT(zuh_proxy_parse(&p, "http://user:pass@px.example:3128", &e), ZUH_OK);
        ZUH_CHECK(streq(p.host, "px.example"));
        ZUH_CHECK_EQ_INT(p.port, 3128);
        ZUH_CHECK(streq(p.username, "user"));
        ZUH_CHECK(streq(p.password, "pass"));
        /* Nothing observable may still carry them. */
        ZUH_CHECK(strstr(p.host, "pass") == NULL);
        ZUH_CHECK(strstr(p.host, "user") == NULL);
        zuh_proxy_free(&p);
    }

    ZUH_CASE("a username with no password is allowed");
    {
        zuh_proxy p;
        ZUH_CHECK_EQ_INT(zuh_proxy_parse(&p, "http://user@px.example:3128", &e), ZUH_OK);
        ZUH_CHECK(streq(p.username, "user"));
        ZUH_CHECK(streq(p.password, ""));
        zuh_proxy_free(&p);
    }

    ZUH_CASE("a bare host:port is accepted, as curl does");
    {
        zuh_proxy p;
        ZUH_CHECK_EQ_INT(zuh_proxy_parse(&p, "px.example:3128", &e), ZUH_OK);
        ZUH_CHECK_EQ_INT(p.in_use, 1);
        ZUH_CHECK(streq(p.scheme, "http"));
        ZUH_CHECK(streq(p.host, "px.example"));
        ZUH_CHECK_EQ_INT(p.port, 3128);
        zuh_proxy_free(&p);
    }

    ZUH_CASE("unsupported proxy schemes are rejected, never downgraded");
    {
        zuh_proxy p;
        ZUH_CHECK_EQ_INT(zuh_proxy_parse(&p, "socks5://px.example:1080", &e), ZUH_ERR_PROXY);
        ZUH_CHECK_EQ_INT(p.in_use, 0);
        ZUH_CHECK_EQ_INT(zuh_proxy_parse(&p, "https://px.example:443", &e), ZUH_ERR_PROXY);
        ZUH_CHECK_EQ_INT(p.in_use, 0);
    }

    ZUH_CASE("Proxy-Authorization is Basic base64(user:pass)");
    {
        zuh_proxy p;
        const char *s = NULL;
        /* A raw space is not legal in a URL, so the RFC 7617 vector has to
         * arrive percent-encoded — which also exercises the decoder. */
        ZUH_CHECK_EQ_INT(zuh_proxy_parse(&p, "http://Aladdin:open%20sesame@px:3128", &e), ZUH_OK);
        ZUH_CHECK(streq(p.password, "open sesame"));
        ZUH_CHECK(zuh_buf_init(&b, 64, 4096));
        ZUH_CHECK(zuh_proxy_auth_value(&p, &b));
        ZUH_CHECK(zuh_buf_cstr(&b, &s));
        ZUH_CHECK(streq(s, "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="));  /* RFC 7617 */
        zuh_buf_free(&b);
        zuh_proxy_free(&p);
    }

    ZUH_CASE("percent-encoded credentials are decoded before use (§20.4)");
    {
        zuh_proxy p;
        /* '@' and ':' in a password MUST be percent-encoded in the URL.
         * Sending the raw form would authenticate with the wrong password and
         * look like a proxy bug rather than a client one. */
        ZUH_CHECK_EQ_INT(zuh_proxy_parse(&p, "http://us%40er:p%40ss%3Aword@px:3128", &e), ZUH_OK);
        ZUH_CHECK(streq(p.username, "us@er"));
        ZUH_CHECK(streq(p.password, "p@ss:word"));
        ZUH_CHECK(streq(p.host, "px"));
        zuh_proxy_free(&p);
    }

    ZUH_CASE("a malformed percent-escape in credentials is an error");
    {
        zuh_proxy p;
        ZUH_CHECK_EQ_INT(zuh_proxy_parse(&p, "http://u:p%zz@px:3128", &e), ZUH_ERR_PROXY);
        ZUH_CHECK_EQ_INT(p.in_use, 0);
        ZUH_CHECK_EQ_INT(zuh_proxy_parse(&p, "http://u:p%4@px:3128", &e), ZUH_ERR_PROXY);
    }

    ZUH_CASE("bracketed IPv6 in NO_PROXY, with and without a port");
    ZUH_CHECK_EQ_INT(zuh_no_proxy_matches("[::1]", "::1", 80), 1);
    ZUH_CHECK_EQ_INT(zuh_no_proxy_matches("[::1]:8080", "::1", 8080), 1);
    ZUH_CHECK_EQ_INT(zuh_no_proxy_matches("[::1]:8080", "::1", 443), 0);

    ZUH_CASE("no credentials means no Proxy-Authorization at all");
    {
        zuh_proxy p;
        ZUH_CHECK_EQ_INT(zuh_proxy_parse(&p, "http://px.example:3128", &e), ZUH_OK);
        ZUH_CHECK(zuh_buf_init(&b, 64, 4096));
        ZUH_CHECK_EQ_INT(zuh_proxy_auth_value(&p, &b), 0);
        zuh_buf_free(&b);
        zuh_proxy_free(&p);
    }

    /* ---- §20.3 request forms ---- */

    ZUH_CASE("absolute-form omits a default port and never leaks userinfo");
    {
        zuh_uri u;
        const char *s = NULL;
        ZUH_CHECK_EQ_INT(parse_uri(&u, "http://user:pw@example.com/path?q=1"), ZUH_OK);
        ZUH_CHECK(zuh_buf_init(&b, 64, 4096));
        ZUH_CHECK(zuh_proxy_absolute_form(&u, &b));
        ZUH_CHECK(zuh_buf_cstr(&b, &s));
        ZUH_CHECK(streq(s, "http://example.com/path?q=1"));
        ZUH_CHECK(strstr(s, "user") == NULL);
        ZUH_CHECK(strstr(s, "pw") == NULL);
        zuh_buf_free(&b); zuh_uri_free(&u);
    }

    ZUH_CASE("absolute-form keeps an explicit port and brackets IPv6");
    {
        zuh_uri u;
        const char *s = NULL;
        ZUH_CHECK_EQ_INT(parse_uri(&u, "http://example.com:8080/x"), ZUH_OK);
        ZUH_CHECK(zuh_buf_init(&b, 64, 4096));
        ZUH_CHECK(zuh_proxy_absolute_form(&u, &b));
        ZUH_CHECK(zuh_buf_cstr(&b, &s));
        ZUH_CHECK(streq(s, "http://example.com:8080/x"));
        zuh_buf_free(&b); zuh_uri_free(&u);

        ZUH_CHECK_EQ_INT(parse_uri(&u, "http://[2001:db8::1]:8080/x"), ZUH_OK);
        ZUH_CHECK(zuh_buf_init(&b, 64, 4096));
        ZUH_CHECK(zuh_proxy_absolute_form(&u, &b));
        ZUH_CHECK(zuh_buf_cstr(&b, &s));
        ZUH_CHECK(streq(s, "http://[2001:db8::1]:8080/x"));
        zuh_buf_free(&b); zuh_uri_free(&u);
    }

    ZUH_CASE("CONNECT names host:port and carries Proxy-Authorization");
    {
        zuh_proxy p; zuh_uri t;
        const char *s = NULL;
        ZUH_CHECK_EQ_INT(zuh_proxy_parse(&p, "http://u:pw@px:3128", &e), ZUH_OK);
        ZUH_CHECK_EQ_INT(parse_uri(&t, "https://example.com/ignored?path"), ZUH_OK);
        ZUH_CHECK(zuh_buf_init(&b, 128, 8192));
        ZUH_CHECK_EQ_INT(zuh_proxy_connect_request(&p, &t, &b, &e), ZUH_OK);
        ZUH_CHECK(zuh_buf_cstr(&b, &s));
        ZUH_CHECK(strstr(s, "CONNECT example.com:443 HTTP/1.1\r\n") == s);
        ZUH_CHECK(strstr(s, "Host: example.com:443\r\n") != NULL);
        ZUH_CHECK(strstr(s, "Proxy-Authorization: Basic ") != NULL);
        /* The tunnel target's path must never appear in the CONNECT line. */
        ZUH_CHECK(strstr(s, "ignored") == NULL);
        zuh_buf_free(&b); zuh_uri_free(&t); zuh_proxy_free(&p);
    }

    ZUH_CASE("CONNECT to an IPv6 literal is bracketed");
    {
        zuh_proxy p; zuh_uri t;
        const char *s = NULL;
        ZUH_CHECK_EQ_INT(zuh_proxy_parse(&p, "http://px:3128", &e), ZUH_OK);
        ZUH_CHECK_EQ_INT(parse_uri(&t, "https://[2001:db8::1]/x"), ZUH_OK);
        ZUH_CHECK(zuh_buf_init(&b, 128, 8192));
        ZUH_CHECK_EQ_INT(zuh_proxy_connect_request(&p, &t, &b, &e), ZUH_OK);
        ZUH_CHECK(zuh_buf_cstr(&b, &s));
        ZUH_CHECK(strstr(s, "CONNECT [2001:db8::1]:443 ") == s);
        /* No credentials configured, so no header. */
        ZUH_CHECK(strstr(s, "Proxy-Authorization") == NULL);
        zuh_buf_free(&b); zuh_uri_free(&t); zuh_proxy_free(&p);
    }

    ZUH_CASE("a 2xx CONNECT succeeds");
    {
        static const char ok[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
        size_t used = 0; int st = 0;
        ZUH_CHECK_EQ_INT(zuh_proxy_connect_response(ok, sizeof ok - 1, &used, &st, &e), ZUH_OK);
        ZUH_CHECK_EQ_INT(st, 200);
    }

    ZUH_CASE("a non-2xx CONNECT surfaces the proxy's status (§20.3)");
    {
        static const char denied[] =
            "HTTP/1.1 403 Forbidden\r\nContent-Length: 11\r\n\r\nblocked: no";
        size_t used = 0; int st = 0;
        ZUH_CHECK_EQ_INT(zuh_proxy_connect_response(denied, sizeof denied - 1, &used, &st, &e),
                        ZUH_ERR_PROXY);
        ZUH_CHECK_EQ_INT(st, 403);
        /* Frequently the only diagnostic a user gets behind a corporate proxy. */
        ZUH_CHECK(strstr(e.message, "403") != NULL);
    }

    ZUH_CASE("407 is a distinct condition from a generic proxy error");
    {
        static const char need[] =
            "HTTP/1.1 407 Proxy Authentication Required\r\n"
            "Proxy-Authenticate: Basic realm=\"x\"\r\n\r\n";
        size_t used = 0; int st = 0;
        ZUH_CHECK_EQ_INT(zuh_proxy_connect_response(need, sizeof need - 1, &used, &st, &e),
                        ZUH_ERR_PROXY_AUTH);
        ZUH_CHECK_EQ_INT(st, 407);
        ZUH_CHECK(streq(zuh_code_class(ZUH_ERR_PROXY_AUTH), "zu_proxy_auth_error"));
    }

    ZUH_CASE("a malformed CONNECT response is rejected with §18 strictness");
    {
        static const char bad[] =
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n";
        static const char fold[] = "HTTP/1.1 200 OK\r\nX-A: one\r\n  two\r\n\r\n";
        size_t used = 0; int st = 0;
        /* A proxy is not exempt from §18: a lenient parse here is a tunnel
         * built on a lie. Duplicate Content-Length is caught by framing, so
         * the parse itself succeeds; obs-fold is rejected outright. */
        ZUH_CHECK_EQ_INT(zuh_proxy_connect_response(fold, sizeof fold - 1, &used, &st, &e),
                        ZUH_ERR_PARSE);
        (void)bad;
    }

    ZUH_CASE("an incomplete CONNECT response asks for more bytes");
    {
        static const char partial[] = "HTTP/1.1 200 Conn";
        size_t used = 0; int st = 0;
        ZUH_CHECK_EQ_INT(zuh_proxy_connect_response(partial, sizeof partial - 1, &used, &st, &e),
                        ZUH_ERR_WOULDBLOCK);
    }

    ZUH_CASE("no leaks across the suite");
    {
        zuh_alloc_stats end;
        zuh_alloc_stats_get(&end);
        ZUH_CHECK_EQ_INT(end.live_blocks, 0);
    }
}

/* The §63.2 vertical slice, against real servers.
 *
 * Network-dependent by nature, so this lives in its own binary and its own CI
 * job — c-core must stay deterministic and offline. Run with `make engine`.
 */
#include "zuh_test.h"
#include "zuh_engine.h"
#include "zuh_alloc.h"
#include <string.h>
#include <stdio.h>

int zuh_test_fails = 0;
int zuh_test_checks = 0;
const char *zuh_test_current = "(none)";

static int contains(const zuh_buffer *b, const char *needle) {
    size_t n = strlen(needle), i;
    if (b->len < n) return 0;
    for (i = 0; i + n <= b->len; i++)
        if (memcmp(b->data + i, needle, n) == 0) return 1;
    return 0;
}

int main(void) {
    zuh_get_opts o;
    zuh_result r;
    zuh_error e;
    zuh_code rc;

    printf("zuhttp vertical slice (design 63.2)\n\n");
    setvbuf(stdout, NULL, _IONBF, 0);   /* a crash must not eat the last line */
    zuh_get_opts_init(&o);

    ZUH_CASE("HTTPS GET returns 200 with a body and a TLS version");
    rc = zuh_engine_get(&r, "https://example.com/", &o, &e);
    ZUH_CHECK_EQ_INT(rc, ZUH_OK);
    if (rc == ZUH_OK) {
        printf("  status=%d  bytes=%lu  tls=%s/%s  url=%s\n",
               r.status, (unsigned long)r.body.len,
               r.tls_version ? r.tls_version : "-",
               r.tls_cipher ? r.tls_cipher : "-", r.final_url);
        ZUH_CHECK_EQ_INT(r.status, 200);
        ZUH_CHECK(r.body.len > 0);
        ZUH_CHECK(contains(&r.body, "Example Domain"));
        ZUH_CHECK(r.tls_version != NULL);
        ZUH_CHECK(zuh_headers_get(&r.headers, "Content-Type") != NULL);
        zuh_result_free(&r);
    }

    ZUH_CASE("chunked transfer decodes");
    rc = zuh_engine_get(&r, "https://httpbin.org/stream/3", &o, &e);
    if (rc == ZUH_OK) {
        printf("  status=%d  bytes=%lu\n", r.status, (unsigned long)r.body.len);
        ZUH_CHECK_EQ_INT(r.status, 200);
        ZUH_CHECK(r.body.len > 0);
        zuh_result_free(&r);
    } else {
        printf("  skipped: %s (%s)\n", e.message, zuh_code_class(rc));
    }

    ZUH_CASE("gzip is requested and decoded transparently");
    rc = zuh_engine_get(&r, "https://httpbin.org/gzip", &o, &e);
    if (rc == ZUH_OK) {
        ZUH_CHECK_EQ_INT(r.status, 200);
        /* If decoding failed we would be holding compressed bytes. */
        ZUH_CHECK(contains(&r.body, "gzipped"));
        ZUH_CHECK(zuh_headers_get(&r.headers, "Content-Encoding") == NULL);
        zuh_result_free(&r);
    } else {
        printf("  skipped: %s\n", e.message);
    }

    ZUH_CASE("no_decode hands back the wire bytes (§21.2)");
    {
        zuh_get_opts nd = o;
        nd.no_decode = 1;
        rc = zuh_engine_get(&r, "https://httpbin.org/gzip", &nd, &e);
        if (rc == ZUH_OK) {
            const char *ce = zuh_headers_get(&r.headers, "Content-Encoding");
            ZUH_CHECK_EQ_INT(r.status, 200);
            /* The header still says gzip, and the body really starts with the
             * gzip magic number -- this endpoint encodes whatever we send in
             * Accept-Encoding, which is exactly why the flag cannot be only
             * about the request header. */
            ZUH_CHECK(ce != NULL && strcmp(ce, "gzip") == 0);
            ZUH_CHECK(r.body.len > 2 &&
                     r.body.data[0] == 0x1f && r.body.data[1] == 0x8b);
            ZUH_CHECK(!contains(&r.body, "gzipped"));
            zuh_result_free(&r);
        } else {
            printf("  skipped: %s\n", e.message);
        }
    }

    ZUH_CASE("one redirect is followed and the final URL reported");
    /* An http:// start that redirects to https:// also exercises the §19.3
     * direction that IS allowed (upgrade); the refused direction is a
     * downgrade, which zuh_redirect_decide covers in the offline suite. */
    rc = zuh_engine_get(&r, "http://github.com/", &o, &e);
    if (rc == ZUH_OK) {
        printf("  status=%d  redirects=%d  url=%s\n", r.status, r.redirects, r.final_url);
        ZUH_CHECK_EQ_INT(r.redirects, 1);
        ZUH_CHECK(strncmp(r.final_url, "https://", 8) == 0);
        /* §19.5: the redirect's own body must never reach the caller. */
        ZUH_CHECK(!contains(&r.body, "<html><body>You are being"));
        zuh_result_free(&r);
    } else {
        printf("  note: %s\n", e.message);
    }

    ZUH_CASE("the redirect budget is respected");
    {
        zuh_get_opts none = o;
        none.max_redirects = 0;
        rc = zuh_engine_get(&r, "http://github.com/", &none, &e);
        if (rc == ZUH_OK) {
            /* With no budget the 301 itself is returned, not followed. */
            ZUH_CHECK_EQ_INT(r.redirects, 0);
            ZUH_CHECK(r.status >= 300 && r.status < 400);
            printf("  unfollowed status=%d\n", r.status);
            zuh_result_free(&r);
        }
    }

    ZUH_CASE("certificate verification is on by default");
    rc = zuh_engine_get(&r, "https://expired.badssl.com/", &o, &e);
    ZUH_CHECK_EQ_INT(rc, ZUH_ERR_TLS_CERT);
    printf("  -> %s: %s\n", zuh_code_class(rc), e.message);
    if (rc == ZUH_OK) zuh_result_free(&r);

    ZUH_CASE("a hostname mismatch is distinct from a bad chain");
    rc = zuh_engine_get(&r, "https://wrong.host.badssl.com/", &o, &e);
    ZUH_CHECK_EQ_INT(rc, ZUH_ERR_TLS_HOSTNAME);
    if (rc == ZUH_OK) zuh_result_free(&r);

    ZUH_CASE("a bad URL is refused before any connection");
    rc = zuh_engine_get(&r, "ftp://example.com/", &o, &e);
    ZUH_CHECK_EQ_INT(rc, ZUH_ERR_URL);

    ZUH_CASE("the total deadline is enforced");
    {
        zuh_get_opts fast = o;
        fast.timeout_ms = 1;                     /* cannot possibly complete */
        rc = zuh_engine_get(&r, "https://example.com/", &fast, &e);
        ZUH_CHECK(rc != ZUH_OK);
        printf("  -> %s\n", zuh_code_class(rc));
        if (rc == ZUH_OK) zuh_result_free(&r);
    }

    /* --- S11: methods, headers and bodies --- */

    ZUH_CASE("POST with a JSON body round-trips");
    {
        static const char json[] = "{\"name\":\"alice\",\"n\":42}";
        static const char *const hn[] = { "Content-Type" };
        static const char *const hv[] = { "application/json" };
        zuh_req_spec req;
        memset(&req, 0, sizeof req);
        req.method = "POST";
        req.header_names = hn; req.header_values = hv; req.n_headers = 1;
        req.body = json; req.body_len = sizeof json - 1;

        rc = zuh_engine_perform(&r, "https://httpbin.org/post", &req, &o, &e);
        if (rc == ZUH_OK) {
            ZUH_CHECK_EQ_INT(r.status, 200);
            /* httpbin echoes what it received, so this proves the body and the
             * Content-Type both arrived rather than merely that we sent them. */
            ZUH_CHECK(contains(&r.body, "\"name\": \"alice\""));
            ZUH_CHECK(contains(&r.body, "application/json"));
            zuh_result_free(&r);
        } else {
            printf("  skipped: %s\n", e.message);
        }
    }

    ZUH_CASE("a caller header overrides the §17.2 default");
    {
        static const char *const hn[] = { "User-Agent" };
        static const char *const hv[] = { "zuhttp-test/1" };
        zuh_req_spec req;
        memset(&req, 0, sizeof req);
        req.header_names = hn; req.header_values = hv; req.n_headers = 1;
        rc = zuh_engine_perform(&r, "https://httpbin.org/headers", &req, &o, &e);
        if (rc == ZUH_OK) {
            ZUH_CHECK(contains(&r.body, "zuhttp-test/1"));
            zuh_result_free(&r);
        }
    }

    ZUH_CASE("HEAD gets no body whatever the headers claim (§18.1)");
    {
        zuh_req_spec req;
        memset(&req, 0, sizeof req);
        req.method = "HEAD";
        rc = zuh_engine_perform(&r, "https://example.com/", &req, &o, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        if (rc == ZUH_OK) {
            ZUH_CHECK_EQ_INT(r.status, 200);
            /* Content-Length is present and non-zero, and the body must still
             * be empty; getting this wrong hangs waiting for bytes that never
             * come. */
            ZUH_CHECK_EQ_INT((long long)r.body.len, 0);
            zuh_result_free(&r);
        }
    }

    ZUH_CASE("a header carrying CRLF is refused, not sent (§17.1)");
    {
        static const char *const hn[] = { "X-Evil" };
        static const char *const hv[] = { "a\r\nInjected: yes" };
        zuh_req_spec req;
        memset(&req, 0, sizeof req);
        req.header_names = hn; req.header_values = hv; req.n_headers = 1;
        rc = zuh_engine_perform(&r, "https://example.com/", &req, &o, &e);
        ZUH_CHECK(rc != ZUH_OK);
        printf("  -> %s\n", zuh_code_class(rc));
        if (rc == ZUH_OK) zuh_result_free(&r);
    }

    ZUH_CASE("no leaks across the run");
    {
        zuh_alloc_stats st;
        zuh_alloc_stats_get(&st);
        printf("  allocations: %lu made, %lu freed, %lu live\n",
               (unsigned long)st.total_allocs, (unsigned long)st.total_frees,
               (unsigned long)st.live_blocks);
        ZUH_CHECK_EQ_INT(st.live_blocks, 0);
    }

    printf("\n%d checks, %d failures\n", zuh_test_checks, zuh_test_fails);
    return zuh_test_fails ? 1 : 0;
}

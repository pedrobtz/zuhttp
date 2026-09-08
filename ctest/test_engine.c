/* The §63.2 vertical slice, against real servers.
 *
 * Network-dependent by nature, so this lives in its own binary and its own CI
 * job — c-core must stay deterministic and offline. Run with `make engine`.
 */
#include "zu_test.h"
#include "zu_engine.h"
#include "zu_alloc.h"
#include <string.h>
#include <stdio.h>

int zu_test_fails = 0;
int zu_test_checks = 0;
const char *zu_test_current = "(none)";

static int contains(const zu_buffer *b, const char *needle) {
    size_t n = strlen(needle), i;
    if (b->len < n) return 0;
    for (i = 0; i + n <= b->len; i++)
        if (memcmp(b->data + i, needle, n) == 0) return 1;
    return 0;
}

int main(void) {
    zu_get_opts o;
    zu_result r;
    zu_error e;
    zu_code rc;

    printf("zuhttp vertical slice (design 63.2)\n\n");
    setvbuf(stdout, NULL, _IONBF, 0);   /* a crash must not eat the last line */
    zu_get_opts_init(&o);

    ZU_CASE("HTTPS GET returns 200 with a body and a TLS version");
    rc = zu_engine_get(&r, "https://example.com/", &o, &e);
    ZU_CHECK_EQ_INT(rc, ZU_OK);
    if (rc == ZU_OK) {
        printf("  status=%d  bytes=%lu  tls=%s/%s  url=%s\n",
               r.status, (unsigned long)r.body.len,
               r.tls_version ? r.tls_version : "-",
               r.tls_cipher ? r.tls_cipher : "-", r.final_url);
        ZU_CHECK_EQ_INT(r.status, 200);
        ZU_CHECK(r.body.len > 0);
        ZU_CHECK(contains(&r.body, "Example Domain"));
        ZU_CHECK(r.tls_version != NULL);
        ZU_CHECK(zu_headers_get(&r.headers, "Content-Type") != NULL);
        zu_result_free(&r);
    }

    ZU_CASE("chunked transfer decodes");
    rc = zu_engine_get(&r, "https://httpbin.org/stream/3", &o, &e);
    if (rc == ZU_OK) {
        printf("  status=%d  bytes=%lu\n", r.status, (unsigned long)r.body.len);
        ZU_CHECK_EQ_INT(r.status, 200);
        ZU_CHECK(r.body.len > 0);
        zu_result_free(&r);
    } else {
        printf("  skipped: %s (%s)\n", e.message, zu_code_class(rc));
    }

    ZU_CASE("gzip is requested and decoded transparently");
    rc = zu_engine_get(&r, "https://httpbin.org/gzip", &o, &e);
    if (rc == ZU_OK) {
        ZU_CHECK_EQ_INT(r.status, 200);
        /* If decoding failed we would be holding compressed bytes. */
        ZU_CHECK(contains(&r.body, "gzipped"));
        ZU_CHECK(zu_headers_get(&r.headers, "Content-Encoding") == NULL);
        zu_result_free(&r);
    } else {
        printf("  skipped: %s\n", e.message);
    }

    ZU_CASE("one redirect is followed and the final URL reported");
    /* An http:// start that redirects to https:// also exercises the §19.3
     * direction that IS allowed (upgrade); the refused direction is a
     * downgrade, which zu_redirect_decide covers in the offline suite. */
    rc = zu_engine_get(&r, "http://github.com/", &o, &e);
    if (rc == ZU_OK) {
        printf("  status=%d  redirects=%d  url=%s\n", r.status, r.redirects, r.final_url);
        ZU_CHECK_EQ_INT(r.redirects, 1);
        ZU_CHECK(strncmp(r.final_url, "https://", 8) == 0);
        /* §19.5: the redirect's own body must never reach the caller. */
        ZU_CHECK(!contains(&r.body, "<html><body>You are being"));
        zu_result_free(&r);
    } else {
        printf("  note: %s\n", e.message);
    }

    ZU_CASE("the redirect budget is respected");
    {
        zu_get_opts none = o;
        none.max_redirects = 0;
        rc = zu_engine_get(&r, "http://github.com/", &none, &e);
        if (rc == ZU_OK) {
            /* With no budget the 301 itself is returned, not followed. */
            ZU_CHECK_EQ_INT(r.redirects, 0);
            ZU_CHECK(r.status >= 300 && r.status < 400);
            printf("  unfollowed status=%d\n", r.status);
            zu_result_free(&r);
        }
    }

    ZU_CASE("certificate verification is on by default");
    rc = zu_engine_get(&r, "https://expired.badssl.com/", &o, &e);
    ZU_CHECK_EQ_INT(rc, ZU_ERR_TLS_CERT);
    printf("  -> %s: %s\n", zu_code_class(rc), e.message);
    if (rc == ZU_OK) zu_result_free(&r);

    ZU_CASE("a hostname mismatch is distinct from a bad chain");
    rc = zu_engine_get(&r, "https://wrong.host.badssl.com/", &o, &e);
    ZU_CHECK_EQ_INT(rc, ZU_ERR_TLS_HOSTNAME);
    if (rc == ZU_OK) zu_result_free(&r);

    ZU_CASE("a bad URL is refused before any connection");
    rc = zu_engine_get(&r, "ftp://example.com/", &o, &e);
    ZU_CHECK_EQ_INT(rc, ZU_ERR_URL);

    ZU_CASE("the total deadline is enforced");
    {
        zu_get_opts fast = o;
        fast.timeout_ms = 1;                     /* cannot possibly complete */
        rc = zu_engine_get(&r, "https://example.com/", &fast, &e);
        ZU_CHECK(rc != ZU_OK);
        printf("  -> %s\n", zu_code_class(rc));
        if (rc == ZU_OK) zu_result_free(&r);
    }

    ZU_CASE("no leaks across the run");
    {
        zu_alloc_stats st;
        zu_alloc_stats_get(&st);
        printf("  allocations: %lu made, %lu freed, %lu live\n",
               (unsigned long)st.total_allocs, (unsigned long)st.total_frees,
               (unsigned long)st.live_blocks);
        ZU_CHECK_EQ_INT(st.live_blocks, 0);
    }

    printf("\n%d checks, %d failures\n", zu_test_checks, zu_test_fails);
    return zu_test_fails ? 1 : 0;
}

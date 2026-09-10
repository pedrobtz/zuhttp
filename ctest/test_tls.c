/* zuhttp — TLS engine tests (roadmap S7).
 *
 * SEPARATE from the c-core suite on purpose: these require a real TLS peer and
 * therefore the network, and c-core must stay deterministic and offline.
 * Built as its own binary and run by the tls-spike workflow.
 *
 * The endpoints are the same ones the S0 spike used, so a regression here is
 * directly comparable to the spike's recorded results.
 */
#if !defined(_WIN32)
#  if defined(__APPLE__)
#    define _DARWIN_C_SOURCE
#  else
#    define _POSIX_C_SOURCE 200112L
#  endif
#endif

#include "zu_test.h"
#include "zu_net.h"
#include "zu_tls.h"
#include "zu_alloc.h"
#include <stdio.h>
#include <string.h>

int zu_test_fails = 0;
int zu_test_checks = 0;
const char *zu_test_current = "(none)";

/* Connect TCP + TLS to host:443. Returns the code from whichever stage failed. */
static zu_code dial(const char *host, const zu_tls_config *cfg,
                    zu_stream **out, zu_tls_info *info, zu_error *err) {
    zu_net_opts o;
    zu_stream *tcp = NULL, *tls = NULL;
    zu_deadline d = zu_deadline_in(15000);
    zu_code rc;

    *out = NULL;
    zu_net_opts_init(&o);
    zu_error_clear(err);

    rc = zu_net_connect(&tcp, host, 443, d, &o, err);
    if (rc != ZU_OK) return rc;

    rc = zu_tls_connect(&tls, tcp, host, cfg, d, err);
    if (rc != ZU_OK) {
        /* On failure the TLS layer must NOT have taken ownership. */
        zu_net_stream_free(tcp);
        return rc;
    }
    if (info) zu_tls_get_info(tls, info);
    *out = tls;
    return ZU_OK;
}

int main(void) {
    zu_tls_config cfg;
    zu_error e;
    zu_stream *s = NULL;
    zu_tls_info info;
    zu_alloc_stats st;

    printf("zuhttp TLS engine tests (S7, backend: %s)\n\n", zu_tls_backend_name());

    ZU_CASE("defaults are secure (§14.1)");
    zu_tls_config_init(&cfg);
    ZU_CHECK_EQ_INT(cfg.verify_peer, 1);
    ZU_CHECK_EQ_INT(cfg.verify_hostname, 1);
    ZU_CHECK_EQ_INT(cfg.revocation, 0);          /* §14.5 / S0 F-4 */
    ZU_CHECK_EQ_INT(cfg.source, ZU_TRUST_SYSTEM);

    ZU_CASE("a good host completes a handshake and reports its protocol");
    zu_tls_config_init(&cfg);
    memset(&info, 0, sizeof info);
    if (dial("example.com", &cfg, &s, &info, &e) == ZU_OK) {
        printf("       negotiated %s / %s\n", info.protocol, info.cipher);
        ZU_CHECK(strncmp(info.protocol, "TLSv1.", 6) == 0);
        ZU_CHECK(info.cipher[0] != '\0');

        ZU_CASE("a real request round-trips over TLS");
        {
            zu_deadline d = zu_deadline_in(15000);
            const char *req = "HEAD / HTTP/1.1\r\nHost: example.com\r\n"
                              "Connection: close\r\n\r\n";
            char buf[256];
            zu_ssize n;
            zu_error_clear(&e);
            ZU_CHECK(zu_stream_write_all(s, req, strlen(req), d, &e));
            n = zu_stream_read(s, buf, sizeof buf - 1, d, &e);
            ZU_CHECK(n > 0);
            if (n > 0) { buf[n] = '\0'; ZU_CHECK(strncmp(buf, "HTTP/1.1 ", 9) == 0); }
        }
        zu_tls_stream_free(s); s = NULL;
    } else {
        printf("       SKIP: no network (%s)\n", e.message);
    }

    /* S0 finding F-3: without SSL_VERIFY_PEER every one of these would
     * SUCCEED while reporting the certificate as untrusted. */
    ZU_CASE("§14.6: an expired certificate is rejected as zu_tls_certificate_error");
    zu_tls_config_init(&cfg);
    if (dial("expired.badssl.com", &cfg, &s, NULL, &e) != ZU_OK) {
        ZU_CHECK_EQ_INT(e.code, ZU_ERR_TLS_CERT);
        printf("       %s\n", e.message);
    } else { ZU_CHECK(0); zu_tls_stream_free(s); s = NULL; }

    ZU_CASE("§14.6: a hostname mismatch is zu_tls_hostname_error, distinctly");
    zu_tls_config_init(&cfg);
    if (dial("wrong.host.badssl.com", &cfg, &s, NULL, &e) != ZU_OK) {
        ZU_CHECK_EQ_INT(e.code, ZU_ERR_TLS_HOSTNAME);
        printf("       %s\n", e.message);
    } else { ZU_CHECK(0); zu_tls_stream_free(s); s = NULL; }

    ZU_CASE("§14.6: an untrusted root is zu_tls_certificate_error");
    zu_tls_config_init(&cfg);
    if (dial("untrusted-root.badssl.com", &cfg, &s, NULL, &e) != ZU_OK) {
        ZU_CHECK_EQ_INT(e.code, ZU_ERR_TLS_CERT);
        printf("       %s\n", e.message);
    } else { ZU_CHECK(0); zu_tls_stream_free(s); s = NULL; }

    ZU_CASE("§14.6: a self-signed certificate is rejected");
    zu_tls_config_init(&cfg);
    if (dial("self-signed.badssl.com", &cfg, &s, NULL, &e) != ZU_OK) {
        ZU_CHECK_EQ_INT(e.code, ZU_ERR_TLS_CERT);
    } else { ZU_CHECK(0); zu_tls_stream_free(s); s = NULL; }

    ZU_CASE("§14.4: a wrong pin is refused even though the chain is valid");
    zu_tls_config_init(&cfg);
    {
        static const char *pins[] = { "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" };
        cfg.pins = pins;
        cfg.n_pins = 1;
        if (dial("example.com", &cfg, &s, NULL, &e) != ZU_OK) {
            ZU_CHECK_EQ_INT(e.code, ZU_ERR_TLS_PIN);
            printf("       %s\n", e.message);
        } else {
            ZU_CHECK(0);   /* a bad pin must never connect */
            zu_tls_stream_free(s); s = NULL;
        }
    }

    ZU_CASE("§14.2: ca_file REPLACES system trust, so a public host fails");
    zu_tls_config_init(&cfg);
    cfg.source = ZU_TRUST_DATA;
    cfg.ca_data = "-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----\n";
    cfg.ca_data_len = strlen((const char *)cfg.ca_data);
    if (dial("example.com", &cfg, &s, NULL, &e) != ZU_OK) {
        ZU_CHECK(e.code == ZU_ERR_TLS || e.code == ZU_ERR_TLS_CERT);
    } else { ZU_CHECK(0); zu_tls_stream_free(s); s = NULL; }

    ZU_CASE("a failed handshake leaves no leaked allocation");
    zu_alloc_stats_get(&st);
    ZU_CHECK_EQ_INT(st.live_blocks, 0);

    printf("\n%d checks, %d failures\n", zu_test_checks, zu_test_fails);
    printf("allocations: %lu made, %lu freed, %lu live\n",
           (unsigned long)st.total_allocs, (unsigned long)st.total_frees,
           (unsigned long)st.live_blocks);
    return zu_test_fails == 0 ? 0 : 1;
}

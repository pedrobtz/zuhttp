/* zuhttp — TLS engine tests (roadmap S7).
 *
 * SEPARATE from the c-core suite on purpose: these require a real TLS peer and
 * therefore the network, and c-core must stay deterministic and offline.
 * Built as its own binary and run by the network workflow.
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

#include "zuh_test.h"
#include "zuh_net.h"
#include "zuh_tls.h"
#include "zuh_alloc.h"
#include <stdio.h>
#include <string.h>

int zuh_test_fails = 0;
int zuh_test_checks = 0;
const char *zuh_test_current = "(none)";

/* Connect TCP + TLS to host:443. Returns the code from whichever stage failed. */
static zuh_code dial_once(const char *host, const zuh_tls_config *cfg,
                         zuh_stream **out, zuh_tls_info *info, zuh_error *err) {
    zuh_net_opts o;
    zuh_stream *tcp = NULL, *tls = NULL;
    zuh_deadline d = zuh_deadline_in(15000);
    zuh_code rc;

    *out = NULL;
    zuh_net_opts_init(&o);
    zuh_error_clear(err);

    rc = zuh_net_connect(&tcp, host, 443, d, &o, err);
    if (rc != ZUH_OK) return rc;

    rc = zuh_tls_connect(&tls, tcp, host, cfg, d, err);
    if (rc != ZUH_OK) {
        /* On failure the TLS layer must NOT have taken ownership. */
        zuh_net_stream_free(tcp);
        return rc;
    }
    if (info) zuh_tls_get_info(tls, info);
    *out = tls;
    return ZUH_OK;
}

/* badssl.com resets connections from CI runners now and then: "read failed
 * (54)", ECONNRESET, mid-handshake, on macOS. A transport failure is retried,
 * twice; a TLS verdict never is, so a flaky network can neither fail these
 * tests nor make one pass. */
static zuh_code dial(const char *host, const zuh_tls_config *cfg,
                    zuh_stream **out, zuh_tls_info *info, zuh_error *err) {
    zuh_code rc = ZUH_ERR_IO;
    int attempt;
    for (attempt = 0; attempt < 3; attempt++) {
        rc = dial_once(host, cfg, out, info, err);
        if (rc != ZUH_ERR_IO && rc != ZUH_ERR_CONNECT && rc != ZUH_ERR_TIMEOUT) break;
        printf("       (transport failure, retrying: %s)\n", err->message);
    }
    return rc;
}

int main(void) {
    zuh_tls_config cfg;
    zuh_error e;
    zuh_stream *s = NULL;
    zuh_tls_info info;
    zuh_alloc_stats st;

    printf("zuhttp TLS engine tests (S7, backend: %s)\n\n", zuh_tls_backend_name());

    ZUH_CASE("defaults are secure (§14.1)");
    zuh_tls_config_init(&cfg);
    ZUH_CHECK_EQ_INT(cfg.verify_peer, 1);
    ZUH_CHECK_EQ_INT(cfg.verify_hostname, 1);
    ZUH_CHECK_EQ_INT(cfg.revocation, 0);          /* §14.5 / S0 F-4 */
    ZUH_CHECK_EQ_INT(cfg.source, ZUH_TRUST_SYSTEM);

    ZUH_CASE("a good host completes a handshake and reports its protocol");
    zuh_tls_config_init(&cfg);
    memset(&info, 0, sizeof info);
    if (dial("example.com", &cfg, &s, &info, &e) == ZUH_OK) {
        printf("       negotiated %s / %s\n", info.protocol, info.cipher);
        ZUH_CHECK(strncmp(info.protocol, "TLSv1.", 6) == 0);
        ZUH_CHECK(info.cipher[0] != '\0');

        ZUH_CASE("a real request round-trips over TLS");
        {
            zuh_deadline d = zuh_deadline_in(15000);
            const char *req = "HEAD / HTTP/1.1\r\nHost: example.com\r\n"
                              "Connection: close\r\n\r\n";
            char buf[256];
            zuh_ssize n;
            zuh_error_clear(&e);
            ZUH_CHECK(zuh_stream_write_all(s, req, strlen(req), d, &e));
            n = zuh_stream_read(s, buf, sizeof buf - 1, d, &e);
            ZUH_CHECK(n > 0);
            if (n > 0) { buf[n] = '\0'; ZUH_CHECK(strncmp(buf, "HTTP/1.1 ", 9) == 0); }
        }
        zuh_tls_stream_free(s); s = NULL;
    } else {
        printf("       SKIP: no network (%s)\n", e.message);
    }

    /* S0 finding F-3: without SSL_VERIFY_PEER every one of these would
     * SUCCEED while reporting the certificate as untrusted. */
    ZUH_CASE("§14.6: an expired certificate is rejected as zu_tls_certificate_error");
    zuh_tls_config_init(&cfg);
    if (dial("expired.badssl.com", &cfg, &s, NULL, &e) != ZUH_OK) {
        ZUH_CHECK_EQ_INT(e.code, ZUH_ERR_TLS_CERT);
        printf("       %s\n", e.message);
    } else { ZUH_CHECK(0); zuh_tls_stream_free(s); s = NULL; }

    ZUH_CASE("§14.6: a hostname mismatch is zu_tls_hostname_error, distinctly");
    zuh_tls_config_init(&cfg);
    if (dial("wrong.host.badssl.com", &cfg, &s, NULL, &e) != ZUH_OK) {
        ZUH_CHECK_EQ_INT(e.code, ZUH_ERR_TLS_HOSTNAME);
        printf("       %s\n", e.message);
    } else { ZUH_CHECK(0); zuh_tls_stream_free(s); s = NULL; }

    ZUH_CASE("§14.6: an untrusted root is zu_tls_certificate_error");
    zuh_tls_config_init(&cfg);
    if (dial("untrusted-root.badssl.com", &cfg, &s, NULL, &e) != ZUH_OK) {
        ZUH_CHECK_EQ_INT(e.code, ZUH_ERR_TLS_CERT);
        printf("       %s\n", e.message);
    } else { ZUH_CHECK(0); zuh_tls_stream_free(s); s = NULL; }

    ZUH_CASE("§14.6: a self-signed certificate is rejected");
    zuh_tls_config_init(&cfg);
    if (dial("self-signed.badssl.com", &cfg, &s, NULL, &e) != ZUH_OK) {
        ZUH_CHECK_EQ_INT(e.code, ZUH_ERR_TLS_CERT);
    } else { ZUH_CHECK(0); zuh_tls_stream_free(s); s = NULL; }

    ZUH_CASE("§14.4: a wrong pin is refused even though the chain is valid");
    zuh_tls_config_init(&cfg);
    {
        static const char *pins[] = { "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" };
        cfg.pins = pins;
        cfg.n_pins = 1;
        if (dial("example.com", &cfg, &s, NULL, &e) != ZUH_OK) {
            ZUH_CHECK_EQ_INT(e.code, ZUH_ERR_TLS_PIN);
            printf("       %s\n", e.message);
        } else {
            ZUH_CHECK(0);   /* a bad pin must never connect */
            zuh_tls_stream_free(s); s = NULL;
        }
    }

    ZUH_CASE("§14.6: a pinned request to an untrusted chain is a certificate error, not a pin error");
    zuh_tls_config_init(&cfg);
    {
        /* The pin is never compared: the chain fails first. Reporting that as
         * a pin mismatch sends the user after the wrong fix (2026-09-25). */
        static const char *pins[] = { "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" };
        cfg.pins = pins;
        cfg.n_pins = 1;
        if (dial("untrusted-root.badssl.com", &cfg, &s, NULL, &e) != ZUH_OK) {
            ZUH_CHECK_EQ_INT(e.code, ZUH_ERR_TLS_CERT);
            printf("       %s\n", e.message);
        } else { ZUH_CHECK(0); zuh_tls_stream_free(s); s = NULL; }
    }

    ZUH_CASE("§14.2: ca_file REPLACES system trust, so a public host fails");
    zuh_tls_config_init(&cfg);
    cfg.source = ZUH_TRUST_DATA;
    cfg.ca_data = "-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----\n";
    cfg.ca_data_len = strlen((const char *)cfg.ca_data);
    if (dial("example.com", &cfg, &s, NULL, &e) != ZUH_OK) {
        ZUH_CHECK(e.code == ZUH_ERR_TLS || e.code == ZUH_ERR_TLS_CERT);
    } else { ZUH_CHECK(0); zuh_tls_stream_free(s); s = NULL; }

    ZUH_CASE("a failed handshake leaves no leaked allocation");
    zuh_alloc_stats_get(&st);
    ZUH_CHECK_EQ_INT(st.live_blocks, 0);

    printf("\n%d checks, %d failures\n", zuh_test_checks, zuh_test_fails);
    printf("allocations: %lu made, %lu freed, %lu live\n",
           (unsigned long)st.total_allocs, (unsigned long)st.total_frees,
           (unsigned long)st.live_blocks);
    return zuh_test_fails == 0 ? 0 : 1;
}

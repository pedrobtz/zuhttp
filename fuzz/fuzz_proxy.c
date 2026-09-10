/* Target 7 — proxy environment parsing (§20.1, §20.2, §43).
 *
 * Environment variables are attacker-influenced more often than they look:
 * the httpoxy class of bug is precisely a request header arriving as an
 * environment variable. So NO_PROXY lists and proxy URLs are parsed as
 * untrusted input.
 *
 * Layout: first byte selects the sub-target, then NAME\0VALUE where useful. */
#include "zu_proxy.h"
#include "zu_alloc.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* An environment backed entirely by fuzzer bytes. */
static char *g_http_proxy, *g_no_proxy;
static const char *fz_getenv(void *ctx, const char *name) {
    (void)ctx;
    if (strcmp(name, "http_proxy") == 0 || strcmp(name, "https_proxy") == 0) return g_http_proxy;
    if (strcmp(name, "no_proxy") == 0) return g_no_proxy;
    return NULL;
}

static char *dupz(const uint8_t *d, size_t n) {
    char *s = (char *)malloc(n + 1);
    if (!s) return NULL;
    if (n) memcpy(s, d, n);
    s[n] = '\0';
    return s;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    zu_error e;
    if (size < 2 || size > 8 * 1024) return 0;

    switch (data[0] % 3) {
    case 0: {   /* NO_PROXY matching against a host from the same input */
        const uint8_t *sep = (const uint8_t *)memchr(data + 1, 0, size - 1);
        char *list = dupz(data + 1, sep ? (size_t)(sep - data - 1) : size - 1);
        char *host = sep ? dupz(sep + 1, (size_t)(data + size - sep - 1)) : dupz((const uint8_t *)"h", 1);
        if (list && host) (void)zu_no_proxy_matches(list, host, 443);
        free(list); free(host);
        break;
    }
    case 1: {   /* proxy URL parsing, including percent-decoding */
        char *url = dupz(data + 1, size - 1);
        zu_proxy p;
        if (url && zu_proxy_parse(&p, url, &e) == ZU_OK && p.in_use) {
            zu_buffer b;
            if (!p.host) abort();
            /* §20.4: credentials are moved OUT of the URL, so the host can
             * never still carry them. */
            if (strchr(p.host, '@')) abort();
            /* The port is parsed out into p.port, so a host still carrying
             * ":3128" would mean the split silently failed. Exactly one colon
             * with digits after it is that shape; an IPv6 literal has two or
             * more colons and is legitimate. */
            {
                const char *first = strchr(p.host, ':');
                if (first && first == strrchr(p.host, ':') && first[1] != '\0') {
                    const char *c;
                    int all_digits = 1;
                    for (c = first + 1; *c; c++)
                        if (*c < '0' || *c > '9') { all_digits = 0; break; }
                    if (all_digits) abort();
                }
            }
            if (zu_buf_init(&b, 64, 1 << 20)) {
                (void)zu_proxy_auth_value(&p, &b);
                zu_buf_free(&b);
            }
        }
        if (url) zu_proxy_free(&p), free(url);
        break;
    }
    default: {  /* full resolution: env -> proxy decision */
        const uint8_t *sep = (const uint8_t *)memchr(data + 1, 0, size - 1);
        zu_uri t;
        static const char k_target[] = "https://target.example/x";
        g_http_proxy = dupz(data + 1, sep ? (size_t)(sep - data - 1) : size - 1);
        g_no_proxy   = sep ? dupz(sep + 1, (size_t)(data + size - sep - 1)) : NULL;
        if (zu_uri_parse(&t, k_target, k_target + sizeof k_target - 1) == ZU_OK) {
            zu_env env;
            zu_proxy p;
            env.get = fz_getenv;
            env.ctx = NULL;
            if (zu_proxy_resolve(&p, &t, &env, NULL, 0, &e) == ZU_OK && p.in_use) {
                if (!p.host || !p.scheme) abort();
                if (strcmp(p.scheme, "http") != 0) abort();   /* never downgraded */
            }
            zu_proxy_free(&p);
            zu_uri_free(&t);
        }
        free(g_http_proxy); free(g_no_proxy);
        g_http_proxy = g_no_proxy = NULL;
        break;
    }
    }
    return 0;
}

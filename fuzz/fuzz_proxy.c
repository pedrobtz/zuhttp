/* Target 7 — proxy environment parsing (§20.1, §20.2, §43).
 *
 * Environment variables are attacker-influenced more often than they look:
 * the httpoxy class of bug is precisely a request header arriving as an
 * environment variable. So NO_PROXY lists and proxy URLs are parsed as
 * untrusted input.
 *
 * Layout: first byte selects the sub-target, then NAME\0VALUE where useful. */
#include "zuh_proxy.h"
#include "zuh_alloc.h"
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
    zuh_error e;
    if (size < 2 || size > 8 * 1024) return 0;

    switch (data[0] % 4) {
    case 0: {   /* NO_PROXY matching against a host from the same input */
        const uint8_t *sep = (const uint8_t *)memchr(data + 1, 0, size - 1);
        char *list = dupz(data + 1, sep ? (size_t)(sep - data - 1) : size - 1);
        char *host = sep ? dupz(sep + 1, (size_t)(data + size - sep - 1)) : dupz((const uint8_t *)"h", 1);
        if (list && host) (void)zuh_no_proxy_matches(list, host, 443);
        free(list); free(host);
        break;
    }
    case 1: {   /* proxy URL parsing, including percent-decoding */
        char *url = dupz(data + 1, size - 1);
        zuh_proxy p;
        if (url && zuh_proxy_parse(&p, url, &e) == ZUH_OK && p.in_use) {
            zuh_buffer b;
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
            if (zuh_buf_init(&b, 64, 1 << 20)) {
                (void)zuh_proxy_auth_value(&p, &b);
                zuh_buf_free(&b);
            }
        }
        if (url) zuh_proxy_free(&p), free(url);
        break;
    }
    case 3: {   /* #230: CONNECT through a proxy with credentials, and its reply */
        /* Before the first NUL, the target URL; after it, the proxy's reply,
         * which a hostile proxy controls. No other target reached either. */
        const uint8_t *sep = (const uint8_t *)memchr(data + 1, 0, size - 1);
        size_t tlen = sep ? (size_t)(sep - data - 1) : size - 1;
        const char *reply = sep ? (const char *)sep + 1 : "";
        size_t rlen = sep ? (size_t)(data + size - sep - 1) : 0;
        char *turl = dupz(data + 1, tlen);
        zuh_proxy p;
        zuh_uri t;
        zuh_buffer b;
        size_t consumed = 0;
        int status = -1;
        zuh_code rc;
        memset(&p, 0, sizeof p);
        if (turl && zuh_proxy_parse(&p, "http://us%3Aer:p%40ss@px.example:3128", &e) == ZUH_OK &&
            zuh_uri_parse(&t, turl, turl + tlen) == ZUH_OK) {
            if (t.host && zuh_buf_init(&b, 64, 1 << 20)) {
                if (zuh_proxy_connect_request(&p, &t, &b, &e) == ZUH_OK) {
                    const char *req = (const char *)b.data;
                    size_t k;
                    /* One header block, ending the request: a target can
                     * never smuggle a line, or a second request, into it. */
                    if (b.len < 12 || memcmp(req, "CONNECT ", 8) != 0 ||
                        memcmp(req + b.len - 4, "\r\n\r\n", 4) != 0) abort();
                    for (k = 0; k + 4 < b.len; k++)
                        if (memcmp(req + k, "\r\n\r\n", 4) == 0) abort();
                    for (k = 0; k < b.len; k++)
                        if ((req[k] == '\n' && (k == 0 || req[k - 1] != '\r')) ||
                            (req[k] == '\r' && (k + 1 >= b.len || req[k + 1] != '\n')))
                            abort();
                    /* §20.4: the credentials go in Proxy-Authorization, so
                     * the request line never carries them. Searched within
                     * b.len: a zuh_buffer is not NUL-terminated, and strstr()
                     * ran off the end of one the request filled exactly. */
                    {
                        static const char want[] = "\r\nProxy-Authorization: Basic ";
                        size_t wl = sizeof want - 1;
                        int found = 0;
                        for (k = 0; !found && k + wl <= b.len; k++)
                            found = memcmp(req + k, want, wl) == 0;
                        if (!found) abort();
                    }
                    for (k = 0; k < b.len && req[k] != '\r'; k++)
                        if (req[k] == '@') abort();
                }
                zuh_buf_free(&b);
            }
            zuh_uri_free(&t);
        }
        zuh_proxy_free(&p);
        free(turl);
        /* The reply: tunnel only on a 2xx, a 407 is its own class, and the
         * parser never claims more bytes than it was given. */
        rc = zuh_proxy_connect_response(reply, rlen, &consumed, &status, &e);
        if (consumed > rlen) abort();
        if (rc == ZUH_OK && (status < 200 || status > 299)) abort();
        if (rc == ZUH_ERR_PROXY_AUTH && status != 407) abort();
        if (rc == ZUH_ERR_PROXY && (status == 407 || (status >= 200 && status <= 299))) abort();
        break;
    }
    default: {  /* full resolution: env -> proxy decision */
        const uint8_t *sep = (const uint8_t *)memchr(data + 1, 0, size - 1);
        zuh_uri t;
        static const char k_target[] = "https://target.example/x";
        g_http_proxy = dupz(data + 1, sep ? (size_t)(sep - data - 1) : size - 1);
        g_no_proxy   = sep ? dupz(sep + 1, (size_t)(data + size - sep - 1)) : NULL;
        if (zuh_uri_parse(&t, k_target, k_target + sizeof k_target - 1) == ZUH_OK) {
            zuh_env env;
            zuh_proxy p;
            env.get = fz_getenv;
            env.ctx = NULL;
            if (zuh_proxy_resolve(&p, &t, &env, NULL, 0, &e) == ZUH_OK && p.in_use) {
                if (!p.host || !p.scheme) abort();
                if (strcmp(p.scheme, "http") != 0) abort();   /* never downgraded */
            }
            zuh_proxy_free(&p);
            zuh_uri_free(&t);
        }
        free(g_http_proxy); free(g_no_proxy);
        g_http_proxy = g_no_proxy = NULL;
        break;
    }
    }
    return 0;
}

#include "zuh_proxy.h"
#include "zuh_alloc.h"
#include "zuh_headers.h"
#include "zuh_response.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* --- environment seam ----------------------------------------------------- */

static const char *sys_getenv(void *ctx, const char *name) {
    ZUH_UNUSED(ctx);
    return getenv(name);
}

void zuh_env_system(zuh_env *e) {
    if (!e) return;
    e->get = sys_getenv;
    e->ctx = NULL;
}

static const char *env_get(const zuh_env *e, const char *name) {
    const char *v;
    if (!e || !e->get) return NULL;
    v = e->get(e->ctx, name);
    return (v && v[0]) ? v : NULL;   /* an empty variable means "unset" */
}

/* --- small helpers -------------------------------------------------------- */

static char *dup_n(const char *s, size_t n) {
    char *p = (char *)zuh_alloc(n + 1);
    if (!p) return NULL;
    if (n) memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

static char *dup_s(const char *s) { return s ? dup_n(s, strlen(s)) : NULL; }

/* Percent-decode in place, returning the new length, or -1 if the input has
 * a malformed escape. Proxy credentials routinely contain characters that
 * MUST be percent-encoded in a URL ('@', ':', '/'), so sending the raw form
 * would authenticate with the wrong password and look like a server bug.
 *
 * UriEscape.c would have done this, but it is one of the uriparser modules
 * the §8.2 subset deliberately excludes, and this is 20 lines. */
static int hexval(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static zuh_ssize pct_decode(char *s) {
    char *w = s;
    const char *r = s;
    while (*r) {
        if (*r == '%') {
            int hi = hexval(r[1]);
            int lo = hi < 0 ? -1 : hexval(r[2]);
            if (lo < 0) return -1;
            *w++ = (char)((hi << 4) | lo);
            r += 3;
        } else {
            *w++ = *r++;
        }
    }
    *w = '\0';
    return (zuh_ssize)(w - s);
}

/* How many ':' the entry contains, which is what separates "host:port" from
 * an IPv6 literal. */
static size_t count_colons(const char *s, size_t n) {
    size_t i, c = 0;
    for (i = 0; i < n; i++) if (s[i] == ':') c++;
    return c;
}

static int is_ip_literal(const char *s, size_t n) {
    size_t i;
    int digits = 0, dots = 0, other = 0;
    if (memchr(s, ':', n)) return 1;                 /* IPv6 */
    for (i = 0; i < n; i++) {
        if (s[i] >= '0' && s[i] <= '9') digits++;
        else if (s[i] == '.') dots++;
        else other++;
    }
    return other == 0 && dots == 3 && digits > 0;    /* IPv4 */
}

/* --- §20.4 base64 --------------------------------------------------------- */

int zuh_base64_encode(const void *src, size_t n, zuh_buffer *out) {
    static const char k[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const unsigned char *p = (const unsigned char *)src;
    size_t i;
    if (!out) return 0;
    for (i = 0; i + 2 < n; i += 3) {
        unsigned long v = ((unsigned long)p[i] << 16) |
                          ((unsigned long)p[i + 1] << 8) | p[i + 2];
        if (!zuh_buf_append_byte(out, (unsigned char)k[(v >> 18) & 63]) ||
            !zuh_buf_append_byte(out, (unsigned char)k[(v >> 12) & 63]) ||
            !zuh_buf_append_byte(out, (unsigned char)k[(v >>  6) & 63]) ||
            !zuh_buf_append_byte(out, (unsigned char)k[ v        & 63])) return 0;
    }
    if (i < n) {
        unsigned long v = (unsigned long)p[i] << 16;
        int have2 = (i + 1 < n);
        if (have2) v |= (unsigned long)p[i + 1] << 8;
        if (!zuh_buf_append_byte(out, (unsigned char)k[(v >> 18) & 63]) ||
            !zuh_buf_append_byte(out, (unsigned char)k[(v >> 12) & 63])) return 0;
        if (have2) {
            if (!zuh_buf_append_byte(out, (unsigned char)k[(v >> 6) & 63])) return 0;
        } else if (!zuh_buf_append_byte(out, '=')) return 0;
        if (!zuh_buf_append_byte(out, '=')) return 0;
    }
    return 1;
}

/* --- proxy ---------------------------------------------------------------- */

void zuh_proxy_init(zuh_proxy *p) { if (p) memset(p, 0, sizeof *p); }

void zuh_proxy_free(zuh_proxy *p) {
    if (!p) return;
    zuh_free(p->scheme); zuh_free(p->host);
    zuh_free(p->username); zuh_free(p->password); zuh_free(p->source);
    memset(p, 0, sizeof *p);
}

zuh_code zuh_proxy_parse(zuh_proxy *p, const char *url, zuh_error *err) {
    zuh_uri u;
    char *withscheme = NULL;
    const char *text;
    zuh_code rc;

    if (!p) return ZUH_ERR_PROXY;
    zuh_proxy_init(p);
    if (!url || !url[0]) return ZUH_OK;   /* not configured; in_use stays 0 */

    /* curl accepts a bare "host:port". zuh_uri_parse requires a scheme, so
     * supply the default rather than teaching the URI parser about proxies. */
    if (!strstr(url, "://")) {
        size_t n = strlen(url);
        withscheme = (char *)zuh_alloc(n + 8);
        if (!withscheme) return ZUH_ERR_NOMEM;
        memcpy(withscheme, "http://", 7);
        memcpy(withscheme + 7, url, n + 1);
        text = withscheme;
    } else {
        text = url;
    }

    rc = zuh_uri_parse(&u, text, text + strlen(text));
    zuh_free(withscheme);
    if (rc != ZUH_OK) {
        zuh_error_set(err, ZUH_ERR_PROXY, ZUH_PHASE_CONNECT,
                     "proxy URL is not usable");
        return ZUH_ERR_PROXY;
    }
    /* socks5:// and friends parse as neither http nor https, so zuh_uri_parse
     * has already rejected them; this catches https-to-proxy, which zuhttp
     * does not implement and must not silently downgrade. */
    if (strcmp(u.scheme, "http") != 0) {
        zuh_error_set(err, ZUH_ERR_PROXY, ZUH_PHASE_CONNECT,
                     "only http:// proxies are supported, not %s://", u.scheme);
        zuh_uri_free(&u);
        return ZUH_ERR_PROXY;
    }

    p->scheme = dup_s(u.scheme);
    p->host   = dup_s(u.host);
    p->port   = u.port;
    if (!p->scheme || !p->host) { zuh_uri_free(&u); zuh_proxy_free(p); return ZUH_ERR_NOMEM; }

    /* §20.4: split userinfo out of the URL immediately. */
    if (u.userinfo) {
        const char *colon = strchr(u.userinfo, ':');
        if (colon) {
            p->username = dup_n(u.userinfo, (size_t)(colon - u.userinfo));
            p->password = dup_s(colon + 1);
        } else {
            p->username = dup_s(u.userinfo);
            p->password = dup_n("", 0);
        }
        if (!p->username || !p->password) { zuh_uri_free(&u); zuh_proxy_free(p); return ZUH_ERR_NOMEM; }
        if (pct_decode(p->username) < 0 || pct_decode(p->password) < 0) {
            zuh_error_set(err, ZUH_ERR_PROXY, ZUH_PHASE_CONNECT,
                         "proxy credentials contain a malformed percent-escape");
            zuh_uri_free(&u);
            zuh_proxy_free(p);
            return ZUH_ERR_PROXY;
        }
    }
    p->in_use = 1;
    zuh_uri_free(&u);
    return ZUH_OK;
}

/* --- §20.2 NO_PROXY ------------------------------------------------------- */

int zuh_no_proxy_matches(const char *no_proxy, const char *host, uint16_t port) {
    const char *p;
    size_t hlen;

    if (!no_proxy || !host) return 0;
    hlen = strlen(host);
    if (hlen == 0) return 0;

    for (p = no_proxy; *p; ) {
        const char *start, *end, *colon;
        size_t elen;

        while (*p == ',' || *p == ' ' || *p == '\t') p++;
        start = p;
        while (*p && *p != ',') p++;
        end = p;
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) end--;
        if (end == start) continue;

        /* "*" alone bypasses everything. */
        if (end - start == 1 && *start == '*') return 1;

        /* An entry may carry a port, which must then also match.
         *
         * Splitting on "the first colon" is wrong for IPv6, and treating
         * "anything with a colon" as IPv6 is wrong for "example.com:8080".
         * The colon COUNT distinguishes them: exactly one means host:port,
         * two or more means an IPv6 literal — which carries a port only in
         * the bracketed form "[::1]:8080". */
        elen = (size_t)(end - start);
        colon = NULL;
        if (start[0] == '[') {
            const char *rb = (const char *)memchr(start, ']', elen);
            if (!rb) continue;                       /* malformed entry */
            if (rb + 1 < end && rb[1] == ':') colon = rb + 1;
            /* Drop the brackets: hosts are stored unbracketed (§8.2). */
            start++;
            elen = (size_t)(rb - start);
            if (colon) {
                long want = strtol(colon + 1, NULL, 10);
                if (want != (long)port) continue;
            }
        } else {
            if (count_colons(start, elen) == 1)
                colon = (const char *)memchr(start, ':', elen);
            if (colon) {
                long want = strtol(colon + 1, NULL, 10);
                if (want != (long)port) continue;
                elen = (size_t)(colon - start);
            }
        }

        /* A leading dot is ignored: .example.com == example.com. */
        if (elen > 0 && start[0] == '.') { start++; elen--; }
        if (elen == 0) continue;

        if (elen > hlen) continue;
        if (zuh_ascii_ncasecmp(host + (hlen - elen), elen, start, elen) != 0) continue;

        /* Exact match always counts. */
        if (elen == hlen) return 1;
        /* An IP literal matches EXACTLY and never by suffix, or "1.2.3.4"
         * would bypass the proxy for the unrelated host "10.1.2.3.4". */
        if (is_ip_literal(start, elen)) continue;
        /* Otherwise the match must fall on a domain-label boundary, so
         * "example.com" matches "api.example.com" but not "notexample.com". */
        if (host[hlen - elen - 1] == '.') return 1;
    }
    return 0;
}

/* --- §20.1 resolution ----------------------------------------------------- */

zuh_code zuh_proxy_resolve(zuh_proxy *out, const zuh_uri *target, const zuh_env *env,
                         const char *override, int override_set, zuh_error *err) {
    const char *url = NULL;
    const char *src = NULL;
    const char *no_proxy;

    if (!out) return ZUH_ERR_PROXY;
    zuh_proxy_init(out);
    if (!target || !target->scheme || !target->host) return ZUH_ERR_PROXY;

    /* An explicit setting always wins, and an explicit NULL means "disabled",
     * which is deliberately different from "not configured". */
    if (override_set) {
        if (!override || !override[0]) return ZUH_OK;
        {
            zuh_code rc = zuh_proxy_parse(out, override, err);
            if (rc == ZUH_OK && out->in_use) {
                out->source = dup_s("explicit");
                if (!out->source) { zuh_proxy_free(out); return ZUH_ERR_NOMEM; }
            }
            return rc;
        }
    }

    if (target->is_https) {
        url = env_get(env, "https_proxy"); src = "https_proxy";
        if (!url) { url = env_get(env, "HTTPS_PROXY"); src = "HTTPS_PROXY"; }
    } else {
        /* §20.1: lowercase ONLY. In a CGI-like environment the request header
         * "Proxy:" arrives as HTTP_PROXY, which is the httpoxy bug. */
        url = env_get(env, "http_proxy"); src = "http_proxy";
    }
    if (!url) { url = env_get(env, "all_proxy"); src = "all_proxy"; }
    if (!url) { url = env_get(env, "ALL_PROXY"); src = "ALL_PROXY"; }
    if (!url) return ZUH_OK;

    no_proxy = env_get(env, "no_proxy");
    if (!no_proxy) no_proxy = env_get(env, "NO_PROXY");
    if (no_proxy && zuh_no_proxy_matches(no_proxy, target->host, target->port))
        return ZUH_OK;

    {
        zuh_code rc = zuh_proxy_parse(out, url, err);
        if (rc == ZUH_OK && out->in_use) {
            out->source = dup_s(src);
            if (!out->source) { zuh_proxy_free(out); return ZUH_ERR_NOMEM; }
        }
        return rc;
    }
}

/* --- §20.3 request forms -------------------------------------------------- */

int zuh_proxy_absolute_form(const zuh_uri *u, zuh_buffer *out) {
    char portbuf[8];
    if (!u || !out || !u->scheme || !u->host || !u->path_query) return 0;
    /* Userinfo is deliberately never written: this string goes on the wire to
     * the proxy and into traces (§42). */
    if (!zuh_buf_append_str(out, u->scheme) || !zuh_buf_append_str(out, "://")) return 0;
    if (strchr(u->host, ':')) {
        if (!zuh_buf_append_byte(out, '[') || !zuh_buf_append_str(out, u->host)
            || !zuh_buf_append_byte(out, ']')) return 0;
    } else if (!zuh_buf_append_str(out, u->host)) return 0;
    if (u->port_explicit) {
        int n = snprintf(portbuf, sizeof portbuf, ":%u", (unsigned)u->port);
        if (n < 0 || (size_t)n >= sizeof portbuf) return 0;
        if (!zuh_buf_append_str(out, portbuf)) return 0;
    }
    return zuh_buf_append_str(out, u->path_query);
}

int zuh_proxy_auth_value(const zuh_proxy *p, zuh_buffer *out) {
    zuh_buffer raw;
    int ok = 0;
    if (!p || !out || !p->username) return 0;
    if (!zuh_buf_init(&raw, 64, 4096)) return 0;
    if (zuh_buf_append_str(&raw, p->username) && zuh_buf_append_byte(&raw, ':')
        && zuh_buf_append_str(&raw, p->password ? p->password : "")) {
        if (zuh_buf_append_str(out, "Basic "))
            ok = zuh_base64_encode(raw.data, raw.len, out);
    }
    zuh_buf_free(&raw);
    return ok;
}

zuh_code zuh_proxy_connect_request(const zuh_proxy *p, const zuh_uri *target,
                                 zuh_buffer *out, zuh_error *err) {
    char hostport[300];
    int n;

    if (!p || !target || !out || !target->host) return ZUH_ERR_PROXY;

    if (strchr(target->host, ':'))
        n = snprintf(hostport, sizeof hostport, "[%s]:%u", target->host,
                     (unsigned)target->port);
    else
        n = snprintf(hostport, sizeof hostport, "%s:%u", target->host,
                     (unsigned)target->port);
    if (n < 0 || (size_t)n >= sizeof hostport) {
        zuh_error_set(err, ZUH_ERR_PROXY, ZUH_PHASE_CONNECT, "proxy target is too long");
        return ZUH_ERR_PROXY;
    }

    if (!zuh_buf_append_str(out, "CONNECT ") || !zuh_buf_append_str(out, hostport)
        || !zuh_buf_append_str(out, " HTTP/1.1\r\nHost: ")
        || !zuh_buf_append_str(out, hostport)
        || !zuh_buf_append_str(out, "\r\n")) return ZUH_ERR_NOMEM;

    /* §20.4: Proxy-Authorization appears ONLY here — on the connection to the
     * proxy, on the CONNECT request. It is never added to the tunnelled
     * request, so it cannot reach the origin or survive a redirect. */
    if (p->username) {
        if (!zuh_buf_append_str(out, "Proxy-Authorization: ")) return ZUH_ERR_NOMEM;
        if (!zuh_proxy_auth_value(p, out)) return ZUH_ERR_NOMEM;
        if (!zuh_buf_append_str(out, "\r\n")) return ZUH_ERR_NOMEM;
    }
    if (!zuh_buf_append_str(out, "Proxy-Connection: keep-alive\r\n\r\n"))
        return ZUH_ERR_NOMEM;
    return ZUH_OK;
}

zuh_code zuh_proxy_connect_response(const char *buf, size_t len, size_t *consumed,
                                  int *status, zuh_error *err) {
    zuh_response r;
    zuh_code rc;

    if (status) *status = 0;
    zuh_response_init(&r);
    /* Same strictness as any other response (§20.3): a proxy is not exempt
     * from §18, and a lenient parse here is a tunnel built on a lie. */
    rc = zuh_response_parse(&r, buf, len, 0, consumed, err);
    if (rc != ZUH_OK) { zuh_response_free(&r); return rc; }

    if (status) *status = r.status;
    if (r.status >= 200 && r.status < 300) { zuh_response_free(&r); return ZUH_OK; }

    if (r.status == 407) {
        zuh_error_set(err, ZUH_ERR_PROXY_AUTH, ZUH_PHASE_CONNECT,
                     "proxy requires authentication (407)");
        zuh_response_free(&r);
        return ZUH_ERR_PROXY_AUTH;
    }
    zuh_error_set(err, ZUH_ERR_PROXY, ZUH_PHASE_CONNECT,
                 "proxy refused CONNECT with status %d", r.status);
    zuh_response_free(&r);
    return ZUH_ERR_PROXY;
}

#include "zuh_engine.h"
#include "zuh_alloc.h"
#include "zuh_uri.h"
#include "zuh_request.h"
#include "zuh_response.h"
#include "zuh_framing.h"
#include "zuh_redirect.h"
#include "zuh_inflate.h"
#include "zuh_tls.h"
#include "zuh_stream.h"
#include "zuh_pool.h"
#include "zuh_sink.h"
#include "zuh_body.h"
#include "zuh_proxy.h"
#include "zuh_trace.h"
#include "zuh_time.h"
#include <string.h>
#include <stdio.h>

#define ZUH_DEFAULT_TIMEOUT_MS  30000
#define ZUH_DEFAULT_MAX_BODY    (16u * 1024u * 1024u)
#define ZUH_MAX_HEADER_BYTES    (64u * 1024u)
#define ZUH_READ_CHUNK          16384
/* §19.5's "small cap" on a redirect body we are going to drain. Large enough
 * for any real 3xx explanation page, small enough that draining one is never
 * the reason a download is memory-hungry. */
#define ZUH_MAX_REDIRECT_BODY   (64u * 1024u)

void zuh_get_opts_init(zuh_get_opts *o) {
    if (!o) return;
    memset(o, 0, sizeof *o);
    o->timeout_ms    = ZUH_DEFAULT_TIMEOUT_MS;
    o->max_redirects = 10;              /* §19.4; the R layer passes its own */
    o->verify        = 1;               /* never 0 by default (§14.1) */
    o->max_body      = ZUH_DEFAULT_MAX_BODY;
}

void zuh_result_init(zuh_result *r) {
    if (!r) return;
    memset(r, 0, sizeof *r);
    zuh_headers_init(&r->headers);
    zuh_headers_init(&r->trailers);
    zuh_timings_init(&r->timings);
}

void zuh_result_free(zuh_result *r) {
    if (!r) return;
    zuh_headers_free(&r->headers);
    zuh_headers_free(&r->trailers);
    zuh_open_body_free(r->open);
    zuh_buf_free(&r->body);
    zuh_free(r->final_url);
    zuh_free(r->tls_version);
    zuh_free(r->tls_cipher);
    zuh_free(r->remote_ip);
    zuh_free(r->trust_backend);
    memset(r, 0, sizeof *r);
}

static char *dup_str(const char *s) {
    size_t n;
    char *p;
    if (!s) return NULL;
    n = strlen(s);
    p = (char *)zuh_alloc(n + 1);
    if (p) memcpy(p, s, n + 1);
    return p;
}

/* "scheme://host[:port]path?query", never with userinfo (§42.1). */
/* RFC 9112 §3.2: Host is the authority — the host, bracketed if it is an
 * IPv6 literal, plus ":port" unless the port is the scheme's default. Taking
 * cur.host alone dropped the port, so a server on :8080 saw `Host: h`. */
static int host_header(const zuh_uri *u, char *out, size_t cap) {
    int v6 = strchr(u->host, ':') != NULL;
    int n;
    if (u->port != zuh_uri_default_port(u->scheme))
        n = snprintf(out, cap, v6 ? "[%s]:%u" : "%s:%u", u->host, (unsigned)u->port);
    else
        n = snprintf(out, cap, v6 ? "[%s]" : "%s", u->host);
    return n > 0 && (size_t)n < cap;
}

/* Unbounded: every part is already bounded by the parser (§8, 64 KiB), and
 * a cap here once failed a request the server had answered, as "out of
 * memory", for a URL of 9 KiB (review #174). NULL means the allocator failed
 * and nothing else. */
static char *url_of(const zuh_uri *u) {
    zuh_buffer b;
    const char *s = NULL;
    char *out = NULL;
    char port[8];

    if (!zuh_buf_init(&b, 128, 0)) return NULL;
    if (!zuh_buf_append_str(&b, u->scheme) || !zuh_buf_append_str(&b, "://")) goto done;
    if (strchr(u->host, ':')) {
        if (!zuh_buf_append_byte(&b, '[') || !zuh_buf_append_str(&b, u->host)
            || !zuh_buf_append_byte(&b, ']')) goto done;
    } else if (!zuh_buf_append_str(&b, u->host)) goto done;
    if (u->port_explicit) {
        int n = snprintf(port, sizeof port, ":%u", (unsigned)u->port);
        if (n < 0 || (size_t)n >= sizeof port) goto done;
        if (!zuh_buf_append_str(&b, port)) goto done;
    }
    if (!zuh_buf_append_str(&b, u->path_query)) goto done;
    if (zuh_buf_cstr(&b, &s)) out = dup_str(s);
done:
    zuh_buf_free(&b);
    return out;
}

/* The same URL, with §42's policy applied — what a caller is allowed to see.
 *
 * url_of() drops userinfo because it never builds it, which used to be the
 * whole of `final_url`'s "credential-free". It is not: §42.1 counts a query
 * parameter named `access_token` as a credential too, and one came straight
 * back out of zu_resp_url(). The redaction belongs here rather than in R
 * because init.c stores this string ON the response, so a value redacted at
 * the accessor would still be reachable through `resp$url`.
 *
 * NULL policy means the §42.1 defaults, as everywhere else: an unset policy
 * must mean "the defaults" and never "no redaction". */
static char *redacted_url_of(const zuh_uri *u, const zuh_redact_policy *p) {
    zuh_redact_policy dflt;
    zuh_buffer b;
    const char *s = NULL;
    char *raw, *out = NULL;

    raw = url_of(u);
    if (!raw) return NULL;
    if (!p) { zuh_redact_policy_init(&dflt); p = &dflt; }
    if (!zuh_buf_init(&b, 128, 0)) { zuh_free(raw); return NULL; }
    if (zuh_redact_url(p, raw, strlen(raw), &b) && zuh_buf_cstr(&b, &s))
        out = dup_str(s);
    zuh_buf_free(&b);
    zuh_free(raw);
    return out;                       /* NULL feeds the caller's NOMEM path */
}

/* A connection the hop gives up on before done_with_stream() would run:
 * closed, then freed, so every connection the engine opens is closed exactly
 * once (§26.3; review #187 made the mock count it). A free alone releases the
 * descriptor on every backend, but skips the orderly close. */
static void drop_stream(zuh_stream *s) {
    if (!s) return;
    zuh_stream_close(s);
    zuh_stream_free(s);
}

/* Open the transport for one hop: TCP, then TLS when the scheme says so. */
/* --- §26.1 pool key ------------------------------------------------------
 *
 * Built from the URI, the proxy and the §14 TLS configuration this engine
 * actually applies — which is now every field of §26.1 except the client
 * certificate, since client certs are not yet a thing zuh_get_opts can carry.
 *
 * When one IS plumbed through, it must be added here in the same commit. A
 * key that ignores a field two clients differ on is the "coarse key is a
 * security bug, not a performance optimisation" failure §26.1 names — it
 * would let a request with verification off, or without a pin, reuse a
 * connection established with them. zuh_pool_key_eq() compares every field of
 * the struct, so the risk is only ever a field missing HERE.
 *
 * The strings are owned copies, freed by pool_key_free(). Borrowing pointers
 * into the zuh_uri would be cheaper and is what an earlier draft did, but the
 * struct's contract is owned storage, and a later zuh_pool_key_free() on a
 * borrowed key is a double free waiting to happen.
 *
 * acquire and release each build their own key rather than sharing one across
 * the hop. That is four strdups per pooled request instead of two, and it buys
 * the loop's dozen early-return paths having no key to free — the kind of
 * lifetime bookkeeping that leaks the first time someone adds a thirteenth. */
int zuh_engine_pool_key(zuh_pool_key *k, const zuh_uri *u, const zuh_get_opts *o,
                        const zuh_proxy *px) {
    zuh_pool_key_init(k);
    k->scheme = dup_str(u->is_https ? "https" : "http");
    k->host   = dup_str(u->host);
    if (!k->scheme || !k->host) { zuh_pool_key_free(k); return 0; }
    k->port            = u->port;
    k->verify_peer     = o->verify;
    k->verify_hostname = o->verify;
    if (o->ca_file) {
        k->ca_file = dup_str(o->ca_file);
        if (!k->ca_file) { zuh_pool_key_free(k); return 0; }
    }
    /* §26.1 field by field. S16 left a note here saying that anything later
     * plumbed through zuh_get_opts must be added in the same commit, because a
     * key that ignores a field two clients differ on is "a security bug, not a
     * performance optimisation" — it would let a request pinned to one key
     * reuse a connection established without the pin. This is that commit. */
    if (o->tls) {
        k->revocation  = o->tls->revocation;
        k->min_version = o->tls->min_version;
        if (o->tls->ca_extra_file) {
            k->ca_extra_file = dup_str(o->tls->ca_extra_file);
            if (!k->ca_extra_file) { zuh_pool_key_free(k); return 0; }
        }
        if (o->tls->n_pins > 0) {
            /* Joined in the order given. Two clients that list the same pins
             * differently are treated as different, which costs a connection
             * and never shares one that should not be shared — the safe way
             * round for a key whose job is to keep things apart. */
            zuh_buffer b;
            size_t i;
            const char *joined = NULL;
            if (!zuh_buf_init(&b, 128, 64 * 1024)) { zuh_pool_key_free(k); return 0; }
            for (i = 0; i < o->tls->n_pins; i++) {
                if (!zuh_buf_append_str(&b, o->tls->pins[i]) ||
                    !zuh_buf_append_byte(&b, '\x1f')) {
                    zuh_buf_free(&b); zuh_pool_key_free(k); return 0;
                }
            }
            if (!zuh_buf_cstr(&b, &joined)) { zuh_buf_free(&b); zuh_pool_key_free(k); return 0; }
            k->pins = dup_str(joined);
            zuh_buf_free(&b);
            if (!k->pins) { zuh_pool_key_free(k); return 0; }
        }
    }
    /* §65.1: the ALPN a TLS connection offered is the http2 mode's list,
     * which tls_cfg_for() sets whatever zu_tls() said, so the key records
     * that list; and the mode itself, which is all that separates h2c from
     * HTTP/1.1 on an http:// origin. */
    k->http2 = (int)o->http2;
    if (u->is_https) {
        k->alpn = dup_str(zuh_h2_alpn_for(o->http2));
        if (!k->alpn) { zuh_pool_key_free(k); return 0; }
    }
    /* §26.1 requires proxy identity INCLUDING credentials, so that two
     * clients with different proxy credentials cannot share a tunnel. The
     * credentials are part of the key and never part of anything printable —
     * zuh_pool_key is internal and has no formatter. */
    if (px && px->in_use) {
        /* Each field is written as its length, ':', then its bytes, so the
         * key is complete and unambiguous. It used to be formatted into 512
         * bytes with the truncation ignored — a 510-byte username dropped
         * the password, host and port, and a request for one proxy reused
         * another's connection — and joined with ':' and '@', which decoded
         * credentials may themselves contain. */
        const char *f[5];
        char port[16];
        size_t i;
        zuh_buffer b;
        const char *joined = NULL;
        snprintf(port, sizeof port, "%u", (unsigned)px->port);
        f[0] = px->scheme ? px->scheme : "http";
        f[1] = px->username ? px->username : "";
        f[2] = px->password ? px->password : "";
        f[3] = px->host ? px->host : "";
        f[4] = port;
        if (!zuh_buf_init(&b, 128, 0)) { zuh_pool_key_free(k); return 0; }
        for (i = 0; i < 5; i++) {
            if (!zuh_buf_append_u64(&b, (uint64_t)strlen(f[i])) ||
                !zuh_buf_append_byte(&b, ':') || !zuh_buf_append_str(&b, f[i])) {
                zuh_buf_free(&b); zuh_pool_key_free(k); return 0;
            }
        }
        if (!zuh_buf_cstr(&b, &joined)) { zuh_buf_free(&b); zuh_pool_key_free(k); return 0; }
        k->proxy = dup_str(joined);
        zuh_buf_free(&b);
        if (!k->proxy) { zuh_pool_key_free(k); return 0; }
    }
    return 1;
}

/* --- §26.3 may this connection go back? ----------------------------------
 *
 * §26.3's rule is "the safe default is to close", so this returns a NAMED
 * reason rather than a bool and every path that is not provably clean lands
 * on one of them. The order matters: a failed request is judged by WHY it
 * failed before the framing is consulted, because a timeout mid-body and a
 * clean close-framed body are both "no reuse" for very different reasons and
 * the §42 trace should say which. */
/* Hand the connection back to the pool, or close it when there is no pool.
 * zuh_pool_release takes ownership either way, so this is the ONLY place the
 * happy path disposes of a stream and the caller never decides who frees. */
static void done_with_stream(const zuh_get_opts *o, const zuh_uri *u,
                             const zuh_proxy *px, zuh_stream *s, zuh_reuse r) {
    zuh_pool_key key;
    if (!s) return;
    if (o->pool && zuh_engine_pool_key(&key, u, o, px)) {
        zuh_pool_release(o->pool, &key, s, r);
        zuh_pool_key_free(&key);
        return;
    }
    /* No pool, or the key could not be built (OOM). Either way the safe
     * answer is §26.3's: close it. */
    zuh_stream_close(s);
    zuh_stream_free(s);
}

/* Record the negotiated TLS parameters on the result. Runs for a pooled
 * connection as well as a fresh one: the handshake happened on some earlier
 * request, but the session is the same one this response came over, so
 * reporting it is not a courtesy — a caller that logs tls_version would
 * otherwise see NULL on exactly the requests that reused a connection. */
static void record_tls_info(zuh_stream *s, zuh_result *res) {
    zuh_tls_info info;
    if (!zuh_tls_get_info(s, &info)) return;
    zuh_free(res->tls_version); zuh_free(res->tls_cipher);
    zuh_free(res->trust_backend);
    res->tls_version   = dup_str(info.protocol);
    res->tls_cipher    = dup_str(info.cipher);
    res->trust_backend = dup_str(info.trust_backend);
}

/* §20.3: open the tunnel. CONNECT is written to the proxy, its response is
 * parsed with full §18 strictness, and only a 2xx yields a usable socket.
 *
 * A non-2xx is frequently the ONLY diagnostic a user gets in a corporate
 * environment, so the proxy's own status reaches them (zu_proxy_connect_
 * response builds that message) rather than being flattened into "connection
 * failed". */
static zuh_code proxy_tunnel(zuh_stream *tcp, const zuh_proxy *px,
                            const zuh_uri *target, zuh_deadline dl,
                            zuh_error *err) {
    zuh_buffer req, raw;
    zuh_code rc;
    int status = 0;
    size_t consumed = 0;

    if (!zuh_buf_init(&req, 256, 0)) return ZUH_ERR_NOMEM;
    rc = zuh_proxy_connect_request(px, target, &req, err);
    if (rc == ZUH_OK && !zuh_stream_write_all(tcp, req.data, req.len, dl, err))
        rc = err->code ? err->code : ZUH_ERR_IO;
    zuh_buf_free(&req);
    if (rc != ZUH_OK) return rc;

    if (!zuh_buf_init(&raw, 1024, ZUH_MAX_HEADER_BYTES)) return ZUH_ERR_NOMEM;
    for (;;) {
        char chunk[ZUH_READ_CHUNK];
        zuh_ssize n;

        rc = zuh_proxy_connect_response((const char *)raw.data, raw.len,
                                       &consumed, &status, err);
        if (rc != ZUH_ERR_WOULDBLOCK) break;
        if (raw.len >= ZUH_MAX_HEADER_BYTES) {
            zuh_error_set(err, ZUH_ERR_PROXY, ZUH_PHASE_CONNECT,
                         "proxy CONNECT response header block is too large");
            rc = ZUH_ERR_PROXY;
            break;
        }
        n = zuh_stream_read(tcp, chunk, sizeof chunk, dl, err);
        if (n < 0) { rc = err->code; break; }
        if (n == 0) {
            zuh_error_set(err, ZUH_ERR_PROXY, ZUH_PHASE_CONNECT,
                         "proxy closed the connection during CONNECT");
            rc = ZUH_ERR_PROXY;
            break;
        }
        if (!zuh_buf_append(&raw, chunk, (size_t)n)) { rc = ZUH_ERR_NOMEM; break; }
    }
    /* Anything the proxy sent past the CONNECT response would be TLS bytes
     * from the origin, which we have not read yet. A well-behaved proxy sends
     * nothing; one that does has desynchronised the tunnel before it started,
     * and continuing would splice its bytes into the handshake. */
    if (rc == ZUH_OK && raw.len > consumed) {
        zuh_error_set(err, ZUH_ERR_PROXY, ZUH_PHASE_CONNECT,
                     "proxy sent %lu unexpected bytes after CONNECT",
                     (unsigned long)(raw.len - consumed));
        rc = ZUH_ERR_PROXY;
    }
    zuh_buf_free(&raw);
    return rc;
}

/* §14 configuration for one hop: the caller's zu_tls() settings, then the
 * two fields that have their own merged policy argument (§31.9) win, so there
 * is one source of truth for "is this connection verified". */
static void tls_cfg_for(zuh_tls_config *cfg, const zuh_get_opts *o) {
    if (o->tls) *cfg = *o->tls; else zuh_tls_config_init(cfg);
    cfg->verify_peer     = o->verify;
    cfg->verify_hostname = o->verify;
    if (o->ca_file) { cfg->ca_file = o->ca_file; cfg->source = ZUH_TRUST_FILE; }
    /* §65.1, D-90: the offer follows zu_client(http2 = ). */
    cfg->alpn = zuh_h2_alpn_for(o->http2);
}

/* D-71: a backend that dials opens HTTPS itself -- name resolution, TCP, the
 * CONNECT tunnel and TLS -- so the engine hands it the hop and the chosen
 * proxy instead of a socket. zuhttp still decides per hop whether to proxy
 * (§20.1). */
static zuh_code open_dialled(zuh_stream **out, const zuh_uri *u,
                             const zuh_get_opts *o, const zuh_proxy *px,
                             zuh_deadline dl, const zuh_net_opts *nopts,
                             zuh_result *res, zuh_error *err) {
    zuh_tls_config cfg;
    zuh_stream *tls = NULL;
    zuh_millis t0 = zuh_now_ms();
    zuh_code rc;
    int via_proxy = px && px->in_use;
    char ip[64];

    /* The backend writes dns, connect and tls events itself, at the moments
     * its establishment report says they happened. */
    tls_cfg_for(&cfg, o);
    rc = zuh_tls_dial(&tls, u->host, u->port, via_proxy ? px : NULL, &cfg, dl,
                      nopts, err);
    if (rc != ZUH_OK) return rc;
    /* The backend fills dns, connect and tls from what it can see; if it
     * could not split them, the whole open counts as tls. */
    if (res->timings.tls < 0) res->timings.tls = (long)(zuh_now_ms() - t0);
    if (zuh_tls_peer_ip(tls, ip, sizeof ip)) {
        zuh_free(res->remote_ip);
        res->remote_ip = dup_str(ip);
    }
    res->reused_connection = 0;
    res->proxy_used = via_proxy;
    record_tls_info(tls, res);
    *out = tls;
    return ZUH_OK;
}

static zuh_code open_stream(zuh_stream **out, const zuh_uri *u,
                           const zuh_get_opts *o, const zuh_proxy *px,
                           zuh_deadline dl, zuh_result *res, zuh_error *err) {
    zuh_net_opts nopts;
    zuh_stream *tcp = NULL;
    zuh_code rc;
    int via_proxy = px && px->in_use;
    zuh_millis t_open = zuh_now_ms();

    /* §26: a live connection for this exact key, if the pool has one. The
     * pool has already run the fork guard, the idle-timeout check and the
     * §26.2 liveness probe by the time it answers, so a non-NULL return is
     * usable as-is. */
    if (o->pool) {
        zuh_pool_key key;
        zuh_stream *reused = NULL;
        if (!zuh_engine_pool_key(&key, u, o, px)) return ZUH_ERR_NOMEM;
        reused = zuh_pool_acquire_by(o->pool, &key, dl);
        zuh_pool_key_free(&key);
        if (reused) {
            char ip[64];
            /* An HTTP/2 connection keeps its TLS and its address on the
             * transport it wraps (§65.2). */
            zuh_stream *t = zuh_h2_transport(reused);
            if (u->is_https) record_tls_info(t, res);
            res->reused_connection = 1;   /* §35.2 */
            /* §35.2 describes the connection this response arrived on, which
             * a reuse is as much as a fresh dial: the pool key includes the
             * proxy (§26.1), so how it was opened is still how it runs. */
            res->proxy_used = via_proxy;
            if (zuh_tls_peer_ip(t, ip, sizeof ip) ||
                zuh_net_peer_ip(t, ip, sizeof ip)) {
                zuh_free(res->remote_ip);
                res->remote_ip = dup_str(ip);
            }
            /* §35.1 leaves dns/connect/tls at -1 here, which is the honest
             * answer for a pooled connection: those phases did not happen on
             * this request. Reporting 0 would claim they were instantaneous. */
            zuh_trace_add(o->trace, ZUH_EV_CONNECTION_REUSED, u->host, 0);
            *out = reused;
            return ZUH_OK;
        }
    }

    zuh_net_opts_init(&nopts);
    nopts.tick     = o->tick;
    nopts.tick_ctx = o->tick_ctx;
    nopts.trace    = o->trace;
    nopts.timings  = &res->timings;

    /* The dial seam (D-72) is the engine's own TCP, so a test that sets it
     * keeps the wrapping path whatever the backend. */
    if (u->is_https && !o->dial && zuh_tls_available()
        && (zuh_tls_backend_caps() & ZUH_TLS_CAP_DIALS))
        return open_dialled(out, u, o, px, dl, &nopts, res, err);

    /* Through a proxy the socket goes to the PROXY, not the origin. For plain
     * HTTP that is the whole of it — the request then uses absolute-form
     * (§20.3) and the proxy does the rest. */
    {
        const char *host = via_proxy ? px->host : u->host;
        uint16_t    port = via_proxy ? px->port : u->port;
        rc = o->dial ? o->dial(o->dial_ctx, host, port, &tcp, err)
                     : zuh_net_connect(&tcp, host, port, dl, &nopts, err);
    }
    if (rc != ZUH_OK) return rc;
    /* dns and connect are filled by zu_net, which is the only layer that can
     * see the boundary between them. */
    (void)t_open;

    /* §35.2 remote_ip, taken from the TCP stream before TLS wraps it — the
     * outer stream has no address of its own. Through a proxy this is the
     * PROXY's address, which is the honest answer: it is who we are talking
     * to, and the origin's address is something only the proxy knows. */
    {
        char ip[64];
        if (zuh_net_peer_ip(tcp, ip, sizeof ip)) {
            zuh_free(res->remote_ip);
            res->remote_ip = dup_str(ip);
        }
    }
    res->reused_connection = 0;
    res->proxy_used = via_proxy;

    if (!u->is_https) { *out = tcp; return ZUH_OK; }

    /* HTTPS through a proxy tunnels first, and the TLS handshake below then
     * runs against the ORIGIN's hostname over that tunnel — which is what
     * makes the proxy unable to see or forge the origin's certificate. */
    if (via_proxy) {
        rc = proxy_tunnel(tcp, px, u, dl, err);
        if (rc != ZUH_OK) { drop_stream(tcp); return rc; }
    }

    if (!zuh_tls_available()) {
        zuh_error_set(err, ZUH_ERR_TLS, ZUH_PHASE_TLS,
                     "this build has no TLS backend, so https:// is unavailable");
        drop_stream(tcp);
        return ZUH_ERR_TLS;
    }
    {
        zuh_tls_config cfg;
        zuh_stream *tls = NULL;

        tls_cfg_for(&cfg, o);
        {
            zuh_millis t_tls = zuh_now_ms();
            zuh_trace_add(o->trace, ZUH_EV_TLS_START, u->host, 0);
            rc = zuh_tls_connect(&tls, tcp, u->host, &cfg, dl, err);
            res->timings.tls = (long)(zuh_now_ms() - t_tls);
        }
        if (rc != ZUH_OK) {
            /* zuh_tls_connect does not take ownership of `inner` on failure,
             * so the TCP stream is still ours to close and free (S7). */
            drop_stream(tcp);
            return rc;
        }
        record_tls_info(tls, res);
        zuh_trace_add(o->trace, ZUH_EV_TLS_DONE,
                     res->tls_version ? res->tls_version : "tls", 0);
        *out = tls;
        return ZUH_OK;
    }
}

/* Read until the header block is complete. Leftover body bytes are left in
 * `raw` past `consumed`. */
static zuh_code read_headers(zuh_stream *s, zuh_buffer *raw, zuh_response *resp,
                            size_t *consumed, zuh_deadline dl, zuh_error *err) {
    size_t last_len = 0;
    for (;;) {
        char chunk[ZUH_READ_CHUNK];
        zuh_ssize n;
        zuh_code rc = zuh_response_parse(resp, (const char *)raw->data, raw->len,
                                       last_len, consumed, err);
        if (rc != ZUH_ERR_WOULDBLOCK) return rc;
        last_len = raw->len;

        if (raw->len >= ZUH_MAX_HEADER_BYTES) {
            zuh_error_set(err, ZUH_ERR_BODY_LIMIT, ZUH_PHASE_READ,
                         "response header block exceeds %u bytes",
                         (unsigned)ZUH_MAX_HEADER_BYTES);
            return ZUH_ERR_BODY_LIMIT;
        }
        n = zuh_stream_read(s, chunk, sizeof chunk, dl, err);
        if (n < 0) return err->code;
        if (n == 0) {
            zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_READ,
                         "connection closed before the response headers ended");
            return ZUH_ERR_PARSE;
        }
        if (!zuh_buf_append(raw, chunk, (size_t)n)) return ZUH_ERR_NOMEM;
    }
}

/* Read the body according to the §18.1 framing decision. `seed` is whatever
 * already arrived alongside the headers. */
zuh_code zuh_engine_get(zuh_result *out, const char *url,
                      const zuh_get_opts *o, zuh_error *err) {
    return zuh_engine_perform(out, url, NULL, o, err);
}

/* RFC 9110 §8.6: the methods that define a meaning for request content.
 * DELETE and the safe methods do not, so a bodiless one says nothing. */
/* A host name is at most 253 characters on the wire (RFC 1035), and the
 * fixed buffers downstream (the Host header, the redirect trail's origin)
 * hold a little more than that. Refused as the URL error it is, on every
 * hop: a buffer that would not fit it used to surface as "out of memory"
 * (#197). */
#define ZUH_MAX_HOST_LEN 253
static zuh_code check_host(const zuh_uri *u, zuh_error *err) {
    size_t n = u->host ? strlen(u->host) : 0;
    if (n <= ZUH_MAX_HOST_LEN) return ZUH_OK;
    zuh_error_set(err, ZUH_ERR_URL, ZUH_PHASE_NONE,
                 "host name too long (%lu characters; the limit is %u)",
                 (unsigned long)n, (unsigned)ZUH_MAX_HOST_LEN);
    return ZUH_ERR_URL;
}

static int method_expects_content(const char *method) {
    return method && (strcmp(method, "POST") == 0 || strcmp(method, "PUT") == 0 ||
                      strcmp(method, "PATCH") == 0);
}

/* RFC 9112 §6.2 (D-78): the body decides the framing. A caller's
 * Content-Length used to go out as written, so "1" on a five-byte body sent
 * five bytes the server would read as one plus the start of the next
 * request; a caller's Transfer-Encoding went out beside the generated
 * Content-Length over a body that was never chunked. Either leaves the
 * connection out of step with the server. A Content-Length that matches the
 * body is harmless and is accepted — the engine emits its own either way. */
static zuh_code check_caller_framing(const zuh_req_spec *req, size_t body_len,
                                    int streamed, zuh_error *err) {
    size_t i;
    if (!req) return ZUH_OK;
    for (i = 0; i < req->n_headers; i++) {
        const char *name = req->header_names ? req->header_names[i] : NULL;
        const char *v    = req->header_values ? req->header_values[i] : NULL;
        if (!name) continue;
        if (zuh_ascii_casecmp(name, "Transfer-Encoding") == 0) {
            zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_NONE,
                         "a Transfer-Encoding header cannot be set: zuhttp "
                         "frames the body itself, with Content-Length");
            return ZUH_ERR_PARSE;
        }
        if (zuh_ascii_casecmp(name, "Content-Length") == 0) {
            uint64_t n = 0;
            int digits = 0, ok = 1;
            if (streamed) {
                /* D-95: a streamed body has no length to match, so the
                 * message says that rather than "the 0-byte body" (#183). */
                zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_NONE,
                             "a Content-Length header cannot be set on a "
                             "streamed body, which carries no length: zuhttp "
                             "sends it chunked, or as HTTP/2 DATA");
                return ZUH_ERR_PARSE;
            }
            const char *c = v ? v : "";
            while (*c == ' ' || *c == '\t') c++;
            for (; *c >= '0' && *c <= '9'; c++, digits++) {
                if (n > (UINT64_MAX - 9) / 10) { ok = 0; break; }
                n = n * 10 + (uint64_t)(*c - '0');
            }
            while (*c == ' ' || *c == '\t') c++;
            if (!ok || !digits || *c || n != (uint64_t)body_len) {
                zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_NONE,
                             "a Content-Length header of '%.40s' does not "
                             "match the %lu-byte body",
                             v ? v : "", (unsigned long)body_len);
                return ZUH_ERR_PARSE;
            }
        }
    }
    return ZUH_OK;
}

/* §17.1 and D-85: every caller header is checked once, before connecting,
 * so a malformed one costs no connection. The message names the header and
 * the rule, never the value, which may be a credential (§42); a name is
 * echoed only if it is a short token, so the message cannot carry the CR/LF
 * it refuses. */
static zuh_code check_caller_headers(const zuh_req_spec *req, zuh_error *err) {
    size_t i, n = req ? req->n_headers : 0;
    for (i = 0; i < n; i++) {
        const char *nm = req->header_names[i];
        const char *v  = req->header_values[i];
        size_t nlen = nm ? strlen(nm) : 0;
        if (!zuh_header_name_valid(nm, nlen)) {
            zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_NONE,
                         "request header %lu has an invalid name: "
                         "a name must be an RFC 7230 token (§17.1)",
                         (unsigned long)i + 1);
            return ZUH_ERR_PARSE;
        }
        if (!zuh_header_value_valid(v, v ? strlen(v) : 0)) {
            if (nlen <= 64)
                zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_NONE,
                             "request header `%s` has an invalid value: a value "
                             "must not contain CR, LF, NUL or other control "
                             "characters (§17.1)", nm);
            else
                zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_NONE,
                             "request header %lu has an invalid value: a value "
                             "must not contain CR, LF, NUL or other control "
                             "characters (§17.1)", (unsigned long)i + 1);
            return ZUH_ERR_PARSE;
        }
    }
    return ZUH_OK;
}

/* The hop loop. `trail` is §19.4's record of every (method, URL) requested
 * so far; zuh_engine_perform() owns it, so the many exits below need not. */
/* §65.1: which protocol this hop speaks, decided once the connection is
 * open. A pooled HTTP/2 connection already is one; a TLS connection is
 * HTTP/2 when ALPN chose "h2"; http:// is h2c only when the client requires
 * HTTP/2 and the connection is direct. REQUIRED refuses anything else here,
 * before a byte of the request is written, and closes the connection. On
 * success `*s` may have been replaced by the HTTP/2 wrapper that owns it. */
static zuh_code choose_protocol(zuh_stream **s, const zuh_uri *u,
                                const zuh_get_opts *o, const zuh_proxy *px,
                                int *use_h2, zuh_error *err) {
    zuh_tls_info ti;
    zuh_stream *h2 = NULL;
    zuh_code rc;
    int want;

    *use_h2 = 0;
    if (zuh_h2_is(*s)) { *use_h2 = 1; return ZUH_OK; }
    if (u->is_https)
        want = zuh_tls_get_info(*s, &ti) && zuh_h2_alpn_is_h2(ti.alpn);
    else
        want = o->http2 == ZUH_H2_REQUIRED && !(px && px->in_use);
    if (!want) {
        if (o->http2 != ZUH_H2_REQUIRED) return ZUH_OK;
        if (u->is_https)
            zuh_error_set(err, ZUH_ERR_CONNECT, ZUH_PHASE_CONNECT,
                          "HTTP/2 is required, but %.200s did not negotiate it", u->host);
        else
            zuh_error_set(err, ZUH_ERR_CONNECT, ZUH_PHASE_CONNECT,
                          "HTTP/2 is required, but cleartext HTTP/2 to %.200s "
                          "cannot go through an HTTP proxy", u->host);
        zuh_stream_close(*s); zuh_stream_free(*s); *s = NULL;
        return ZUH_ERR_CONNECT;
    }
    rc = zuh_h2_wrap(&h2, *s, ZUH_MAX_HEADER_BYTES, err);
    if (rc != ZUH_OK) { zuh_stream_close(*s); zuh_stream_free(*s); *s = NULL; return rc; }
    *s = h2;
    *use_h2 = 1;
    return ZUH_OK;
}

/* §26.3 for an HTTP/2 exchange. The §18.1 framing rules do not apply
 * (§65.2): the stream ended or it did not, and the session knows whether the
 * connection can carry another one. */
static zuh_reuse h2_reuse(zuh_code rc, zuh_stream *s) {
    if (rc == ZUH_ERR_TIMEOUT || rc == ZUH_ERR_CANCELLED || rc == ZUH_ERR_INTERRUPTED)
        return ZUH_NOREUSE_CANCELLED;
    if (rc != ZUH_OK || !zuh_h2_reusable(s)) return ZUH_NOREUSE_BODY_INCOMPLETE;
    return ZUH_REUSE_OK;
}

/* --- §65.4 a body the caller pulls ------------------------------------- */

struct zuh_open_body {
    zuh_stream     *s;
    int             h2;
    zuh_pool       *pool;          /* NULL: close at the end */
    zuh_pool_key    key;
    int             have_key;
    zuh_reuse       reuse_if_ended; /* §26.3, decided from the headers */
    zuh_body_reader rd;            /* HTTP/1.1 framing */
    zuh_body_pipe   pipe;
    zuh_sink        sink;          /* into `staged` */
    zuh_buffer      staged;        /* decoded, not yet handed out */
    size_t          staged_off;
    long            timeout_ms;
    int             ended, aborted, failed;
    /* §65.7: a request body still being sent while the response streams
     * (full duplex); released when this body is freed. */
    zuh_body_source src;
};

/* Give the connection back, or close it, exactly once. */
static void open_body_release(zuh_open_body *b, zuh_reuse r) {
    if (!b->s) return;
    if (b->pool && b->have_key) zuh_pool_release(b->pool, &b->key, b->s, r);
    else { zuh_stream_close(b->s); zuh_stream_free(b->s); }
    b->s = NULL;
}

static zuh_code open_body_new(zuh_open_body **out, zuh_stream *s, int h2,
                              const zuh_framing *fr, const char *seed, size_t seed_len,
                              zuh_headers *h, int minor, uint64_t cap, int no_decode,
                              const zuh_get_opts *o, const zuh_uri *u,
                              const zuh_proxy *px, zuh_error *err) {
    zuh_open_body *b;
    zuh_code rc;
    /* §65.7: the response can arrive before the in-memory request body has
     * all gone out, and the caller's buffer does not outlive this call. */
    if (h2 && (rc = zuh_h2_own_body(s, err)) != ZUH_OK) return rc;
    b = (zuh_open_body *)zuh_calloc(1, sizeof *b);
    if (!b || !zuh_buf_init(&b->staged, 0, (size_t)-1)) {
        zuh_free(b);
        zuh_error_set(err, ZUH_ERR_NOMEM, ZUH_PHASE_READ, "out of memory");
        return ZUH_ERR_NOMEM;
    }
    zuh_sink_memory_init(&b->sink, &b->staged);
    rc = zuh_body_pipe_init(&b->pipe, &b->sink, h, no_decode, cap, err);
    if (rc == ZUH_OK && !h2) {
        rc = zuh_body_reader_init(&b->rd, fr, seed, seed_len, err);
        if (rc != ZUH_OK) zuh_body_pipe_free(&b->pipe);
    }
    if (rc != ZUH_OK) { zuh_buf_free(&b->staged); zuh_free(b); return rc; }
    b->h2 = h2;
    /* §65.4: each read gets the request's `timeout` afresh, which is not
     * the attempt's share of the total budget that `timeout_ms` carries
     * (review #181). */
    b->timeout_ms = o->body_timeout_ms > 0 ? o->body_timeout_ms
                  : o->timeout_ms > 0      ? o->timeout_ms : ZUH_DEFAULT_TIMEOUT_MS;
    b->reuse_if_ended = h2 ? ZUH_REUSE_OK : zuh_reuse_decide(ZUH_OK, fr, h, minor);
    /* The key is built now, while the hop's options are in scope; the pool
     * outlives any one request (§26.5), and the R layer keeps it alive for
     * as long as this body is (init.c). */
    if (o->pool && zuh_engine_pool_key(&b->key, u, o, px)) {
        b->pool = o->pool;
        b->have_key = 1;
    }
    b->s = s;
    *out = b;
    return ZUH_OK;
}

zuh_code zuh_open_body_read(zuh_open_body *b, zuh_buffer *out, size_t n,
                            zuh_error *err) {
    return zuh_open_body_read_within(b, out, n, 0, err);
}

zuh_code zuh_open_body_read_within(zuh_open_body *b, zuh_buffer *out, size_t n,
                                   long timeout_ms, zuh_error *err) {
    zuh_deadline dl;
    if (!b || b->failed) {
        zuh_error_set(err, ZUH_ERR_IO, ZUH_PHASE_READ, "the response body failed earlier");
        return ZUH_ERR_IO;
    }
    if (b->aborted) {
        zuh_error_set(err, ZUH_ERR_CANCELLED, ZUH_PHASE_READ, "the response body was aborted");
        return ZUH_ERR_CANCELLED;
    }
    dl = zuh_deadline_in(timeout_ms > 0 ? timeout_ms : b->timeout_ms);
    while (b->staged.len == b->staged_off && !b->ended) {
        zuh_code rc;
        b->staged.len = 0;
        b->staged_off = 0;
        if (b->h2) {
            int done = 0;
            rc = zuh_h2_body_step(b->s, &b->pipe, &done, dl, err);
            if (rc == ZUH_OK) b->ended = done;
        } else {
            rc = zuh_body_reader_step(&b->rd, b->s, &b->pipe, dl, err);
            if (rc == ZUH_OK) b->ended = b->rd.done;
        }
        if (rc != ZUH_OK) {
            b->failed = 1;
            open_body_release(b, rc == ZUH_ERR_CANCELLED || rc == ZUH_ERR_TIMEOUT
                                     ? ZUH_NOREUSE_CANCELLED : ZUH_NOREUSE_BODY_INCOMPLETE);
            return rc;
        }
        if (b->ended) {
            zuh_reuse r = b->h2 ? (zuh_h2_reusable(b->s) ? ZUH_REUSE_OK
                                                       : ZUH_NOREUSE_BODY_INCOMPLETE)
                                : b->reuse_if_ended;
            if (r == ZUH_REUSE_OK && b->pipe.surplus > 0) r = ZUH_NOREUSE_FRAMING;
            open_body_release(b, r);
        }
    }
    {
        size_t avail = b->staged.len - b->staged_off;
        if (n > avail) n = avail;
        if (n && !zuh_buf_append(out, b->staged.data + b->staged_off, n)) {
            zuh_error_set(err, ZUH_ERR_NOMEM, ZUH_PHASE_READ, "out of memory");
            return ZUH_ERR_NOMEM;
        }
        b->staged_off += n;
    }
    return ZUH_OK;
}

void zuh_open_body_abort(zuh_open_body *b) {
    if (!b || b->ended || b->aborted || b->failed) return;
    b->aborted = 1;
    if (b->h2 && b->s) {
        zuh_h2_cancel(b->s, zuh_deadline_in(1000));
        open_body_release(b, zuh_h2_reusable(b->s) ? ZUH_REUSE_OK : ZUH_NOREUSE_CANCELLED);
    } else {
        open_body_release(b, ZUH_NOREUSE_CANCELLED);
    }
}

int zuh_open_body_done(const zuh_open_body *b) {
    /* Ended means the wire is done; done means the caller has had it all. */
    return !b || b->aborted || b->failed ||
           (b->ended && b->staged_off == b->staged.len);
}

int zuh_open_body_ended_clean(const zuh_open_body *b) {
    return b && !b->aborted && !b->failed && b->ended && b->staged_off == b->staged.len;
}

int zuh_open_body_busy(const zuh_open_body *b) {
    return b && b->h2 && b->s && zuh_h2_in_source(b->s);
}

const zuh_headers *zuh_open_body_trailers(const zuh_open_body *b) {
    return b ? &b->pipe.trailers : NULL;
}

void zuh_open_body_free(zuh_open_body *b) {
    if (!b) return;
    zuh_open_body_abort(b);
    open_body_release(b, ZUH_NOREUSE_CANCELLED);
    if (!b->h2) zuh_body_reader_free(&b->rd);
    zuh_body_pipe_free(&b->pipe);
    zuh_buf_free(&b->staged);
    if (b->have_key) zuh_pool_key_free(&b->key);
    if (b->src.release) b->src.release(b->src.ctx);
    zuh_free(b);
}

void *zuh_open_body_source_ctx(const zuh_open_body *b) {
    return b ? b->src.ctx : NULL;
}

static zuh_code perform_hops(zuh_result *out, const char *url,
                             const zuh_req_spec *req, const zuh_get_opts *o,
                             zuh_redirect_trail *trail, zuh_body_source *src,
                             zuh_error *err) {
    zuh_get_opts defaults;
    /* §65.7: a streamed body is sent on the first hop only; it cannot be
     * replayed, so a redirect that would resend it is refused below. */
    int src_live = src && src->next;
    zuh_uri cur;
    zuh_deadline total;
    size_t hops = 0;
    zuh_code rc;
    zuh_sink mem_sink;
    zuh_sink *body_sink = NULL;
    zuh_env  sysenv;
    zuh_millis t_start;
    const char *method = (req && req->method) ? req->method : "GET";
    const void *body   = req ? req->body : NULL;
    size_t body_len    = req ? req->body_len : 0;
    size_t n_hdr       = req ? req->n_headers : 0;
    int is_head        = (strcmp(method, "HEAD") == 0);
    /* §19.2: set once a redirect crosses origins, and never cleared — a chain
     * that later returns to the first origin does not get the credentials
     * back, because the hop in between chose where to send us. */
    int strip_creds    = 0;

    if (!out || !url) return ZUH_ERR_URL;
    zuh_env_system(&sysenv);
    t_start = zuh_now_ms();
    zuh_result_init(out);
    /* Through zuh_trace_add_url, not zuh_trace_add: this is the caller's URL
     * verbatim, so it is the one most likely to carry userinfo or a secret
     * query parameter (§42.1). */
    zuh_trace_add_url(o ? o->trace : NULL, ZUH_EV_REQUEST_START,
                     o ? o->redact : NULL, url, 0);
    if (!o) { zuh_get_opts_init(&defaults); o = &defaults; }

    /* §24.1: one deadline for the whole operation, redirects included. */
    total = zuh_deadline_in(o->timeout_ms > 0 ? o->timeout_ms : ZUH_DEFAULT_TIMEOUT_MS);

    rc = zuh_uri_parse(&cur, url, url + strlen(url));
    if (rc == ZUH_ERR_NOMEM) {
        zuh_error_set(err, rc, ZUH_PHASE_NONE, "out of memory");
        return rc;
    }
    if (rc != ZUH_OK) {
        /* §42.2: the message is an egress like the URL field, and the URL
         * that failed to parse is the one most likely to be pasted with its
         * credentials. The redactor works on unparsed text for this case. */
        zuh_buffer shown;
        const char *txt = NULL;
        if (zuh_buf_init(&shown, 128, 0) &&
            zuh_redact_url(o->redact, url, strlen(url), &shown) &&
            zuh_buf_cstr(&shown, &txt))
            zuh_error_set(err, ZUH_ERR_URL, ZUH_PHASE_NONE, "not a usable URL: %s", txt);
        else
            zuh_error_set(err, ZUH_ERR_URL, ZUH_PHASE_NONE, "not a usable URL");
        zuh_buf_free(&shown);
        return ZUH_ERR_URL;
    }

    rc = check_host(&cur, err);
    if (rc == ZUH_OK) rc = check_caller_framing(req, body_len, src_live, err);
    if (rc == ZUH_OK) rc = check_caller_headers(req, err);
    if (rc != ZUH_OK) { zuh_uri_free(&cur); zuh_result_free(out); return rc; }
    rc = zuh_redirect_trail_add(trail, method, &cur);
    if (rc != ZUH_OK) { zuh_uri_free(&cur); zuh_result_free(out); return rc; }

    /* §27: where the final body goes. `o->sink` is the caller's; without one
     * the body is buffered into the result, which is the pre-S17 behaviour and
     * still what zu_resp_raw() needs. mem_sink always exists because followed
     * redirect bodies use it whatever the caller chose (§19.5). */
    zuh_sink_memory_init(&mem_sink, &out->body);
    body_sink = o->sink ? o->sink : &mem_sink;

    for (;;) {
        zuh_stream *s = NULL;
        zuh_request rq;
        zuh_response resp;
        size_t hi;
        zuh_buffer wire, raw, absform, auth;
        int have_absform = 0;
        zuh_proxy px;
        zuh_body_pipe pipe;
        zuh_sink *hop_sink = NULL;
        size_t consumed = 0;
        size_t sent_bytes = 0;
        int combine = 0;            /* the body rides in the header write */
        int may_follow = 0;

        int use_h2 = 0;
        int streamed = 0;
        uint64_t surplus = 0;
        char hosthdr[300];

        memset(&pipe, 0, sizeof pipe);
        /* Pre-set to the §26.3 safe default. `fr` is only really filled once
         * zuh_response_decide_framing() succeeds, so every path that fails
         * before that point must still give reuse_after() something that
         * means "do not reuse" rather than whatever was on the stack. */
        zuh_framing fr = { ZUH_FRAME_UNTIL_CLOSE, 0, 0 };

        /* Resolved per hop, not once: a redirect may cross from a proxied
         * host to a NO_PROXY one (or the reverse), and reusing the first
         * hop's decision would send the second hop the wrong way (§20.2). */
        zuh_proxy_init(&px);
        rc = zuh_proxy_resolve(&px, &cur, o->env ? o->env : &sysenv,
                              o->proxy, o->proxy_set, err);
        if (rc != ZUH_OK) { zuh_proxy_free(&px); zuh_uri_free(&cur); zuh_result_free(out); return rc; }

        rc = open_stream(&s, &cur, o, &px, total, out, err);
        if (rc == ZUH_OK) rc = choose_protocol(&s, &cur, o, &px, &use_h2, err);
        if (rc != ZUH_OK) {
            zuh_proxy_free(&px); zuh_uri_free(&cur); zuh_result_free(out);
            return rc;
        }

        /* --- send --- */
        zuh_request_init(&rq);
        rq.method = method;
        rq.target = cur.path_query;
        /* §17.2: without a pool this connection is closed after the
         * response (done_with_stream), so promising keep-alive would only
         * leave the server holding it until its own idle timeout. */
        rq.close_connection = o->pool == NULL;
        if (!host_header(&cur, hosthdr, sizeof hosthdr)) {
            zuh_error_set(err, ZUH_ERR_URL, ZUH_PHASE_NONE, "host name too long");
            zuh_request_free(&rq); drop_stream(s);
            zuh_uri_free(&cur); zuh_result_free(out); zuh_proxy_free(&px);
            return ZUH_ERR_URL;
        }
        rq.host   = hosthdr;
        rq.form   = ZUH_TARGET_ORIGIN;
        /* §20.3: plain HTTP through a proxy uses absolute-form, so the proxy
         * knows which origin to reach. HTTPS does not — by then we are inside
         * a CONNECT tunnel talking to the origin itself, and an absolute-form
         * request there would be both wrong and a disclosure. */
        if (px.in_use && !cur.is_https) {
            if (!zuh_buf_init(&absform, 128, 0)) {   /* bounded by the URI (#174) */
                zuh_request_free(&rq); drop_stream(s);
                zuh_uri_free(&cur); zuh_result_free(out); zuh_proxy_free(&px);
                return ZUH_ERR_NOMEM;
            }
            have_absform = 1;
            if (!zuh_proxy_absolute_form(&cur, &absform) ||
                !zuh_buf_cstr(&absform, &rq.target)) {
                zuh_buf_free(&absform);
                zuh_request_free(&rq); drop_stream(s);
                zuh_uri_free(&cur); zuh_result_free(out); zuh_proxy_free(&px);
                return ZUH_ERR_NOMEM;
            }
            rq.form = ZUH_TARGET_ABSOLUTE;

            /* §20.4: the header goes on the connection TO THE PROXY, which
             * for absolute-form is this very request. Proxy-Authorization is
             * hop-by-hop, so the proxy consumes it and does not forward it to
             * the origin — and because the proxy is re-resolved per hop, a
             * redirect onto a NO_PROXY host simply never reaches this branch
             * and so cannot carry the credential onward (§19.2). */
            if (px.username) {
                const char *v = NULL;
                /* Failing to build the credential fails the request: sending
                 * it without one would only earn a 407 and hide the cause. */
                rc = ZUH_ERR_NOMEM;
                if (zuh_buf_init(&auth, 64, 4096)) {
                    if (zuh_proxy_auth_value(&px, &auth) && zuh_buf_cstr(&auth, &v))
                        rc = zuh_headers_add_str(&rq.headers, "Proxy-Authorization", v);
                    zuh_buf_free(&auth);
                }
                if (rc != ZUH_OK) {
                    if (have_absform) zuh_buf_free(&absform);
                    zuh_request_free(&rq); drop_stream(s);
                    zuh_uri_free(&cur); zuh_result_free(out); zuh_proxy_free(&px);
                    return rc;
                }
            }
        }
        if (src_live) {
            /* D-95: the one request zuhttp chunks (HTTP/1.1; HTTP/2 frames
             * it as DATA), since its length is not known in advance. */
            rq.body = ZUH_BODY_CHUNKED;
        } else if (body_len > 0 || method_expects_content(method)) {
            /* D-100: a bodiless POST, PUT or PATCH says `Content-Length: 0`
             * (RFC 9110 §8.6), as curl and Go do; some servers answer the
             * header's absence with 411. Over HTTP/2 the end-of-stream flag
             * says it, and zuh_h2_begin() adds nothing. */
            rq.body           = ZUH_BODY_LENGTH;
            rq.content_length = (uint64_t)body_len;
        } else {
            rq.body = ZUH_BODY_NONE;
        }
        /* §21.2: a caller who asked for the wire bytes wants the server to
         * stop encoding, not just for us to stop decoding — otherwise
         * "wire bytes" means "gzip, if the server felt like it". An explicit
         * Accept-Encoding from the caller still wins: this is only a default,
         * and it is added before the caller's headers for that reason. */
        if (o->no_decode) {
            rc = zuh_headers_add_str(&rq.headers, "Accept-Encoding", "identity");
            if (rc != ZUH_OK) {
                if (have_absform) zuh_buf_free(&absform);
                zuh_request_free(&rq); drop_stream(s);
                zuh_uri_free(&cur); zuh_result_free(out); zuh_proxy_free(&px);
                return rc;
            }
        }
        /* Caller headers first, so §17.2's defaults only fill what is absent
         * and an explicit Accept or User-Agent wins. Every name and value is
         * validated here, which is what stops a header carrying a CRLF from
         * becoming a second request (§17.1). */
        for (hi = 0; hi < n_hdr; hi++) {
            /* §19.2: after a cross-origin hop the caller's credentials stay
             * behind. This loop rebuilds the headers from the caller's list
             * on every hop, which is why the filter has to be here: until
             * 2026-09-26 nothing read dec.strip_credentials at all, and an
             * Authorization header followed a redirect to any origin. */
            if (strip_creds &&
                zuh_redirect_is_credential_header(o->redact, req->header_names[hi]))
                continue;
            /* D-78: framing comes from this hop's body, which a 303 may have
             * dropped; the caller's length, checked above, is never sent. */
            if (zuh_ascii_casecmp(req->header_names[hi], "Content-Length") == 0)
                continue;
            rc = zuh_headers_add_str(&rq.headers, req->header_names[hi],
                                    req->header_values[hi]);
            if (rc != ZUH_OK) {
                /* check_caller_headers() refused anything malformed before
                 * connecting, so what is left is running out of memory. */
                zuh_error_set(err, rc, ZUH_PHASE_NONE,
                             "request header %lu could not be added",
                             (unsigned long)hi + 1);
                if (have_absform) zuh_buf_free(&absform);
                zuh_request_free(&rq); drop_stream(s);
                zuh_uri_free(&cur); zuh_result_free(out); zuh_proxy_free(&px);
                return rc;
            }
        }
        if (use_h2) {
            /* §65.2: the same request as an HTTP/2 header block. The §17.2
             * defaults are added as for HTTP/1.1, so a request reads the same
             * either way; the driver drops what HTTP/2 forbids (Host becomes
             * :authority). It is sent below, with the wait for the response,
             * by zuh_h2_begin(). */
            rc = zuh_request_add_defaults(&rq, o->user_agent);
            if (rc == ZUH_OK && body_len > 0) {
                char cl[32];
                snprintf(cl, sizeof cl, "%lu", (unsigned long)body_len);
                rc = zuh_headers_add_str(&rq.headers, "Content-Length", cl);
            }
            if (rc != ZUH_OK) {
                if (!err->code)
                    zuh_error_set(err, rc, ZUH_PHASE_NONE, "could not build the request");
                zuh_request_free(&rq); drop_stream(s);
                zuh_uri_free(&cur); zuh_result_free(out); zuh_proxy_free(&px);
                return rc;
            }
        } else {
            if (!zuh_buf_init(&wire, 512, 64 * 1024)) {
                if (have_absform) zuh_buf_free(&absform);
                zuh_request_free(&rq); drop_stream(s);
                zuh_uri_free(&cur); zuh_result_free(out); zuh_proxy_free(&px);
                return ZUH_ERR_NOMEM;
            }
            rc = zuh_request_add_defaults(&rq, o->user_agent);
            if (rc == ZUH_OK) rc = zuh_request_write(&rq, &wire);
            /* The 64 KiB cap is on the header block (§17.1), so running into it
             * is the caller's headers being too large, not memory running out. */
            if (rc == ZUH_ERR_NOMEM && zuh_buf_hit_limit(&wire)) {
                zuh_error_set(err, ZUH_ERR_OVERFLOW, ZUH_PHASE_NONE,
                             "request headers exceed the 64 KiB limit");
                rc = ZUH_ERR_OVERFLOW;
            } else if (rc != ZUH_OK && !err->code) {
                zuh_error_set(err, rc, ZUH_PHASE_NONE, "could not build the request");
            }
            /* A body that fits beside the headers goes in the same write: one
             * write means one TCP segment for a small request. A larger one is
             * written after them, under the same deadline. It used to be appended
             * regardless, so the header cap limited every upload to 64 KiB. */
            /* Decided once, on the header block alone: the append grows
             * wire.len, so testing the room again afterwards sent a body
             * that had just been combined a second time (#208). */
            sent_bytes = wire.len + body_len;
            combine = body_len > 0 && body_len <= wire.max - wire.len;
            if (rc == ZUH_OK && combine) {
                if (!zuh_buf_append(&wire, body, body_len)) {
                    zuh_error_set(err, ZUH_ERR_NOMEM, ZUH_PHASE_NONE, "out of memory");
                    rc = ZUH_ERR_NOMEM;
                }
            } else if (rc == ZUH_OK && body_len > 0) {
                if (!zuh_stream_write_all(s, wire.data, wire.len, total, err))
                    rc = err->code ? err->code : ZUH_ERR_IO;
                else
                    wire.len = 0;
                if (rc == ZUH_OK && !zuh_stream_write_all(s, body, body_len, total, err))
                    rc = err->code ? err->code : ZUH_ERR_IO;
            }
            if (rc == ZUH_OK && wire.len &&
                !zuh_stream_write_all(s, wire.data, wire.len, total, err))
                rc = err->code ? err->code : ZUH_ERR_IO;
            /* §65.7 over HTTP/1.1: each piece as one chunk, then the last
             * chunk. A failure leaves the request half-sent, so the
             * connection is closed below, never pooled (D-47). */
            while (rc == ZUH_OK && src_live) {
                const void *d = NULL;
                size_t l = 0;
                char hex[24];
                rc = src->next(src->ctx, &d, &l, err);
                if (rc != ZUH_OK) break;
                snprintf(hex, sizeof hex, "%lx\r\n", (unsigned long)l);
                if (!zuh_stream_write_all(s, hex, strlen(hex), total, err) ||
                    (l && !zuh_stream_write_all(s, d, l, total, err)) ||
                    !zuh_stream_write_all(s, "\r\n", 2, total, err)) {
                    rc = err->code ? err->code : ZUH_ERR_IO;
                    break;
                }
                sent_bytes += l;
                if (l == 0) break;
            }
            if (rc == ZUH_OK) {
                out->timings.request_write = (long)(zuh_now_ms() - t_start);
                zuh_trace_add(o->trace, ZUH_EV_REQUEST_SENT, method, (uint64_t)sent_bytes);
            }
            zuh_buf_free(&wire);
            if (have_absform) { zuh_buf_free(&absform); have_absform = 0; }
            zuh_request_free(&rq);
            if (rc != ZUH_OK) {
                drop_stream(s); zuh_uri_free(&cur); zuh_result_free(out); zuh_proxy_free(&px);
                return rc;
            }
        }

        /* --- receive --- */
        zuh_response_init(&resp);
        if (!zuh_buf_init(&raw, 4096, ZUH_MAX_HEADER_BYTES + ZUH_READ_CHUNK)) {
            if (use_h2) zuh_request_free(&rq);
            zuh_response_free(&resp); drop_stream(s);
            zuh_uri_free(&cur); zuh_result_free(out); zuh_proxy_free(&px);
            return ZUH_ERR_NOMEM;
        }
        if (use_h2) {
            zuh_h2_request hr;
            int bodiless = 0;
            hr.method    = method;
            hr.scheme    = cur.is_https ? "https" : "http";
            hr.authority = hosthdr;
            hr.path      = cur.path_query;
            hr.headers   = &rq.headers;
            hr.body      = body_len ? body : NULL;
            hr.body_len  = body_len;
            hr.source    = src_live ? src : NULL;
            rc = zuh_h2_begin(s, &hr, &resp.status, &resp.headers, &bodiless, total, err);
            zuh_request_free(&rq);
            if (rc == ZUH_OK) {
                /* Written and answered in one call, so the write is timed to
                 * the response headers: an upper bound, not the write alone. */
                out->timings.request_write = (long)(zuh_now_ms() - t_start);
                /* The body bytes sent by the time the response headers
                 * arrived: all of an in-memory body unless the server
                 * answered first, and never body_len, which is 0 for a
                 * streamed one (review #169). */
                zuh_trace_add(o->trace, ZUH_EV_REQUEST_SENT, method, zuh_h2_body_sent(s));
                /* END_STREAM frames an HTTP/2 body (§65.2), so §18.1 is not
                 * consulted. FRAME_NONE marks the bodiless responses, which
                 * are never decoded, exactly as for HTTP/1.1. */
                resp.framing.kind = (bodiless || is_head || resp.status == 204 ||
                                     resp.status == 304) ? ZUH_FRAME_NONE
                                                         : ZUH_FRAME_UNTIL_CLOSE;
            }
        } else {
            rc = read_headers(s, &raw, &resp, &consumed, total, err);
            /* §18: skip 1xx and parse the real response behind it. */
            while (rc == ZUH_OK && zuh_response_is_informational(&resp)) {
                zuh_buf_consume(&raw, consumed);
                zuh_response_free(&resp);
                zuh_response_init(&resp);
                consumed = 0;
                rc = read_headers(s, &raw, &resp, &consumed, total, err);
            }
        }
        if (rc == ZUH_OK) {
            /* §35.1's ttfb. Measured at the end of the header block rather
             * than at the literal first byte: that is the first moment the
             * response means anything, and it is what every other client
             * reports under this name. */
            out->timings.ttfb = (long)(zuh_now_ms() - t_start);
            {
                char st[32];
                snprintf(st, sizeof st, "%d", resp.status);
                zuh_trace_add(o->trace, ZUH_EV_HEADERS_RECEIVED, st,
                             (uint64_t)resp.headers.n);
            }
        }
        if (rc == ZUH_OK && !use_h2) rc = zuh_response_decide_framing(&resp, is_head, err);
        if (rc == ZUH_OK) {
            /* §19.5: "Redirect response bodies must never reach the caller's
             * sink." A 3xx we are going to follow is drained into a capped
             * buffer instead — drained rather than skipped, because the
             * connection is only poolable if the body was consumed whole.
             *
             * The buffer, rather than a discard sink, is because the redirect
             * DECISION has not been made yet: zuh_redirect_decide() may refuse
             * to follow (a cross-scheme downgrade, say), and then this 3xx is
             * the response the caller receives and its body is theirs. Held
             * bytes are bounded by ZUH_MAX_REDIRECT_BODY, so this is not a
             * route back to buffering a large body. */
            may_follow = zuh_status_is_redirect(resp.status) &&
                         o->max_redirects > 0 &&
                         zuh_headers_get(&resp.headers, "Location") != NULL;
            uint64_t cap = o->max_body ? o->max_body : ZUH_DEFAULT_MAX_BODY;

            fr = resp.framing;
            /* A followed redirect's body lands in the result buffer, which
             * is reset before the next hop — never in the caller's sink. When
             * the decision below turns out to be "do not follow", the 3xx is
             * the caller's response and those bytes are flushed onward. */
            hop_sink = may_follow ? &mem_sink : body_sink;
            if (may_follow) cap = ZUH_MAX_REDIRECT_BODY;
            /* Per hop, not cumulative: the limit describes one body. */
            hop_sink->written = 0;
            /* Two responses are never decoded. A bodiless one (HEAD, 204,
             * 304): its Content-Encoding and Content-Length describe the
             * representation, not bytes that follow (RFC 9112 §6.3), so
             * decoding nothing failed on an unsupported coding and stripped
             * both headers from the rest. And a redirect about to be
             * followed: its body is thrown away, so decoding it could only
             * turn an irrelevant body into a failed request. */
            if (o->stream_body && !may_follow && !o->sink) {
                /* §65.4: the connection and the unread body go to the
                 * caller; nothing below reads or releases it. */
                rc = open_body_new(&out->open, s, use_h2, &fr,
                                   (const char *)raw.data + consumed, raw.len - consumed,
                                   &resp.headers, resp.minor_version, cap,
                                   o->no_decode || resp.framing.kind == ZUH_FRAME_NONE,
                                   o, &cur, &px, err);
                if (rc == ZUH_OK) {
                    s = NULL;
                    streamed = 1;
                    /* §65.7: over HTTP/2 the request body may still be
                     * going out as the response streams; the pulled body
                     * keeps the source alive and releases it. */
                    if (use_h2 && src_live) {
                        out->open->src = *src;
                        memset(src, 0, sizeof *src);
                    }
                }
            }
            if (!streamed && rc == ZUH_OK)
                rc = zuh_body_pipe_init(&pipe, hop_sink, &resp.headers,
                                   o->no_decode || may_follow ||
                                   resp.framing.kind == ZUH_FRAME_NONE,
                                   cap, err);
            if (streamed)
                ;
            else if (rc == ZUH_OK && use_h2)
                rc = zuh_h2_body(s, &pipe, total, err);
            else if (rc == ZUH_OK)
                rc = zuh_body_read(s, &fr, &pipe,
                               (const char *)raw.data + consumed, raw.len - consumed,
                               total, err);
            if (!may_follow && !streamed) {
                /* §65.3: the trailers belong to the caller's response. */
                zuh_headers_free(&out->trailers);
                out->trailers = pipe.trailers;      /* ownership moves */
                zuh_headers_init(&pipe.trailers);
                out->timings.response_read = (long)(zuh_now_ms() - t_start);
                out->timings.body_bytes_wire    = pipe.raw_seen;
                out->timings.body_bytes_decoded = hop_sink ? hop_sink->written : 0;
                zuh_trace_add(o->trace, ZUH_EV_BODY_CHUNK, "body",
                             hop_sink ? hop_sink->written : 0);
            }
            if (!streamed) {
                surplus = pipe.surplus;
                zuh_body_pipe_free(&pipe);
            }
        }
        zuh_buf_free(&raw);
        /* §26.3. The decision is made HERE, while the framing and the
         * response headers that justify it are still in scope — not inside
         * the pool, which cannot see them. */
        {
            zuh_reuse reason = use_h2 ? h2_reuse(rc, s)
                                      : zuh_reuse_decide(rc, &fr, &resp.headers,
                                                         resp.minor_version);
            /* §19.5: a redirect body that cannot be drained — over the
             * ZUH_MAX_REDIRECT_BODY budget, or cut short — costs the
             * connection, not the request. The headers are complete and the
             * Location is valid; `reason` already refuses reuse, since the
             * framing position is unknown. Failures that concern the request
             * rather than this body (a timeout, an interrupt) still stop it. */
            if (may_follow && (rc == ZUH_ERR_BODY_LIMIT || rc == ZUH_ERR_PARSE)) {
                rc = ZUH_OK;
                zuh_error_clear(err);
            }
            /* §27.2: a sink that asked to stop ended the transfer CLEANLY —
             * the caller gets their response. The connection still cannot be
             * reused, because the body was not read to its end and the
             * framing position is therefore unknown (§26.3). Flipping rc here
             * rather than in the R layer matters: the engine has to keep
             * building the result, and by the time it has returned an error
             * the result is already torn down. */
            if (rc == ZUH_ERR_CANCELLED && hop_sink && hop_sink->stopped) {
                rc = ZUH_OK;
                reason = ZUH_NOREUSE_CANCELLED;
                /* §65.5: over HTTP/2 the stream is reset and the connection
                 * kept, which is what a stopped callback means there. */
                if (use_h2) {
                    zuh_h2_cancel(s, total);
                    reason = h2_reuse(ZUH_OK, s);
                }
            }
            /* The server sent bytes past this response's framing. They were
             * dropped, not delivered, but the connection is now out of step:
             * whatever arrives next on it may not answer the next request.
             * The §26.2 probe would usually catch it, but only if the bytes
             * arrive before the next request is written. */
            if (rc == ZUH_OK && surplus > 0 && reason == ZUH_REUSE_OK)
                reason = ZUH_NOREUSE_FRAMING;
            done_with_stream(o, &cur, &px, s, reason);
        }

        if (rc != ZUH_OK) {
            zuh_response_free(&resp); zuh_uri_free(&cur); zuh_result_free(out);
            zuh_proxy_free(&px);
            return rc;
        }

        out->status = resp.status;
        out->http_version = use_h2 ? 0 : resp.minor_version;
        out->http_major   = use_h2 ? 2 : 1;
        zuh_headers_free(&out->headers);
        out->headers = resp.headers;          /* ownership moves */
        zuh_headers_init(&resp.headers);
        zuh_response_free(&resp);

        /* --- redirect? --- */
        /* `redirects = 0` means "give me the 3xx". Any other limit is a
         * limit: zuh_redirect_decide() raises zu_too_many_redirects once it is
         * reached (§19.4). Testing `hops < max` here used to skip that call,
         * so an exhausted chain returned its last 3xx as if it were final. */
        if (zuh_status_is_redirect(out->status) && o->max_redirects > 0) {
            const char *loc = zuh_headers_get(&out->headers, "Location");
            zuh_uri next;
            zuh_redirect_policy pol;
            zuh_redirect_decision dec;

            if (!loc) { zuh_proxy_free(&px); break; }   /* a redirect with no Location */
            rc = zuh_uri_resolve(&next, &cur, loc, loc + strlen(loc));
            if (rc != ZUH_OK) {
                if (rc == ZUH_ERR_NOMEM)
                    zuh_error_set(err, rc, ZUH_PHASE_NONE, "out of memory");
                else
                    zuh_error_set(err, ZUH_ERR_URL, ZUH_PHASE_NONE,
                                 "redirect Location is not a usable URL");
                zuh_uri_free(&cur); zuh_result_free(out); zuh_proxy_free(&px);
                return rc == ZUH_ERR_NOMEM ? rc : ZUH_ERR_URL;
            }
            zuh_redirect_policy_init(&pol);
            pol.max_redirects = (size_t)o->max_redirects;
            rc = zuh_redirect_decide(&pol, out->status, method, &cur, &next,
                                    hops, &dec, err);
            if (rc != ZUH_OK) {
                zuh_uri_free(&next); zuh_uri_free(&cur); zuh_result_free(out); zuh_proxy_free(&px);
                return rc;
            }
            if (dec.action == ZUH_REDIRECT_FOLLOW) {
                /* §19.1: a rewritten method drops the body with it. Keeping
                 * the body after 303 -> GET would send a body no method
                 * expects. */
                if (dec.rewrite_to_get) { method = "GET"; is_head = 0; }
                if (dec.drop_body) { body = NULL; body_len = 0; }
                /* §28.2, §65.7: a streamed body has been sent and cannot
                 * be sent again; a 307/308 that would resend it is refused
                 * rather than sent short. A 303 drops it, as it drops any
                 * body. */
                if (src_live && !dec.drop_body) {
                    zuh_error_set(err, ZUH_ERR_BODY_NOT_REPLAYABLE, ZUH_PHASE_NONE,
                                  "a %d redirect would resend a streamed request body, "
                                  "which cannot be replayed", out->status);
                    zuh_uri_free(&next); zuh_uri_free(&cur); zuh_result_free(out);
                    zuh_proxy_free(&px);
                    return ZUH_ERR_BODY_NOT_REPLAYABLE;
                }
                src_live = 0;
                if (dec.strip_credentials) strip_creds = 1;
                zuh_uri_free(&cur);
                cur = next;
                hops++;
                out->redirects = (int)hops;
                /* §19.4: a (method, URL) already requested in this chain is
                 * a loop, and following it again can only repeat what the
                 * server already said. The hop count alone made a self-
                 * redirect cost max_redirects round trips to report. */
                rc = check_host(&cur, err);
                if (rc == ZUH_OK) rc = zuh_redirect_trail_add(trail, method, &cur);
                if (rc != ZUH_OK) {
                    if (rc == ZUH_ERR_REDIRECT)
                        zuh_error_set(err, rc, ZUH_PHASE_NONE,
                                     "redirect loop: hop %lu returns to a URL "
                                     "this request already visited",
                                     (unsigned long)hops);
                    else
                        zuh_error_set(err, rc, ZUH_PHASE_NONE, "out of memory");
                    zuh_uri_free(&cur); zuh_result_free(out); zuh_proxy_free(&px);
                    return rc;
                }
                zuh_buf_reset(&out->body);
                zuh_headers_free(&out->headers);
                zuh_headers_init(&out->headers);
                /* The target is rebuilt from the resolved URI, never taken
                 * from `loc`: that points into the headers freed two lines
                 * up, so reading it here reported freed memory. url_of() is
                 * the same builder final_url uses, so the event and
                 * zu_resp_url() cannot disagree about where the request went
                 * — it brackets IPv6 hosts and keeps an explicit port, which
                 * a hand-rolled origin string here got wrong both ways. It
                 * allocates, hence the trace check: nobody pays for a target
                 * nobody asked for. */
                if (o->trace) {
                    char *target = url_of(&cur);
                    zuh_trace_add_url(o->trace, ZUH_EV_REDIRECT_FOLLOWED,
                                     o->redact, target, (uint64_t)hops);
                    zuh_free(target);
                }
                zuh_proxy_free(&px);           /* re-resolved for the next hop */
                continue;                     /* §19.5: the body never reaches the caller */
            }
            zuh_uri_free(&next);
        }
        /* The decision was "do not follow", so this 3xx IS the caller's
         * response and the bytes held for it are theirs. Unreachable today —
         * zuh_redirect_decide() follows or fails once may_follow holds — and
         * kept so that a decision that one day declines (§19.3) cannot lose
         * the body. Without this a
         * download whose final hop is an unfollowed redirect would leave an
         * empty file and put the body somewhere the caller never looks. */
        if (body_sink != &mem_sink && out->body.len) {
            rc = zuh_sink_write(body_sink, out->body.data, out->body.len, err);
            zuh_buf_reset(&out->body);
            if (rc != ZUH_OK) {
                zuh_uri_free(&cur); zuh_result_free(out); zuh_proxy_free(&px);
                return rc;
            }
        }
        /* Every exit from a hop frees `px`, the success path included: it
         * holds the proxy password, and a request whose final hop was proxied
         * once left it on the heap after returning (§42). */
        zuh_proxy_free(&px);
        break;
    }

    out->timings.total = (long)(zuh_now_ms() - t_start);
    zuh_trace_add(o->trace, ZUH_EV_REQUEST_DONE, NULL, (uint64_t)out->status);

    out->final_url = redacted_url_of(&cur, o->redact);
    zuh_uri_free(&cur);
    if (!out->final_url) { zuh_result_free(out); return ZUH_ERR_NOMEM; }
    return ZUH_OK;
}

zuh_code zuh_engine_perform(zuh_result *out, const char *url,
                          const zuh_req_spec *req, const zuh_get_opts *o,
                          zuh_error *err) {
    zuh_redirect_trail trail;
    zuh_code rc;
    zuh_body_source src;
    if (err) zuh_error_clear(err);   /* a stale code would hide a bare failure */
    /* §65.7: the engine owns the source from here; released once, below,
     * unless a pulled body took it over. */
    if (req) src = req->source; else memset(&src, 0, sizeof src);
    zuh_redirect_trail_init(&trail);
    rc = perform_hops(out, url, req, o, &trail, &src, err);
    zuh_redirect_trail_free(&trail);
    if (src.release) src.release(src.ctx);
    /* Every failure carries a filled error object (§34.4). Dozens of exits
     * return ZUH_ERR_NOMEM bare; one place says so for all of them, rather
     * than leaving init.c's "request failed" fallback to guess. */
    if (rc != ZUH_OK && err && err->code == ZUH_OK)
        zuh_error_set(err, rc, ZUH_PHASE_NONE,
                      rc == ZUH_ERR_NOMEM ? "out of memory" : "request failed");
    return rc;
}

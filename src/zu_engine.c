#include "zu_engine.h"
#include "zu_alloc.h"
#include "zu_uri.h"
#include "zu_request.h"
#include "zu_response.h"
#include "zu_framing.h"
#include "zu_redirect.h"
#include "zu_inflate.h"
#include "zu_tls.h"
#include "zu_stream.h"
#include "zu_pool.h"
#include "zu_sink.h"
#include "zu_body.h"
#include "zu_proxy.h"
#include "zu_time.h"
#include <string.h>
#include <stdio.h>

#define ZU_DEFAULT_TIMEOUT_MS  30000
#define ZU_DEFAULT_MAX_BODY    (16u * 1024u * 1024u)
#define ZU_MAX_HEADER_BYTES    (64u * 1024u)
#define ZU_READ_CHUNK          16384
/* §19.5's "small cap" on a redirect body we are going to drain. Large enough
 * for any real 3xx explanation page, small enough that draining one is never
 * the reason a download is memory-hungry. */
#define ZU_MAX_REDIRECT_BODY   (64u * 1024u)

void zu_get_opts_init(zu_get_opts *o) {
    if (!o) return;
    memset(o, 0, sizeof *o);
    o->timeout_ms    = ZU_DEFAULT_TIMEOUT_MS;
    o->max_redirects = 1;               /* §63.2: the slice follows one */
    o->verify        = 1;               /* never 0 by default (§14.1) */
    o->max_body      = ZU_DEFAULT_MAX_BODY;
}

void zu_result_init(zu_result *r) {
    if (!r) return;
    memset(r, 0, sizeof *r);
    zu_headers_init(&r->headers);
}

void zu_result_free(zu_result *r) {
    if (!r) return;
    zu_headers_free(&r->headers);
    zu_buf_free(&r->body);
    zu_free(r->final_url);
    zu_free(r->tls_version);
    zu_free(r->tls_cipher);
    zu_free(r->remote_ip);
    zu_free(r->trust_backend);
    memset(r, 0, sizeof *r);
}

static char *dup_str(const char *s) {
    size_t n;
    char *p;
    if (!s) return NULL;
    n = strlen(s);
    p = (char *)zu_alloc(n + 1);
    if (p) memcpy(p, s, n + 1);
    return p;
}

/* "scheme://host[:port]path?query", never with userinfo (§42.1). */
static char *url_of(const zu_uri *u) {
    zu_buffer b;
    const char *s = NULL;
    char *out = NULL;
    char port[8];

    if (!zu_buf_init(&b, 128, 8192)) return NULL;
    if (!zu_buf_append_str(&b, u->scheme) || !zu_buf_append_str(&b, "://")) goto done;
    if (strchr(u->host, ':')) {
        if (!zu_buf_append_byte(&b, '[') || !zu_buf_append_str(&b, u->host)
            || !zu_buf_append_byte(&b, ']')) goto done;
    } else if (!zu_buf_append_str(&b, u->host)) goto done;
    if (u->port_explicit) {
        int n = snprintf(port, sizeof port, ":%u", (unsigned)u->port);
        if (n < 0 || (size_t)n >= sizeof port) goto done;
        if (!zu_buf_append_str(&b, port)) goto done;
    }
    if (!zu_buf_append_str(&b, u->path_query)) goto done;
    if (zu_buf_cstr(&b, &s)) out = dup_str(s);
done:
    zu_buf_free(&b);
    return out;
}

/* Open the transport for one hop: TCP, then TLS when the scheme says so. */
/* --- §26.1 pool key ------------------------------------------------------
 *
 * Built from the URI, the proxy and the §14 TLS configuration this engine
 * actually applies — which is now every field of §26.1 except the client
 * certificate, since client certs are not yet a thing zu_get_opts can carry.
 *
 * When one IS plumbed through, it must be added here in the same commit. A
 * key that ignores a field two clients differ on is the "coarse key is a
 * security bug, not a performance optimisation" failure §26.1 names — it
 * would let a request with verification off, or without a pin, reuse a
 * connection established with them. zu_pool_key_eq() compares every field of
 * the struct, so the risk is only ever a field missing HERE.
 *
 * The strings are owned copies, freed by pool_key_free(). Borrowing pointers
 * into the zu_uri would be cheaper and is what an earlier draft did, but the
 * struct's contract is owned storage, and a later zu_pool_key_free() on a
 * borrowed key is a double free waiting to happen.
 *
 * acquire and release each build their own key rather than sharing one across
 * the hop. That is four strdups per pooled request instead of two, and it buys
 * the loop's dozen early-return paths having no key to free — the kind of
 * lifetime bookkeeping that leaks the first time someone adds a thirteenth. */
static int pool_key_for(zu_pool_key *k, const zu_uri *u, const zu_get_opts *o,
                        const zu_proxy *px) {
    zu_pool_key_init(k);
    k->scheme = dup_str(u->is_https ? "https" : "http");
    k->host   = dup_str(u->host);
    if (!k->scheme || !k->host) { zu_pool_key_free(k); return 0; }
    k->port            = u->port;
    k->verify_peer     = o->verify;
    k->verify_hostname = o->verify;
    if (o->ca_file) {
        k->ca_file = dup_str(o->ca_file);
        if (!k->ca_file) { zu_pool_key_free(k); return 0; }
    }
    /* §26.1 field by field. S16 left a note here saying that anything later
     * plumbed through zu_get_opts must be added in the same commit, because a
     * key that ignores a field two clients differ on is "a security bug, not a
     * performance optimisation" — it would let a request pinned to one key
     * reuse a connection established without the pin. This is that commit. */
    if (o->tls) {
        k->revocation  = o->tls->revocation;
        k->min_version = o->tls->min_version;
        if (o->tls->ca_extra_file) {
            k->ca_extra_file = dup_str(o->tls->ca_extra_file);
            if (!k->ca_extra_file) { zu_pool_key_free(k); return 0; }
        }
        if (o->tls->alpn) {
            k->alpn = dup_str(o->tls->alpn);
            if (!k->alpn) { zu_pool_key_free(k); return 0; }
        }
        if (o->tls->n_pins > 0) {
            /* Joined in the order given. Two clients that list the same pins
             * differently are treated as different, which costs a connection
             * and never shares one that should not be shared — the safe way
             * round for a key whose job is to keep things apart. */
            zu_buffer b;
            size_t i;
            const char *joined = NULL;
            if (!zu_buf_init(&b, 128, 64 * 1024)) { zu_pool_key_free(k); return 0; }
            for (i = 0; i < o->tls->n_pins; i++) {
                if (!zu_buf_append_str(&b, o->tls->pins[i]) ||
                    !zu_buf_append_byte(&b, '\x1f')) {
                    zu_buf_free(&b); zu_pool_key_free(k); return 0;
                }
            }
            if (!zu_buf_cstr(&b, &joined)) { zu_buf_free(&b); zu_pool_key_free(k); return 0; }
            k->pins = dup_str(joined);
            zu_buf_free(&b);
            if (!k->pins) { zu_pool_key_free(k); return 0; }
        }
    }
    /* §26.1 requires proxy identity INCLUDING credentials, so that two
     * clients with different proxy credentials cannot share a tunnel. The
     * credentials are part of the key and never part of anything printable —
     * zu_pool_key is internal and has no formatter. */
    if (px && px->in_use) {
        char buf[512];
        snprintf(buf, sizeof buf, "%s://%s:%s@%s:%u",
                 px->scheme ? px->scheme : "http",
                 px->username ? px->username : "",
                 px->password ? px->password : "",
                 px->host ? px->host : "", (unsigned)px->port);
        k->proxy = dup_str(buf);
        if (!k->proxy) { zu_pool_key_free(k); return 0; }
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
 * zu_pool_release takes ownership either way, so this is the ONLY place the
 * happy path disposes of a stream and the caller never decides who frees. */
static void done_with_stream(const zu_get_opts *o, const zu_uri *u,
                             const zu_proxy *px, zu_stream *s, zu_reuse r) {
    zu_pool_key key;
    if (!s) return;
    if (o->pool && pool_key_for(&key, u, o, px)) {
        zu_pool_release(o->pool, &key, s, r);
        zu_pool_key_free(&key);
        return;
    }
    /* No pool, or the key could not be built (OOM). Either way the safe
     * answer is §26.3's: close it. */
    zu_stream_close(s);
    zu_stream_free(s);
}

/* Record the negotiated TLS parameters on the result. Runs for a pooled
 * connection as well as a fresh one: the handshake happened on some earlier
 * request, but the session is the same one this response came over, so
 * reporting it is not a courtesy — a caller that logs tls_version would
 * otherwise see NULL on exactly the requests that reused a connection. */
static void record_tls_info(zu_stream *s, zu_result *res) {
    zu_tls_info info;
    if (!zu_tls_get_info(s, &info)) return;
    zu_free(res->tls_version); zu_free(res->tls_cipher);
    zu_free(res->trust_backend);
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
static zu_code proxy_tunnel(zu_stream *tcp, const zu_proxy *px,
                            const zu_uri *target, zu_deadline dl,
                            zu_error *err) {
    zu_buffer req, raw;
    zu_code rc;
    int status = 0;
    size_t consumed = 0;

    if (!zu_buf_init(&req, 256, 8192)) return ZU_ERR_NOMEM;
    rc = zu_proxy_connect_request(px, target, &req, err);
    if (rc == ZU_OK && !zu_stream_write_all(tcp, req.data, req.len, dl, err))
        rc = err->code ? err->code : ZU_ERR_IO;
    zu_buf_free(&req);
    if (rc != ZU_OK) return rc;

    if (!zu_buf_init(&raw, 1024, ZU_MAX_HEADER_BYTES)) return ZU_ERR_NOMEM;
    for (;;) {
        char chunk[ZU_READ_CHUNK];
        zu_ssize n;

        rc = zu_proxy_connect_response((const char *)raw.data, raw.len,
                                       &consumed, &status, err);
        if (rc != ZU_ERR_WOULDBLOCK) break;
        if (raw.len >= ZU_MAX_HEADER_BYTES) {
            zu_error_set(err, ZU_ERR_PROXY, ZU_PHASE_CONNECT,
                         "proxy CONNECT response header block is too large");
            rc = ZU_ERR_PROXY;
            break;
        }
        n = zu_stream_read(tcp, chunk, sizeof chunk, dl, err);
        if (n < 0) { rc = err->code; break; }
        if (n == 0) {
            zu_error_set(err, ZU_ERR_PROXY, ZU_PHASE_CONNECT,
                         "proxy closed the connection during CONNECT");
            rc = ZU_ERR_PROXY;
            break;
        }
        if (!zu_buf_append(&raw, chunk, (size_t)n)) { rc = ZU_ERR_NOMEM; break; }
    }
    /* Anything the proxy sent past the CONNECT response would be TLS bytes
     * from the origin, which we have not read yet. A well-behaved proxy sends
     * nothing; one that does has desynchronised the tunnel before it started,
     * and continuing would splice its bytes into the handshake. */
    if (rc == ZU_OK && raw.len > consumed) {
        zu_error_set(err, ZU_ERR_PROXY, ZU_PHASE_CONNECT,
                     "proxy sent %lu unexpected bytes after CONNECT",
                     (unsigned long)(raw.len - consumed));
        rc = ZU_ERR_PROXY;
    }
    zu_buf_free(&raw);
    return rc;
}

static zu_code open_stream(zu_stream **out, const zu_uri *u,
                           const zu_get_opts *o, const zu_proxy *px,
                           zu_deadline dl, zu_result *res, zu_error *err) {
    zu_net_opts nopts;
    zu_stream *tcp = NULL;
    zu_code rc;
    int via_proxy = px && px->in_use;

    /* §26: a live connection for this exact key, if the pool has one. The
     * pool has already run the fork guard, the idle-timeout check and the
     * §26.2 liveness probe by the time it answers, so a non-NULL return is
     * usable as-is. */
    if (o->pool) {
        zu_pool_key key;
        zu_stream *reused = NULL;
        if (!pool_key_for(&key, u, o, px)) return ZU_ERR_NOMEM;
        reused = zu_pool_acquire(o->pool, &key);
        zu_pool_key_free(&key);
        if (reused) {
            if (u->is_https) record_tls_info(reused, res);
            res->reused_connection = 1;   /* §35.2 */
            *out = reused;
            return ZU_OK;
        }
    }

    zu_net_opts_init(&nopts);
    nopts.tick     = o->tick;
    nopts.tick_ctx = o->tick_ctx;

    /* Through a proxy the socket goes to the PROXY, not the origin. For plain
     * HTTP that is the whole of it — the request then uses absolute-form
     * (§20.3) and the proxy does the rest. */
    if (via_proxy)
        rc = zu_net_connect(&tcp, px->host, px->port, dl, &nopts, err);
    else
        rc = zu_net_connect(&tcp, u->host, u->port, dl, &nopts, err);
    if (rc != ZU_OK) return rc;

    /* §35.2 remote_ip, taken from the TCP stream before TLS wraps it — the
     * outer stream has no address of its own. Through a proxy this is the
     * PROXY's address, which is the honest answer: it is who we are talking
     * to, and the origin's address is something only the proxy knows. */
    {
        char ip[64];
        if (zu_net_peer_ip(tcp, ip, sizeof ip)) {
            zu_free(res->remote_ip);
            res->remote_ip = dup_str(ip);
        }
    }
    res->reused_connection = 0;
    res->proxy_used = via_proxy;

    if (!u->is_https) { *out = tcp; return ZU_OK; }

    /* HTTPS through a proxy tunnels first, and the TLS handshake below then
     * runs against the ORIGIN's hostname over that tunnel — which is what
     * makes the proxy unable to see or forge the origin's certificate. */
    if (via_proxy) {
        rc = proxy_tunnel(tcp, px, u, dl, err);
        if (rc != ZU_OK) { zu_stream_free(tcp); return rc; }
    }

    if (!zu_tls_available()) {
        zu_error_set(err, ZU_ERR_TLS, ZU_PHASE_TLS,
                     "this build has no TLS backend, so https:// is unavailable");
        zu_stream_free(tcp);
        return ZU_ERR_TLS;
    }
    {
        zu_tls_config cfg;
        zu_stream *tls = NULL;

        /* Start from the caller's §14 configuration when there is one, so
         * ca_extra, pins, revocation and min_version arrive intact... */
        if (o->tls) cfg = *o->tls; else zu_tls_config_init(&cfg);
        /* ...then the two fields that have their own merged policy argument
         * win, because §31.9 already owns them and two sources of truth for
         * "is this connection verified" is not a thing to have. */
        cfg.verify_peer     = o->verify;
        cfg.verify_hostname = o->verify;
        if (o->ca_file) { cfg.ca_file = o->ca_file; cfg.source = ZU_TRUST_FILE; }

        rc = zu_tls_connect(&tls, tcp, u->host, &cfg, dl, err);
        if (rc != ZU_OK) {
            /* zu_tls_connect does not take ownership of `inner` on failure,
             * so the TCP stream is still ours to free (S7). */
            zu_stream_free(tcp);
            return rc;
        }
        record_tls_info(tls, res);
        *out = tls;
        return ZU_OK;
    }
}

/* Read until the header block is complete. Leftover body bytes are left in
 * `raw` past `consumed`. */
static zu_code read_headers(zu_stream *s, zu_buffer *raw, zu_response *resp,
                            size_t *consumed, zu_deadline dl, zu_error *err) {
    size_t last_len = 0;
    for (;;) {
        char chunk[ZU_READ_CHUNK];
        zu_ssize n;
        zu_code rc = zu_response_parse(resp, (const char *)raw->data, raw->len,
                                       last_len, consumed, err);
        if (rc != ZU_ERR_WOULDBLOCK) return rc;
        last_len = raw->len;

        if (raw->len >= ZU_MAX_HEADER_BYTES) {
            zu_error_set(err, ZU_ERR_BODY_LIMIT, ZU_PHASE_READ,
                         "response header block exceeds %u bytes",
                         (unsigned)ZU_MAX_HEADER_BYTES);
            return ZU_ERR_BODY_LIMIT;
        }
        n = zu_stream_read(s, chunk, sizeof chunk, dl, err);
        if (n < 0) return err->code;
        if (n == 0) {
            zu_error_set(err, ZU_ERR_PARSE, ZU_PHASE_READ,
                         "connection closed before the response headers ended");
            return ZU_ERR_PARSE;
        }
        if (!zu_buf_append(raw, chunk, (size_t)n)) return ZU_ERR_NOMEM;
    }
}

/* Read the body according to the §18.1 framing decision. `seed` is whatever
 * already arrived alongside the headers. */
zu_code zu_engine_get(zu_result *out, const char *url,
                      const zu_get_opts *o, zu_error *err) {
    return zu_engine_perform(out, url, NULL, o, err);
}

zu_code zu_engine_perform(zu_result *out, const char *url,
                          const zu_req_spec *req, const zu_get_opts *o,
                          zu_error *err) {
    zu_get_opts defaults;
    zu_uri cur;
    zu_deadline total;
    size_t hops = 0;
    zu_code rc;
    zu_sink mem_sink;
    zu_sink *body_sink = NULL;
    zu_env  sysenv;
    const char *method = (req && req->method) ? req->method : "GET";
    const void *body   = req ? req->body : NULL;
    size_t body_len    = req ? req->body_len : 0;
    size_t n_hdr       = req ? req->n_headers : 0;
    int is_head        = (strcmp(method, "HEAD") == 0);

    if (!out || !url) return ZU_ERR_URL;
    zu_env_system(&sysenv);
    zu_result_init(out);
    if (!o) { zu_get_opts_init(&defaults); o = &defaults; }

    /* §24.1: one deadline for the whole operation, redirects included. */
    total = zu_deadline_in(o->timeout_ms > 0 ? o->timeout_ms : ZU_DEFAULT_TIMEOUT_MS);

    rc = zu_uri_parse(&cur, url, url + strlen(url));
    if (rc != ZU_OK) {
        zu_error_set(err, ZU_ERR_URL, ZU_PHASE_NONE, "not a usable URL: %s", url);
        return ZU_ERR_URL;
    }

    /* §27: where the final body goes. `o->sink` is the caller's; without one
     * the body is buffered into the result, which is the pre-S17 behaviour and
     * still what zu_resp_raw() needs. mem_sink always exists because followed
     * redirect bodies use it whatever the caller chose (§19.5). */
    zu_sink_memory_init(&mem_sink, &out->body);
    body_sink = o->sink ? o->sink : &mem_sink;

    for (;;) {
        zu_stream *s = NULL;
        zu_request rq;
        zu_response resp;
        size_t hi;
        zu_buffer wire, raw, absform, auth;
        int have_absform = 0;
        zu_proxy px;
        zu_body_pipe pipe;
        zu_sink *hop_sink = NULL;
        size_t consumed = 0;

        memset(&pipe, 0, sizeof pipe);
        /* Pre-set to the §26.3 safe default. `fr` is only really filled once
         * zu_response_decide_framing() succeeds, so every path that fails
         * before that point must still give reuse_after() something that
         * means "do not reuse" rather than whatever was on the stack. */
        zu_framing fr = { ZU_FRAME_UNTIL_CLOSE, 0, 0 };

        /* Resolved per hop, not once: a redirect may cross from a proxied
         * host to a NO_PROXY one (or the reverse), and reusing the first
         * hop's decision would send the second hop the wrong way (§20.2). */
        zu_proxy_init(&px);
        rc = zu_proxy_resolve(&px, &cur, o->env ? o->env : &sysenv,
                              o->proxy, o->proxy_set, err);
        if (rc != ZU_OK) { zu_proxy_free(&px); zu_uri_free(&cur); zu_result_free(out); return rc; }

        rc = open_stream(&s, &cur, o, &px, total, out, err);
        if (rc != ZU_OK) {
            zu_proxy_free(&px); zu_uri_free(&cur); zu_result_free(out);
            return rc;
        }

        /* --- send --- */
        zu_request_init(&rq);
        rq.method = method;
        rq.target = cur.path_query;
        rq.host   = cur.host;
        rq.form   = ZU_TARGET_ORIGIN;
        /* §20.3: plain HTTP through a proxy uses absolute-form, so the proxy
         * knows which origin to reach. HTTPS does not — by then we are inside
         * a CONNECT tunnel talking to the origin itself, and an absolute-form
         * request there would be both wrong and a disclosure. */
        if (px.in_use && !cur.is_https) {
            if (!zu_buf_init(&absform, 128, 8192)) {
                zu_request_free(&rq); zu_stream_free(s);
                zu_uri_free(&cur); zu_result_free(out); zu_proxy_free(&px);
                return ZU_ERR_NOMEM;
            }
            have_absform = 1;
            if (!zu_proxy_absolute_form(&cur, &absform) ||
                !zu_buf_cstr(&absform, &rq.target)) {
                zu_buf_free(&absform);
                zu_request_free(&rq); zu_stream_free(s);
                zu_uri_free(&cur); zu_result_free(out); zu_proxy_free(&px);
                return ZU_ERR_NOMEM;
            }
            rq.form = ZU_TARGET_ABSOLUTE;

            /* §20.4: the header goes on the connection TO THE PROXY, which
             * for absolute-form is this very request. Proxy-Authorization is
             * hop-by-hop, so the proxy consumes it and does not forward it to
             * the origin — and because the proxy is re-resolved per hop, a
             * redirect onto a NO_PROXY host simply never reaches this branch
             * and so cannot carry the credential onward (§19.2). */
            if (zu_buf_init(&auth, 64, 4096)) {
                const char *v = NULL;
                if (zu_proxy_auth_value(&px, &auth) && zu_buf_cstr(&auth, &v))
                    rc = zu_headers_add_str(&rq.headers, "Proxy-Authorization", v);
                zu_buf_free(&auth);
                if (rc != ZU_OK) {
                    if (have_absform) zu_buf_free(&absform);
                    zu_request_free(&rq); zu_stream_free(s);
                    zu_uri_free(&cur); zu_result_free(out); zu_proxy_free(&px);
                    return rc;
                }
            }
        }
        if (body_len > 0) {
            rq.body           = ZU_BODY_LENGTH;
            rq.content_length = (uint64_t)body_len;
        } else {
            rq.body = ZU_BODY_NONE;
        }
        /* §21.2: a caller who asked for the wire bytes wants the server to
         * stop encoding, not just for us to stop decoding — otherwise
         * "wire bytes" means "gzip, if the server felt like it". An explicit
         * Accept-Encoding from the caller still wins: this is only a default,
         * and it is added before the caller's headers for that reason. */
        if (o->no_decode) {
            rc = zu_headers_add_str(&rq.headers, "Accept-Encoding", "identity");
            if (rc != ZU_OK) {
                zu_request_free(&rq); zu_stream_free(s);
                zu_uri_free(&cur); zu_result_free(out); zu_proxy_free(&px);
                return rc;
            }
        }
        /* Caller headers first, so §17.2's defaults only fill what is absent
         * and an explicit Accept or User-Agent wins. Every name and value is
         * validated here, which is what stops a header carrying a CRLF from
         * becoming a second request (§17.1). */
        for (hi = 0; hi < n_hdr; hi++) {
            rc = zu_headers_add_str(&rq.headers, req->header_names[hi],
                                    req->header_values[hi]);
            if (rc != ZU_OK) {
                zu_error_set(err, rc, ZU_PHASE_NONE,
                             "header %lu is not valid", (unsigned long)hi + 1);
                zu_request_free(&rq); zu_stream_free(s);
                zu_uri_free(&cur); zu_result_free(out); zu_proxy_free(&px);
                return rc;
            }
        }
        if (!zu_buf_init(&wire, 512, 64 * 1024)) {
            zu_request_free(&rq); zu_stream_free(s);
            zu_uri_free(&cur); zu_result_free(out); zu_proxy_free(&px);
            return ZU_ERR_NOMEM;
        }
        rc = zu_request_add_defaults(&rq, o->user_agent);
        if (rc == ZU_OK) rc = zu_request_write(&rq, &wire);
        /* The body is appended to the same buffer rather than written
         * separately: one write means one TCP segment for a small request,
         * and it keeps the "headers sent but body not" window closed. */
        if (rc == ZU_OK && body_len > 0 && !zu_buf_append(&wire, body, body_len))
            rc = ZU_ERR_NOMEM;
        if (rc == ZU_OK && !zu_stream_write_all(s, wire.data, wire.len, total, err))
            rc = err->code ? err->code : ZU_ERR_IO;
        zu_buf_free(&wire);
        if (have_absform) { zu_buf_free(&absform); have_absform = 0; }
        zu_request_free(&rq);
        if (rc != ZU_OK) {
            zu_stream_free(s); zu_uri_free(&cur); zu_result_free(out); zu_proxy_free(&px);
            return rc;
        }

        /* --- receive --- */
        zu_response_init(&resp);
        if (!zu_buf_init(&raw, 4096, ZU_MAX_HEADER_BYTES + ZU_READ_CHUNK)) {
            zu_response_free(&resp); zu_stream_free(s);
            zu_uri_free(&cur); zu_result_free(out); zu_proxy_free(&px);
            return ZU_ERR_NOMEM;
        }
        rc = read_headers(s, &raw, &resp, &consumed, total, err);
        /* §18: skip 1xx and parse the real response behind it. */
        while (rc == ZU_OK && zu_response_is_informational(&resp)) {
            zu_buf_consume(&raw, consumed);
            zu_response_free(&resp);
            zu_response_init(&resp);
            consumed = 0;
            rc = read_headers(s, &raw, &resp, &consumed, total, err);
        }
        if (rc == ZU_OK) rc = zu_response_decide_framing(&resp, is_head, err);
        if (rc == ZU_OK) {
            /* §19.5: "Redirect response bodies must never reach the caller's
             * sink." A 3xx we are going to follow is drained into a capped
             * buffer instead — drained rather than skipped, because the
             * connection is only poolable if the body was consumed whole.
             *
             * The buffer, rather than a discard sink, is because the redirect
             * DECISION has not been made yet: zu_redirect_decide() may refuse
             * to follow (a cross-scheme downgrade, say), and then this 3xx is
             * the response the caller receives and its body is theirs. Held
             * bytes are bounded by ZU_MAX_REDIRECT_BODY, so this is not a
             * route back to buffering a large body. */
            int may_follow = zu_status_is_redirect(resp.status) &&
                             hops < (size_t)o->max_redirects &&
                             zu_headers_get(&resp.headers, "Location") != NULL;
            uint64_t cap = o->max_body ? o->max_body : ZU_DEFAULT_MAX_BODY;

            fr = resp.framing;
            /* A followed redirect's body lands in the result buffer, which
             * is reset before the next hop — never in the caller's sink. When
             * the decision below turns out to be "do not follow", the 3xx is
             * the caller's response and those bytes are flushed onward. */
            hop_sink = may_follow ? &mem_sink : body_sink;
            if (may_follow) cap = ZU_MAX_REDIRECT_BODY;
            /* Per hop, not cumulative: the limit describes one body. */
            hop_sink->written = 0;
            rc = zu_body_pipe_init(&pipe, hop_sink, &resp.headers,
                                   o->no_decode, cap, err);
            if (rc == ZU_OK)
                rc = zu_body_read(s, &fr, &pipe,
                               (const char *)raw.data + consumed, raw.len - consumed,
                               cap, total, err);
            zu_body_pipe_free(&pipe);
        }
        zu_buf_free(&raw);
        /* §26.3. The decision is made HERE, while the framing and the
         * response headers that justify it are still in scope — not inside
         * the pool, which cannot see them. */
        {
            zu_reuse reason = zu_reuse_decide(rc, &fr, &resp.headers,
                                              resp.minor_version);
            /* §27.2: a sink that asked to stop ended the transfer CLEANLY —
             * the caller gets their response. The connection still cannot be
             * reused, because the body was not read to its end and the
             * framing position is therefore unknown (§26.3). Flipping rc here
             * rather than in the R layer matters: the engine has to keep
             * building the result, and by the time it has returned an error
             * the result is already torn down. */
            if (rc == ZU_ERR_CANCELLED && hop_sink && hop_sink->stopped) {
                rc = ZU_OK;
                reason = ZU_NOREUSE_CANCELLED;
            }
            done_with_stream(o, &cur, &px, s, reason);
        }

        if (rc != ZU_OK) {
            zu_response_free(&resp); zu_uri_free(&cur); zu_result_free(out);
            zu_proxy_free(&px);
            return rc;
        }

        out->status = resp.status;
        out->http_version = resp.minor_version;
        zu_headers_free(&out->headers);
        out->headers = resp.headers;          /* ownership moves */
        zu_headers_init(&resp.headers);
        zu_response_free(&resp);

        /* --- redirect? --- */
        if (zu_status_is_redirect(out->status) && hops < (size_t)o->max_redirects) {
            const char *loc = zu_headers_get(&out->headers, "Location");
            zu_uri next;
            zu_redirect_policy pol;
            zu_redirect_decision dec;

            if (!loc) break;                  /* a redirect with no Location */
            rc = zu_uri_resolve(&next, &cur, loc, loc + strlen(loc));
            if (rc != ZU_OK) {
                zu_error_set(err, ZU_ERR_URL, ZU_PHASE_NONE,
                             "redirect Location is not a usable URL");
                zu_uri_free(&cur); zu_result_free(out);
                return ZU_ERR_URL;
            }
            zu_redirect_policy_init(&pol);
            pol.max_redirects = (size_t)o->max_redirects;
            rc = zu_redirect_decide(&pol, out->status, method, &cur, &next,
                                    hops, &dec, err);
            if (rc != ZU_OK) {
                zu_uri_free(&next); zu_uri_free(&cur); zu_result_free(out); zu_proxy_free(&px);
                return rc;
            }
            if (dec.action == ZU_REDIRECT_FOLLOW) {
                /* §19.1: a rewritten method drops the body with it. Keeping
                 * the body after 303 -> GET would send a body no method
                 * expects. */
                if (dec.rewrite_to_get) { method = "GET"; is_head = 0; }
                if (dec.drop_body) { body = NULL; body_len = 0; }
                zu_uri_free(&cur);
                cur = next;
                hops++;
                out->redirects = (int)hops;
                zu_buf_reset(&out->body);
                zu_headers_free(&out->headers);
                zu_headers_init(&out->headers);
                zu_proxy_free(&px);           /* re-resolved for the next hop */
                continue;                     /* §19.5: the body never reaches the caller */
            }
            zu_uri_free(&next);
        }
        /* The decision was "do not follow", so this 3xx IS the caller's
         * response and the bytes held for it are theirs. Without this a
         * download whose final hop is an unfollowed redirect would leave an
         * empty file and put the body somewhere the caller never looks. */
        if (body_sink != &mem_sink && out->body.len) {
            rc = zu_sink_write(body_sink, out->body.data, out->body.len, err);
            zu_buf_reset(&out->body);
            if (rc != ZU_OK) { zu_uri_free(&cur); zu_result_free(out); return rc; }
        }
        break;
    }

    out->final_url = url_of(&cur);
    zu_uri_free(&cur);
    if (!out->final_url) { zu_result_free(out); return ZU_ERR_NOMEM; }
    return ZU_OK;
}

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
#include "zu_time.h"
#include <string.h>
#include <stdio.h>

#define ZU_DEFAULT_TIMEOUT_MS  30000
#define ZU_DEFAULT_MAX_BODY    (16u * 1024u * 1024u)
#define ZU_MAX_HEADER_BYTES    (64u * 1024u)
#define ZU_READ_CHUNK          16384

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
 * Built from the URI and the TLS settings this engine actually applies. That
 * is the whole of the §26.1 key that varies today: zu_get_opts carries no
 * proxy, no pin set, no client certificate and no ALPN override, so those
 * fields stay NULL rather than being invented here.
 *
 * When any of them IS plumbed through zu_get_opts, it must be added here in
 * the same commit. A key that ignores a field two clients differ on is the
 * "coarse key is a security bug, not a performance optimisation" failure
 * §26.1 names — it would let a request with verification off reuse a
 * connection established with it on. zu_pool_key_eq() compares every field of
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
static int pool_key_for(zu_pool_key *k, const zu_uri *u, const zu_get_opts *o) {
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
                             zu_stream *s, zu_reuse r) {
    zu_pool_key key;
    if (!s) return;
    if (o->pool && pool_key_for(&key, u, o)) {
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
    res->tls_version = dup_str(info.protocol);
    res->tls_cipher  = dup_str(info.cipher);
}

static zu_code open_stream(zu_stream **out, const zu_uri *u,
                           const zu_get_opts *o, zu_deadline dl,
                           zu_result *res, zu_error *err) {
    zu_net_opts nopts;
    zu_stream *tcp = NULL;
    zu_code rc;

    /* §26: a live connection for this exact key, if the pool has one. The
     * pool has already run the fork guard, the idle-timeout check and the
     * §26.2 liveness probe by the time it answers, so a non-NULL return is
     * usable as-is. */
    if (o->pool) {
        zu_pool_key key;
        zu_stream *reused = NULL;
        if (!pool_key_for(&key, u, o)) return ZU_ERR_NOMEM;
        reused = zu_pool_acquire(o->pool, &key);
        zu_pool_key_free(&key);
        if (reused) {
            if (u->is_https) record_tls_info(reused, res);
            *out = reused;
            return ZU_OK;
        }
    }

    zu_net_opts_init(&nopts);
    nopts.tick     = o->tick;
    nopts.tick_ctx = o->tick_ctx;

    rc = zu_net_connect(&tcp, u->host, u->port, dl, &nopts, err);
    if (rc != ZU_OK) return rc;

    if (!u->is_https) { *out = tcp; return ZU_OK; }

    if (!zu_tls_available()) {
        zu_error_set(err, ZU_ERR_TLS, ZU_PHASE_TLS,
                     "this build has no TLS backend, so https:// is unavailable");
        zu_stream_free(tcp);
        return ZU_ERR_TLS;
    }
    {
        zu_tls_config cfg;
        zu_stream *tls = NULL;

        zu_tls_config_init(&cfg);
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
static zu_code read_body(zu_stream *s, const zu_framing *fr, zu_buffer *out,
                         const char *seed, size_t seed_len,
                         uint64_t max_body, zu_deadline dl, zu_error *err) {
    if (fr->kind == ZU_FRAME_NONE) return ZU_OK;

    if (fr->kind == ZU_FRAME_CHUNKED) {
        zu_chunked dec;
        char *work;
        zu_code rc = zu_chunked_init(&dec, 0, max_body);
        if (rc != ZU_OK) return rc;

        work = (char *)zu_alloc(ZU_READ_CHUNK);
        if (!work) { zu_chunked_free(&dec); return ZU_ERR_NOMEM; }

        if (seed_len) {
            size_t len = seed_len;
            memcpy(work, seed, seed_len);
            rc = zu_chunked_decode(&dec, work, &len, err);
            if (len && !zu_buf_append(out, work, len)) rc = ZU_ERR_NOMEM;
        } else {
            rc = ZU_ERR_WOULDBLOCK;
        }
        while (rc == ZU_ERR_WOULDBLOCK) {
            size_t len;
            zu_ssize n = zu_stream_read(s, work, ZU_READ_CHUNK, dl, err);
            if (n < 0) { rc = err->code; break; }
            if (n == 0) {
                zu_error_set(err, ZU_ERR_PARSE, ZU_PHASE_READ,
                             "connection closed inside a chunked body");
                rc = ZU_ERR_PARSE;
                break;
            }
            len = (size_t)n;
            rc = zu_chunked_decode(&dec, work, &len, err);
            if (len && !zu_buf_append(out, work, len)) { rc = ZU_ERR_NOMEM; break; }
        }
        zu_free(work);
        zu_chunked_free(&dec);
        return rc == ZU_OK ? ZU_OK : rc;
    }

    /* LENGTH and UNTIL_CLOSE differ only in when they stop. */
    if (seed_len && !zu_buf_append(out, seed, seed_len)) return ZU_ERR_NOMEM;
    for (;;) {
        char chunk[ZU_READ_CHUNK];
        zu_ssize n;

        if (fr->kind == ZU_FRAME_LENGTH && out->len >= fr->length) break;
        if (out->len > max_body) {
            zu_error_set(err, ZU_ERR_BODY_LIMIT, ZU_PHASE_READ,
                         "response body exceeds the configured limit");
            return ZU_ERR_BODY_LIMIT;
        }
        n = zu_stream_read(s, chunk, sizeof chunk, dl, err);
        if (n < 0) return err->code;
        if (n == 0) {
            if (fr->kind == ZU_FRAME_UNTIL_CLOSE) break;
            zu_error_set(err, ZU_ERR_PARSE, ZU_PHASE_READ,
                         "connection closed with %lu of %lu body bytes read",
                         (unsigned long)out->len, (unsigned long)fr->length);
            return ZU_ERR_PARSE;
        }
        if (!zu_buf_append(out, chunk, (size_t)n)) return ZU_ERR_NOMEM;
    }
    if (fr->kind == ZU_FRAME_LENGTH && out->len > fr->length)
        out->len = (size_t)fr->length;   /* trailing bytes are the next response */
    return ZU_OK;
}

/* §21: decode Content-Encoding in place. */
static zu_code decode_body(zu_headers *h, zu_buffer *body, uint64_t max_body,
                           zu_error *err) {
    const char *enc = zu_headers_get(h, "Content-Encoding");
    zu_encoding kind = zu_encoding_parse(enc);
    zu_inflate z;
    zu_buffer out;
    zu_code rc;

    if (kind == ZU_ENC_IDENTITY) return ZU_OK;
    if (kind == ZU_ENC_UNSUPPORTED) {
        zu_error_set(err, ZU_ERR_BODY_DECODE, ZU_PHASE_DECODE,
                     "unsupported Content-Encoding: %s", enc ? enc : "(none)");
        return ZU_ERR_BODY_DECODE;
    }
    rc = zu_inflate_init(&z, kind, max_body, 0);
    if (rc != ZU_OK) return rc;
    if (!zu_buf_init(&out, body->len ? body->len * 2 : 256, max_body * 2 + 1024)) {
        zu_inflate_free(&z);
        return ZU_ERR_NOMEM;
    }
    rc = zu_inflate_run(&z, body->data, body->len, &out, err);
    zu_inflate_free(&z);
    if (rc != ZU_OK && rc != ZU_ERR_WOULDBLOCK) { zu_buf_free(&out); return rc; }

    zu_buf_free(body);
    *body = out;                     /* ownership moves */
    /* The body is no longer encoded, so the header would now be a lie. */
    (void)zu_headers_remove(h, "Content-Encoding");
    (void)zu_headers_remove(h, "Content-Length");
    return ZU_OK;
}

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
    const char *method = (req && req->method) ? req->method : "GET";
    const void *body   = req ? req->body : NULL;
    size_t body_len    = req ? req->body_len : 0;
    size_t n_hdr       = req ? req->n_headers : 0;
    int is_head        = (strcmp(method, "HEAD") == 0);

    if (!out || !url) return ZU_ERR_URL;
    zu_result_init(out);
    if (!o) { zu_get_opts_init(&defaults); o = &defaults; }

    /* §24.1: one deadline for the whole operation, redirects included. */
    total = zu_deadline_in(o->timeout_ms > 0 ? o->timeout_ms : ZU_DEFAULT_TIMEOUT_MS);

    rc = zu_uri_parse(&cur, url, url + strlen(url));
    if (rc != ZU_OK) {
        zu_error_set(err, ZU_ERR_URL, ZU_PHASE_NONE, "not a usable URL: %s", url);
        return ZU_ERR_URL;
    }

    for (;;) {
        zu_stream *s = NULL;
        zu_request rq;
        zu_response resp;
        size_t hi;
        zu_buffer wire, raw;
        size_t consumed = 0;
        /* Pre-set to the §26.3 safe default. `fr` is only really filled once
         * zu_response_decide_framing() succeeds, so every path that fails
         * before that point must still give reuse_after() something that
         * means "do not reuse" rather than whatever was on the stack. */
        zu_framing fr = { ZU_FRAME_UNTIL_CLOSE, 0, 0 };

        rc = open_stream(&s, &cur, o, total, out, err);
        if (rc != ZU_OK) { zu_uri_free(&cur); zu_result_free(out); return rc; }

        /* --- send --- */
        zu_request_init(&rq);
        rq.method = method;
        rq.target = cur.path_query;
        rq.host   = cur.host;
        rq.form   = ZU_TARGET_ORIGIN;
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
                zu_uri_free(&cur); zu_result_free(out);
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
                zu_uri_free(&cur); zu_result_free(out);
                return rc;
            }
        }
        if (!zu_buf_init(&wire, 512, 64 * 1024)) {
            zu_request_free(&rq); zu_stream_free(s);
            zu_uri_free(&cur); zu_result_free(out);
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
        zu_request_free(&rq);
        if (rc != ZU_OK) {
            zu_stream_free(s); zu_uri_free(&cur); zu_result_free(out);
            return rc;
        }

        /* --- receive --- */
        zu_response_init(&resp);
        if (!zu_buf_init(&raw, 4096, ZU_MAX_HEADER_BYTES + ZU_READ_CHUNK)) {
            zu_response_free(&resp); zu_stream_free(s);
            zu_uri_free(&cur); zu_result_free(out);
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
            fr = resp.framing;
            rc = read_body(s, &fr, &out->body,
                           (const char *)raw.data + consumed, raw.len - consumed,
                           o->max_body ? o->max_body : ZU_DEFAULT_MAX_BODY,
                           total, err);
        }
        zu_buf_free(&raw);
        /* §26.3. The decision is made HERE, while the framing and the
         * response headers that justify it are still in scope — not inside
         * the pool, which cannot see them. */
        done_with_stream(o, &cur, s, zu_reuse_decide(rc, &fr, &resp.headers, resp.minor_version));

        if (rc != ZU_OK) {
            zu_response_free(&resp); zu_uri_free(&cur); zu_result_free(out);
            return rc;
        }

        out->status = resp.status;
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
                zu_uri_free(&next); zu_uri_free(&cur); zu_result_free(out);
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
                continue;                     /* §19.5: the body never reaches the caller */
            }
            zu_uri_free(&next);
        }
        break;
    }

    if (!o->no_decode) {
        rc = decode_body(&out->headers, &out->body,
                         o->max_body ? o->max_body : ZU_DEFAULT_MAX_BODY, err);
        if (rc != ZU_OK) { zu_uri_free(&cur); zu_result_free(out); return rc; }
    }

    out->final_url = url_of(&cur);
    zu_uri_free(&cur);
    if (!out->final_url) { zu_result_free(out); return ZU_ERR_NOMEM; }
    return ZU_OK;
}

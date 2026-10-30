#include "zuh_pool.h"
#include "zuh_alloc.h"
#include "zuh_headers.h"   /* zuh_ascii_casecmp, and §26.3 reads Connection */
#include <string.h>

/* --- small string helpers ------------------------------------------------ */

static char *dup_or_null(const char *s) {
    size_t n;
    char *p;
    if (!s) return NULL;
    n = strlen(s);
    p = (char *)zuh_alloc(n + 1);
    if (p) memcpy(p, s, n + 1);
    return p;
}

/* NULL and "" are DIFFERENT here: an empty ca_file is a caller error we want
 * to see, not a synonym for "unset". */
static int str_eq(const char *a, const char *b) {
    if (a == b) return 1;
    if (!a || !b) return 0;
    return strcmp(a, b) == 0;
}

/* Scheme and host are case-insensitive per RFC 3986; everything else is not.
 * zuh_uri lowercases both already, so this is belt-and-braces for keys built
 * by hand (proxy config, tests). */
static int str_eq_ci(const char *a, const char *b) {
    if (a == b) return 1;
    if (!a || !b) return 0;
    return zuh_ascii_casecmp(a, b) == 0;
}

/* --- §26.1 key ----------------------------------------------------------- */

void zuh_pool_key_init(zuh_pool_key *k) {
    if (!k) return;
    memset(k, 0, sizeof *k);
    k->verify_peer     = 1;
    k->verify_hostname = 1;
}

void zuh_pool_key_free(zuh_pool_key *k) {
    if (!k) return;
    zuh_free(k->scheme);   zuh_free(k->host);       zuh_free(k->proxy);
    zuh_free(k->alpn);     zuh_free(k->ca_file);    zuh_free(k->ca_extra_file);
    zuh_free(k->ca_data_id); zuh_free(k->pins);     zuh_free(k->client_cert);
    memset(k, 0, sizeof *k);
}

#define COPY_STR(field)                                             \
    do { if (src->field) {                                          \
            dst->field = dup_or_null(src->field);                   \
            if (!dst->field) { zuh_pool_key_free(dst); return 0; }   \
        } } while (0)

int zuh_pool_key_copy(zuh_pool_key *dst, const zuh_pool_key *src) {
    if (!dst || !src) return 0;
    zuh_pool_key_init(dst);
    dst->port            = src->port;
    dst->verify_peer     = src->verify_peer;
    dst->verify_hostname = src->verify_hostname;
    dst->revocation      = src->revocation;
    dst->min_version     = src->min_version;
    COPY_STR(scheme); COPY_STR(host); COPY_STR(proxy); COPY_STR(alpn);
    COPY_STR(ca_file); COPY_STR(ca_extra_file); COPY_STR(ca_data_id);
    COPY_STR(pins); COPY_STR(client_cert);
    return 1;
}
#undef COPY_STR

int zuh_pool_key_eq(const zuh_pool_key *a, const zuh_pool_key *b) {
    if (a == b) return 1;
    if (!a || !b) return 0;
    /* Every field of §26.1. Adding a field to zuh_pool_key without adding it
     * here is the "coarse key" security bug that section warns about; the
     * test suite walks every field to catch exactly that. */
    return a->port            == b->port
        && a->verify_peer     == b->verify_peer
        && a->verify_hostname == b->verify_hostname
        && a->revocation      == b->revocation
        && a->min_version     == b->min_version
        && str_eq_ci(a->scheme, b->scheme)
        && str_eq_ci(a->host,   b->host)
        && str_eq(a->proxy,         b->proxy)
        && str_eq(a->alpn,          b->alpn)
        && str_eq(a->ca_file,       b->ca_file)
        && str_eq(a->ca_extra_file, b->ca_extra_file)
        && str_eq(a->ca_data_id,    b->ca_data_id)
        && str_eq(a->pins,          b->pins)
        && str_eq(a->client_cert,   b->client_cert);
}

/* --- §26.3 reasons ------------------------------------------------------- */

static const char *const k_reuse_name[ZUH_REUSE_REASON_COUNT] = {
    "ok",
    "body_incomplete",
    "cancelled",
    "framing",
    "close_framed",
    "connection_close",
    "redirect_body",
    "tls_error"
};

const char *zuh_reuse_name(zuh_reuse r) {
    if (r < 0 || r >= ZUH_REUSE_REASON_COUNT) return "unknown";
    return k_reuse_name[r];
}

/* --- pool ---------------------------------------------------------------- */

typedef struct pool_entry {
    struct pool_entry *next;
    zuh_pool_key        key;
    zuh_stream         *stream;
    zuh_millis          idle_since;
} pool_entry;

struct zuh_pool {
    pool_entry     *head;         /* most recently released first */
    size_t          idle;
    zuh_pool_config  cfg;
    zuh_fork_guard   guard;
    zuh_pool_stats   stats;
    zuh_millis     (*now_ms)(void *);
    void           *now_ctx;
};

void zuh_pool_config_init(zuh_pool_config *c) {
    if (!c) return;
    c->max_idle        = 16;
    c->max_per_host    = 4;
    c->idle_timeout_ms = 30000;
    c->stale_probe_ms  = 0;   /* non-blocking: the answer is already known */
}

static zuh_millis pool_now(const zuh_pool *p) {
    if (p->now_ms) return p->now_ms(p->now_ctx);
    return zuh_now_ms();
}

zuh_pool *zuh_pool_new(const zuh_pool_config *cfg) {
    zuh_pool *p = (zuh_pool *)zuh_calloc(1, sizeof *p);
    if (!p) return NULL;
    if (cfg) p->cfg = *cfg;
    else     zuh_pool_config_init(&p->cfg);
    zuh_fork_guard_arm(&p->guard);
    return p;
}

void zuh_pool_set_clock(zuh_pool *p, zuh_millis (*now_ms)(void *), void *ctx) {
    if (!p) return;
    p->now_ms  = now_ms;
    p->now_ctx = ctx;
}

/* Unlink and release one entry. `graceful` is 0 for inherited connections:
 * §26.4 requires dropping them WITHOUT a TLS shutdown, because a graceful
 * close would write to a socket the parent still owns. */
static void entry_destroy(pool_entry *e, int graceful) {
    if (!e) return;
    if (e->stream) {
        if (graceful) zuh_stream_close(e->stream);
        zuh_stream_free(e->stream);
    }
    zuh_pool_key_free(&e->key);
    zuh_free(e);
}

void zuh_pool_clear(zuh_pool *p) {
    pool_entry *e, *next;
    if (!p) return;
    for (e = p->head; e; e = next) { next = e->next; entry_destroy(e, 1); }
    p->head = NULL;
    p->idle = 0;
    p->stats.idle = 0;
}

int zuh_pool_check_fork(zuh_pool *p) {
    pool_entry *e, *next;
    size_t dropped = 0;
    if (!p) return 0;
    if (!zuh_fork_guard_tripped(&p->guard)) return 0;

    for (e = p->head; e; e = next) {
        next = e->next;
        entry_destroy(e, 0);   /* NOT graceful — the parent owns these sockets */
        dropped++;
    }
    p->head = NULL;
    p->idle = 0;
    p->stats.idle = 0;
    p->stats.discarded_fork += dropped;
    p->stats.forks_detected++;
    zuh_fork_guard_arm(&p->guard);   /* the child now owns an empty pool */
    return 1;
}

void zuh_pool_free(zuh_pool *p) {
    if (!p) return;
    /* A finalizer runs in whichever process holds the last reference, so the
     * guard applies here too (§26.4: "in every finalizer"). */
    if (zuh_fork_guard_tripped(&p->guard)) zuh_pool_check_fork(p);
    else                                  zuh_pool_clear(p);
    zuh_free(p);
}

static size_t count_for_host(const zuh_pool *p, const zuh_pool_key *key) {
    const pool_entry *e;
    size_t n = 0;
    for (e = p->head; e; e = e->next)
        if (e->key.port == key->port
            && str_eq_ci(e->key.scheme, key->scheme)
            && str_eq_ci(e->key.host, key->host)) n++;
    return n;
}

/* §26.2: expired, or readable before we have written anything. A readable
 * idle socket is either closed by the peer or carrying unread bytes from a
 * previous response; both mean discard. An "unknown" probe (-1) is treated as
 * NOT stale, because a backend with no probe would otherwise empty the pool
 * on every acquisition — the expiry check remains the backstop. */
static int entry_unusable(zuh_pool *p, pool_entry *e, zuh_millis now) {
    if (p->cfg.idle_timeout_ms > 0 && now - e->idle_since >= p->cfg.idle_timeout_ms) {
        p->stats.discarded_expired++;
        return 1;
    }
    if (zuh_stream_readable(e->stream, p->cfg.stale_probe_ms) == 1) {
        p->stats.discarded_stale++;
        return 1;
    }
    return 0;
}

zuh_stream *zuh_pool_acquire(zuh_pool *p, const zuh_pool_key *key) {
    pool_entry **link, *e;
    zuh_millis now;
    if (!p || !key) return NULL;

    zuh_pool_check_fork(p);          /* §26.4: on EVERY acquisition */
    now = pool_now(p);

    for (link = &p->head; (e = *link) != NULL; ) {
        if (!zuh_pool_key_eq(&e->key, key)) { link = &e->next; continue; }
        *link = e->next;
        p->idle--;
        if (entry_unusable(p, e, now)) { entry_destroy(e, 1); continue; }
        {
            zuh_stream *s = e->stream;
            e->stream = NULL;
            zuh_pool_key_free(&e->key);
            zuh_free(e);
            p->stats.hits++;
            p->stats.idle = p->idle;
            return s;
        }
    }
    p->stats.misses++;
    p->stats.idle = p->idle;
    return NULL;
}

/* Drop the least recently released entry, optionally only for one host. */
static void evict_oldest(zuh_pool *p, const zuh_pool_key *host_of) {
    pool_entry **link, **victim = NULL;
    pool_entry *e;
    for (link = &p->head; (e = *link) != NULL; link = &e->next) {
        if (host_of && !(e->key.port == host_of->port
                         && str_eq_ci(e->key.scheme, host_of->scheme)
                         && str_eq_ci(e->key.host, host_of->host))) continue;
        victim = link;   /* the list is newest-first, so the last match is oldest */
    }
    if (!victim) return;
    e = *victim;
    *victim = e->next;
    entry_destroy(e, 1);
    p->idle--;
    p->stats.discarded_capacity++;
}

void zuh_pool_release(zuh_pool *p, const zuh_pool_key *key, zuh_stream *s, zuh_reuse r) {
    pool_entry *e;

    if (!s) return;
    if (!p || !key) { zuh_stream_close(s); zuh_stream_free(s); return; }

    zuh_pool_check_fork(p);

    /* §26.3: "The safe default is to close." */
    if (r != ZUH_REUSE_OK) {
        p->stats.discarded_unusable++;
        zuh_stream_close(s);
        zuh_stream_free(s);
        return;
    }
    /* Already readable at release time means unread bytes remain: the caller
     * believes the body was complete and it was not. Do not pool it. */
    if (zuh_stream_readable(s, p->cfg.stale_probe_ms) == 1) {
        p->stats.discarded_stale++;
        zuh_stream_close(s);
        zuh_stream_free(s);
        return;
    }
    if (p->cfg.max_idle == 0) {
        p->stats.discarded_capacity++;
        zuh_stream_close(s);
        zuh_stream_free(s);
        return;
    }

    e = (pool_entry *)zuh_calloc(1, sizeof *e);
    if (!e || !zuh_pool_key_copy(&e->key, key)) {
        zuh_free(e);
        zuh_stream_close(s);
        zuh_stream_free(s);
        return;
    }
    e->stream     = s;
    e->idle_since = pool_now(p);

    if (p->cfg.max_per_host > 0 && count_for_host(p, key) >= p->cfg.max_per_host)
        evict_oldest(p, key);
    while (p->idle >= p->cfg.max_idle)
        evict_oldest(p, NULL);

    e->next = p->head;
    p->head = e;
    p->idle++;
    p->stats.idle = p->idle;
}

void zuh_pool_stats_get(const zuh_pool *p, zuh_pool_stats *out) {
    if (!out) return;
    if (!p) { memset(out, 0, sizeof *out); return; }
    *out = p->stats;
    out->idle = p->idle;
}

size_t zuh_pool_idle_count(const zuh_pool *p) { return p ? p->idle : 0; }

/* Does a comma-separated header value carry `tok` as a token?
 *
 * `Connection: close` is the common case, but the field is a LIST — a server
 * may legitimately send "keep-alive, close" or "Upgrade, close", and RFC 9110
 * makes the comparison case-insensitive. Matching the whole value against
 * "close" (which an earlier draft of this function did) silently reuses a
 * connection the server just said it was closing, and the symptom is the next
 * request on that socket failing for no visible reason. */
static int header_has_token(const char *v, const char *tok) {
    size_t n = strlen(tok);
    if (!v) return 0;
    while (*v) {
        const char *end;
        size_t len;
        while (*v == ' ' || *v == '\t' || *v == ',') v++;
        if (!*v) break;
        end = v;
        while (*end && *end != ',') end++;
        len = (size_t)(end - v);
        while (len > 0 && (v[len - 1] == ' ' || v[len - 1] == '\t')) len--;
        if (len == n) {
            size_t i;
            for (i = 0; i < n; i++) {
                char a = v[i], b = tok[i];
                if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
                if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
                if (a != b) break;
            }
            if (i == n) return 1;
        }
        v = end;
    }
    return 0;
}

/* Any Connection header carrying the token, not just the first: a response
 * with two Connection lines is unusual but legal, and the safe reading is the
 * union of them. */
static int connection_has(const zuh_headers *h, const char *tok) {
    size_t n = zuh_headers_count(h, "Connection"), i;
    for (i = 0; i < n; i++)
        if (header_has_token(zuh_headers_get_at(h, "Connection", i), tok))
            return 1;
    return 0;
}

zuh_reuse zuh_reuse_decide(zuh_code rc, const zuh_framing *fr,
                         const zuh_headers *resp_headers, int minor_version) {

    if (rc != ZUH_OK) {
        switch (rc) {
            case ZUH_ERR_TIMEOUT:
            case ZUH_ERR_CANCELLED:
            case ZUH_ERR_INTERRUPTED:  return ZUH_NOREUSE_CANCELLED;
            case ZUH_ERR_PARSE:        return ZUH_NOREUSE_FRAMING;
            case ZUH_ERR_TLS:
            case ZUH_ERR_TLS_CERT:
            case ZUH_ERR_TLS_HOSTNAME:
            case ZUH_ERR_TLS_HANDSHAKE:
            case ZUH_ERR_TLS_PIN:
            case ZUH_ERR_TLS_UNSUPPORTED: return ZUH_NOREUSE_TLS_ERROR;
            /* Anything else means the body did not arrive whole, so the next
             * response cannot be located on this connection. */
            default:                  return ZUH_NOREUSE_BODY_INCOMPLETE;
        }
    }

    /* Rule 5 of §18.1: no framing information, body ends at EOF. */
    if (!fr->poolable || fr->kind == ZUH_FRAME_UNTIL_CLOSE)
        return ZUH_NOREUSE_CLOSE_FRAMED;

    /* Either side may end the connection; the server's word is in the
     * response. Our own request says close only when there is no pool
     * (§17.2), and then nothing is pooled, so only the response is checked. */
    if (connection_has(resp_headers, "close"))
        return ZUH_NOREUSE_CONNECTION_CLOSE;

    /* HTTP/1.0 is not persistent by default — it is persistent only if the
     * server opts in with `Connection: keep-alive`. Treating a 1.0 response
     * like a 1.1 one leaves a connection in the pool that the server is about
     * to close, and the next request to draw it fails. §26.3's "the safe
     * default is to close" is exactly this case. */
    if (minor_version == 0 && !connection_has(resp_headers, "keep-alive"))
        return ZUH_NOREUSE_CONNECTION_CLOSE;

    return ZUH_REUSE_OK;
}


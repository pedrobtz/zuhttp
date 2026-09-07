#include "zu_pool.h"
#include "zu_alloc.h"
#include "zu_headers.h"   /* zu_ascii_casecmp */
#include <string.h>

/* --- small string helpers ------------------------------------------------ */

static char *dup_or_null(const char *s) {
    size_t n;
    char *p;
    if (!s) return NULL;
    n = strlen(s);
    p = (char *)zu_alloc(n + 1);
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
 * zu_uri lowercases both already, so this is belt-and-braces for keys built
 * by hand (proxy config, tests). */
static int str_eq_ci(const char *a, const char *b) {
    if (a == b) return 1;
    if (!a || !b) return 0;
    return zu_ascii_casecmp(a, b) == 0;
}

/* --- §26.1 key ----------------------------------------------------------- */

void zu_pool_key_init(zu_pool_key *k) {
    if (!k) return;
    memset(k, 0, sizeof *k);
    k->verify_peer     = 1;
    k->verify_hostname = 1;
}

void zu_pool_key_free(zu_pool_key *k) {
    if (!k) return;
    zu_free(k->scheme);   zu_free(k->host);       zu_free(k->proxy);
    zu_free(k->alpn);     zu_free(k->ca_file);    zu_free(k->ca_extra_file);
    zu_free(k->ca_data_id); zu_free(k->pins);     zu_free(k->client_cert);
    memset(k, 0, sizeof *k);
}

#define COPY_STR(field)                                             \
    do { if (src->field) {                                          \
            dst->field = dup_or_null(src->field);                   \
            if (!dst->field) { zu_pool_key_free(dst); return 0; }   \
        } } while (0)

int zu_pool_key_copy(zu_pool_key *dst, const zu_pool_key *src) {
    if (!dst || !src) return 0;
    zu_pool_key_init(dst);
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

int zu_pool_key_eq(const zu_pool_key *a, const zu_pool_key *b) {
    if (a == b) return 1;
    if (!a || !b) return 0;
    /* Every field of §26.1. Adding a field to zu_pool_key without adding it
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

static const char *const k_reuse_name[ZU_REUSE_REASON_COUNT] = {
    "ok",
    "body_incomplete",
    "cancelled",
    "framing",
    "close_framed",
    "connection_close",
    "redirect_body",
    "tls_error"
};

const char *zu_reuse_name(zu_reuse r) {
    if (r < 0 || r >= ZU_REUSE_REASON_COUNT) return "unknown";
    return k_reuse_name[r];
}

/* --- pool ---------------------------------------------------------------- */

typedef struct pool_entry {
    struct pool_entry *next;
    zu_pool_key        key;
    zu_stream         *stream;
    zu_millis          idle_since;
} pool_entry;

struct zu_pool {
    pool_entry     *head;         /* most recently released first */
    size_t          idle;
    zu_pool_config  cfg;
    zu_fork_guard   guard;
    zu_pool_stats   stats;
    zu_millis     (*now_ms)(void *);
    void           *now_ctx;
};

void zu_pool_config_init(zu_pool_config *c) {
    if (!c) return;
    c->max_idle        = 16;
    c->max_per_host    = 4;
    c->idle_timeout_ms = 30000;
    c->stale_probe_ms  = 0;   /* non-blocking: the answer is already known */
}

static zu_millis pool_now(const zu_pool *p) {
    if (p->now_ms) return p->now_ms(p->now_ctx);
    return zu_now_ms();
}

zu_pool *zu_pool_new(const zu_pool_config *cfg) {
    zu_pool *p = (zu_pool *)zu_calloc(1, sizeof *p);
    if (!p) return NULL;
    if (cfg) p->cfg = *cfg;
    else     zu_pool_config_init(&p->cfg);
    zu_fork_guard_arm(&p->guard);
    return p;
}

void zu_pool_set_clock(zu_pool *p, zu_millis (*now_ms)(void *), void *ctx) {
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
        if (graceful) zu_stream_close(e->stream);
        zu_stream_free(e->stream);
    }
    zu_pool_key_free(&e->key);
    zu_free(e);
}

void zu_pool_clear(zu_pool *p) {
    pool_entry *e, *next;
    if (!p) return;
    for (e = p->head; e; e = next) { next = e->next; entry_destroy(e, 1); }
    p->head = NULL;
    p->idle = 0;
    p->stats.idle = 0;
}

int zu_pool_check_fork(zu_pool *p) {
    pool_entry *e, *next;
    size_t dropped = 0;
    if (!p) return 0;
    if (!zu_fork_guard_tripped(&p->guard)) return 0;

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
    zu_fork_guard_arm(&p->guard);   /* the child now owns an empty pool */
    return 1;
}

void zu_pool_free(zu_pool *p) {
    if (!p) return;
    /* A finalizer runs in whichever process holds the last reference, so the
     * guard applies here too (§26.4: "in every finalizer"). */
    if (zu_fork_guard_tripped(&p->guard)) zu_pool_check_fork(p);
    else                                  zu_pool_clear(p);
    zu_free(p);
}

static size_t count_for_host(const zu_pool *p, const zu_pool_key *key) {
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
static int entry_unusable(zu_pool *p, pool_entry *e, zu_millis now) {
    if (p->cfg.idle_timeout_ms > 0 && now - e->idle_since >= p->cfg.idle_timeout_ms) {
        p->stats.discarded_expired++;
        return 1;
    }
    if (zu_stream_readable(e->stream, p->cfg.stale_probe_ms) == 1) {
        p->stats.discarded_stale++;
        return 1;
    }
    return 0;
}

zu_stream *zu_pool_acquire(zu_pool *p, const zu_pool_key *key) {
    pool_entry **link, *e;
    zu_millis now;
    if (!p || !key) return NULL;

    zu_pool_check_fork(p);          /* §26.4: on EVERY acquisition */
    now = pool_now(p);

    for (link = &p->head; (e = *link) != NULL; ) {
        if (!zu_pool_key_eq(&e->key, key)) { link = &e->next; continue; }
        *link = e->next;
        p->idle--;
        if (entry_unusable(p, e, now)) { entry_destroy(e, 1); continue; }
        {
            zu_stream *s = e->stream;
            e->stream = NULL;
            zu_pool_key_free(&e->key);
            zu_free(e);
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
static void evict_oldest(zu_pool *p, const zu_pool_key *host_of) {
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

void zu_pool_release(zu_pool *p, const zu_pool_key *key, zu_stream *s, zu_reuse r) {
    pool_entry *e;

    if (!s) return;
    if (!p || !key) { zu_stream_close(s); zu_stream_free(s); return; }

    zu_pool_check_fork(p);

    /* §26.3: "The safe default is to close." */
    if (r != ZU_REUSE_OK) {
        p->stats.discarded_unusable++;
        zu_stream_close(s);
        zu_stream_free(s);
        return;
    }
    /* Already readable at release time means unread bytes remain: the caller
     * believes the body was complete and it was not. Do not pool it. */
    if (zu_stream_readable(s, p->cfg.stale_probe_ms) == 1) {
        p->stats.discarded_stale++;
        zu_stream_close(s);
        zu_stream_free(s);
        return;
    }
    if (p->cfg.max_idle == 0) {
        p->stats.discarded_capacity++;
        zu_stream_close(s);
        zu_stream_free(s);
        return;
    }

    e = (pool_entry *)zu_calloc(1, sizeof *e);
    if (!e || !zu_pool_key_copy(&e->key, key)) {
        zu_free(e);
        zu_stream_close(s);
        zu_stream_free(s);
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

void zu_pool_stats_get(const zu_pool *p, zu_pool_stats *out) {
    if (!out) return;
    if (!p) { memset(out, 0, sizeof *out); return; }
    *out = p->stats;
    out->idle = p->idle;
}

size_t zu_pool_idle_count(const zu_pool *p) { return p ? p->idle : 0; }

/* Target 14 — the connection pool against a model (§26; #247).
 *
 * The pool is a long-lived object: connections go in and out of it in
 * whatever order the requests, the clock, the server and fork() dictate.
 * ctest/test_pool.c scripts fixed paths through it; #154 (a release from
 * inside acquire's probe) came from an interleaving nobody had scripted.
 * Here the input is a sequence of operations on one pool, and a reference
 * model, written from §26 rather than from zuh_pool.c, says what each must
 * do. After every step:
 *
 *   - an acquire returns exactly the connection the model picks (the newest
 *     idle one for that key that has not expired and is not readable), or
 *     nothing; and never one made before the last fork (§26.4);
 *   - the idle count, and every counter zu_pool_stats() reports, match;
 *   - every connection has been closed and freed exactly as often as the
 *     model says: once each when the pool discards it, and closed zero
 *     times when it is dropped after a fork, because a graceful close in a
 *     child writes into the parent's session (§26.4);
 *   - max_idle and max_per_host hold; the per-host count is by scheme,
 *     host and port, across keys that differ only in their TLS settings;
 *   - every allocation is freed by the end.
 *
 * Process identity is the harness's: zuh_fork.c is not linked, and the
 * four functions below stand in for it, so a fork is an increment of the
 * process id and the pool sees it at its next operation, as a child does.
 *
 * Input: byte 0 sets max_idle (bits 0-2, 0 to 7) and max_per_host (bits
 * 3-4, 0 meaning no limit); byte 1 bits 0-2 set idle_timeout in units of
 * 100 ms (0 never expires). Then one byte per operation: the low three bits
 * pick it, the rest (0 to 31) is its argument.
 *
 *   0 acquire key a % 6, dialling a new connection on a miss
 *   1 release a checked-out connection (a % n) clean
 *   2 release after a partial read: bit 0 says how, as the engine says it
 *     (body_incomplete) or by a caller who thought it was done (reason ok,
 *     unread bytes waiting: the release probe must see them)
 *   3 release after an error, one of the six other §26.3 reasons
 *   4 the server closes an idle connection (it becomes readable)
 *   5 advance the clock by a * 25 ms
 *   6 fork: the connections in flight belong to the parent, and the
 *     harness drops them as a child does, freed without a close
 *   7 a % 4: clear; check_fork; nothing; free the pool and make a new one
 */
#include "zuh_pool.h"
#include "zuh_fork.h"
#include "zuh_alloc.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* --- the process, as the pool sees it ------------------------------------- */

static long g_pid = 1000;
long zuh_pid_current(void) { return g_pid; }
void zuh_fork_guard_arm(zuh_fork_guard *g) {
    if (!g) return;
    g->owner_pid = zuh_pid_current();
    g->armed = 1;
}
int zuh_fork_guard_tripped(const zuh_fork_guard *g) {
    return g && g->armed && g->owner_pid != zuh_pid_current();
}
const char *zuh_fork_message(void) { return "fuzz_pool: forked"; }

static zuh_millis g_now;
static zuh_millis fake_now(void *ctx) { (void)ctx; return g_now; }

/* --- connections that count what is done to them -------------------------- */

#define MAXS 1024
#define NKEY 6           /* host k % 3; min_version 12 or 13: same host, other key */
#define MAXOUT 16

typedef struct {
    int  closes, frees;      /* what the pool and the harness did */
    int  exp_closes, exp_frees;
    int  readable;           /* the peer closed it, or bytes are waiting */
    long born;               /* the process that dialled it */
} rec;

static rec    g_rec[MAXS];
static size_t g_nrec;

static void c_close(zuh_stream *s) { ((rec *)s->impl)->closes++; }
static void c_destroy(zuh_stream *s) { ((rec *)s->impl)->frees++; zuh_free(s); }
static int  c_readable(zuh_stream *s, int ms) { (void)ms; return ((rec *)s->impl)->readable; }
static const zuh_stream_vtable k_vt = { "fuzz-pool", NULL, NULL, c_close, c_destroy, c_readable };

static size_t id_of(const zuh_stream *s) { return (size_t)((rec *)s->impl - g_rec); }

/* --- the model ------------------------------------------------------------ */

typedef struct { int key; size_t id; zuh_millis since; } ment;

static struct {
    ment           list[8];     /* newest first; max_idle <= 7 */
    size_t         n;
    zuh_pool_stats st;
    long           owner;
    zuh_pool_config cfg;
} M;

static void m_gone(size_t id, int closed) {
    g_rec[id].exp_frees++;
    if (closed) g_rec[id].exp_closes++;
}

static void m_unlink(size_t i) {
    memmove(&M.list[i], &M.list[i + 1], (M.n - i - 1) * sizeof M.list[0]);
    M.n--;
}

/* §26.4: in a child, every inherited connection goes, none of them closed. */
static void m_check_fork(void) {
    size_t i;
    if (M.owner == g_pid) return;
    for (i = 0; i < M.n; i++) m_gone(M.list[i].id, 0);
    M.st.discarded_fork += M.n;
    M.st.forks_detected++;
    M.n = 0;
    M.owner = g_pid;
}

/* The connection acquire must return, or MAXS for none. */
static size_t m_acquire(int key) {
    size_t i = 0;
    m_check_fork();
    while (i < M.n) {
        ment e = M.list[i];
        if (e.key != key) { i++; continue; }
        m_unlink(i);
        if (M.cfg.idle_timeout_ms > 0 && g_now - e.since >= M.cfg.idle_timeout_ms) {
            M.st.discarded_expired++;
            m_gone(e.id, 1);
            continue;
        }
        if (g_rec[e.id].readable) {          /* §26.2: stale */
            M.st.discarded_stale++;
            m_gone(e.id, 1);
            continue;
        }
        M.st.hits++;
        return e.id;
    }
    M.st.misses++;
    return MAXS;
}

static void m_evict_oldest(int host) {     /* host < 0: any */
    size_t i = M.n;
    while (i-- > 0) {
        if (host >= 0 && M.list[i].key % 3 != host) continue;
        m_gone(M.list[i].id, 1);
        m_unlink(i);
        M.st.discarded_capacity++;
        return;
    }
}

static void m_release(size_t id, int key, zuh_reuse r) {
    size_t i, same = 0;
    m_check_fork();
    if (r != ZUH_REUSE_OK) { M.st.discarded_unusable++; m_gone(id, 1); return; }
    if (g_rec[id].readable) { M.st.discarded_stale++; m_gone(id, 1); return; }
    if (M.cfg.max_idle == 0) { M.st.discarded_capacity++; m_gone(id, 1); return; }
    for (i = 0; i < M.n; i++) same += M.list[i].key % 3 == key % 3;
    if (M.cfg.max_per_host > 0 && same >= M.cfg.max_per_host) m_evict_oldest(key % 3);
    while (M.n >= M.cfg.max_idle) m_evict_oldest(-1);
    memmove(&M.list[1], &M.list[0], M.n * sizeof M.list[0]);
    M.list[0].key = key;
    M.list[0].id = id;
    M.list[0].since = g_now;
    M.n++;
}

static void m_clear(void) {
    size_t i;
    /* §26.4 applies to every operation in a child, clear included. */
    m_check_fork();
    for (i = 0; i < M.n; i++) m_gone(M.list[i].id, 1);
    M.n = 0;
}

/* --- the harness ---------------------------------------------------------- */

static void make_key(zuh_pool_key *k, int i) {
    static const char *const host[3] = { "a.test", "b.test", "c.test" };
    zuh_pool_key_init(k);
    k->scheme = (char *)zuh_alloc(6);
    k->host = (char *)zuh_alloc(7);
    if (k->scheme) memcpy(k->scheme, "https", 6);
    if (k->host) memcpy(k->host, host[i % 3], 7);
    k->port = 443;
    k->min_version = 12 + i / 3;
}

static zuh_stream *dial(void) {
    zuh_stream *s;
    rec *c;
    if (g_nrec >= MAXS) return NULL;
    s = (zuh_stream *)zuh_calloc(1, sizeof *s);
    if (!s) abort();
    c = &g_rec[g_nrec++];
    memset(c, 0, sizeof *c);
    c->born = g_pid;
    s->vt = &k_vt;
    s->impl = c;
    return s;
}

/* The pool and the model agree, on every count and every connection. */
static void sync_check(const zuh_pool *p) {
    zuh_pool_stats st;
    size_t i;
    int h, per[3] = { 0, 0, 0 };
    zuh_pool_stats_get(p, &st);
    if (zuh_pool_idle_count(p) != M.n || st.idle != M.n) abort();
    if (st.hits != M.st.hits || st.misses != M.st.misses ||
        st.discarded_stale != M.st.discarded_stale ||
        st.discarded_expired != M.st.discarded_expired ||
        st.discarded_capacity != M.st.discarded_capacity ||
        st.discarded_unusable != M.st.discarded_unusable ||
        st.discarded_fork != M.st.discarded_fork ||
        st.forks_detected != M.st.forks_detected) abort();
    for (i = 0; i < g_nrec; i++)
        if (g_rec[i].closes != g_rec[i].exp_closes || g_rec[i].frees != g_rec[i].exp_frees ||
            g_rec[i].frees > 1 || g_rec[i].closes > 1) abort();
    /* The caps, stated directly rather than trusted to the model. */
    if (M.n > M.cfg.max_idle) abort();
    for (i = 0; i < M.n; i++) per[M.list[i].key % 3]++;
    for (h = 0; h < 3; h++)
        if (M.cfg.max_per_host > 0 && (size_t)per[h] > M.cfg.max_per_host) abort();
}

typedef struct { zuh_stream *s; int key; } checked_out;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    zuh_alloc_stats before, after;
    zuh_pool_key keys[NKEY];
    checked_out out[MAXOUT];
    size_t nout = 0, i, nops;
    zuh_pool *p;
    int k;

    if (size < 2) return 0;
    zuh_alloc_stats_get(&before);
    memset(&M, 0, sizeof M);
    g_nrec = 0;
    g_now = 1000;
    zuh_pool_config_init(&M.cfg);
    M.cfg.max_idle = data[0] & 7;
    M.cfg.max_per_host = (data[0] >> 3) & 3;
    M.cfg.idle_timeout_ms = (long)(data[1] & 7) * 100;
    M.owner = g_pid;
    p = zuh_pool_new(&M.cfg);
    if (!p) abort();
    zuh_pool_set_clock(p, fake_now, NULL);
    for (k = 0; k < NKEY; k++) make_key(&keys[k], k);

    nops = size - 2;
    if (nops > 512) nops = 512;
    for (i = 0; i < nops; i++) {
        unsigned op = data[2 + i] & 7, a = data[2 + i] >> 3;
        switch (op) {
        case 0: {                                           /* acquire */
            int key = (int)(a % NKEY);
            size_t want = m_acquire(key);
            zuh_stream *s = zuh_pool_acquire(p, &keys[key]);
            if (want == MAXS) {
                if (s) abort();                             /* reused what it must not */
                s = dial();
                if (!s) break;
            } else {
                if (!s || id_of(s) != want) abort();        /* the wrong connection */
            }
            /* §26.4: nothing dialled before the last fork, never closed. */
            if (g_rec[id_of(s)].born != g_pid || g_rec[id_of(s)].closes) abort();
            if (nout == MAXOUT) {                           /* the harness has no room */
                m_gone(id_of(s), 1);
                zuh_stream_close(s); zuh_stream_free(s);
                break;
            }
            out[nout].s = s;
            out[nout].key = key;
            nout++;
            break;
        }
        case 1: case 2: case 3: {                           /* release */
            zuh_reuse r = ZUH_REUSE_OK;
            size_t slot, id;
            if (nout == 0) break;
            if (op == 1) slot = a % nout;
            else if (op == 2) {
                slot = (a >> 1) % nout;
                if (a & 1) g_rec[id_of(out[slot].s)].readable = 1;
                else r = ZUH_NOREUSE_BODY_INCOMPLETE;
            } else {
                r = (zuh_reuse)(ZUH_NOREUSE_CANCELLED + (int)(a % 6));
                slot = (a / 6) % nout;
            }
            id = id_of(out[slot].s);
            m_release(id, out[slot].key, r);
            zuh_pool_release(p, &keys[out[slot].key], out[slot].s, r);
            out[slot] = out[--nout];
            break;
        }
        case 4:                                             /* the server closes one */
            if (M.n) g_rec[M.list[a % M.n].id].readable = 1;
            break;
        case 5:
            g_now += (zuh_millis)a * 25;
            break;
        case 6: {                                           /* fork */
            size_t j;
            g_pid++;
            for (j = 0; j < nout; j++) {
                m_gone(id_of(out[j].s), 0);
                zuh_stream_free(out[j].s);
            }
            nout = 0;
            break;
        }
        default:
            switch (a % 4) {
            case 0: m_clear(); zuh_pool_clear(p); break;
            case 1: {
                long was = M.owner;
                m_check_fork();
                if (zuh_pool_check_fork(p) != (was != g_pid)) abort();
                break;
            }
            case 2: break;
            default:                                        /* a finalizer, then a new client */
                if (M.owner != g_pid) m_check_fork(); else m_clear();
                zuh_pool_free(p);
                memset(&M.st, 0, sizeof M.st);
                M.owner = g_pid;
                p = zuh_pool_new(&M.cfg);
                if (!p) abort();
                zuh_pool_set_clock(p, fake_now, NULL);
                break;
            }
            break;
        }
        sync_check(p);
    }

    /* The end: the harness hands back what it holds, the pool is freed. */
    for (i = 0; i < nout; i++) {
        m_gone(id_of(out[i].s), 1);
        zuh_stream_close(out[i].s);
        zuh_stream_free(out[i].s);
    }
    if (M.owner != g_pid) m_check_fork(); else m_clear();
    zuh_pool_free(p);
    for (i = 0; i < g_nrec; i++)
        if (g_rec[i].frees != 1 || g_rec[i].closes != g_rec[i].exp_closes) abort();
    for (k = 0; k < NKEY; k++) zuh_pool_key_free(&keys[k]);
    zuh_alloc_stats_get(&after);
    if (after.live_blocks != before.live_blocks) abort();
    return 0;
}

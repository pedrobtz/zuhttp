#include "zuh_uri.h"
#include "zuh_alloc.h"
#include "zuh_headers.h"   /* zuh_ascii_casecmp */
#include <string.h>
#include <stdio.h>

void zuh_uri_init(zuh_uri *u) { memset(u, 0, sizeof *u); }

void zuh_uri_free(zuh_uri *u) {
    if (!u) return;
    zuh_free(u->scheme); zuh_free(u->host);
    zuh_free(u->path_query); zuh_free(u->userinfo);
    memset(u, 0, sizeof *u);
}

static char *dup_str(const char *s) {
    size_t n;
    char *p;
    if (!s) return NULL;
    n = strlen(s);
    p = (char *)zuh_alloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n + 1);
    return p;
}

int zuh_uri_copy(zuh_uri *dst, const zuh_uri *src) {
    if (!dst || !src) return 0;
    zuh_uri_init(dst);
    dst->port = src->port;
    dst->is_https = src->is_https;
    dst->port_explicit = src->port_explicit;
    if (src->scheme     && !(dst->scheme     = dup_str(src->scheme)))     goto fail;
    if (src->host       && !(dst->host       = dup_str(src->host)))       goto fail;
    if (src->path_query && !(dst->path_query = dup_str(src->path_query))) goto fail;
    if (src->userinfo   && !(dst->userinfo   = dup_str(src->userinfo)))   goto fail;
    return 1;
fail:
    zuh_uri_free(dst);
    return 0;
}

uint16_t zuh_uri_default_port(const char *scheme) {
    if (!scheme) return 0;
    if (zuh_ascii_casecmp(scheme, "https") == 0) return 443;
    if (zuh_ascii_casecmp(scheme, "http")  == 0) return 80;
    return 0;
}

int zuh_uri_same_origin(const zuh_uri *a, const zuh_uri *b) {
    uint16_t pa, pb;
    if (!a || !b) return 0;
    if (!a->scheme || !b->scheme || !a->host || !b->host) return 0;
    if (zuh_ascii_casecmp(a->scheme, b->scheme) != 0) return 0;
    if (zuh_ascii_casecmp(a->host, b->host) != 0) return 0;
    pa = a->port ? a->port : zuh_uri_default_port(a->scheme);
    pb = b->port ? b->port : zuh_uri_default_port(b->scheme);
    return pa == pb;
}

int zuh_uri_origin_string(const zuh_uri *u, char *out, size_t cap) {
    uint16_t def;
    if (!u || !out || cap == 0) return 0;
    if (!u->scheme || !u->host) { out[0] = '\0'; return 0; }
    def = zuh_uri_default_port(u->scheme);
    /* userinfo is deliberately never included (§42.1). */
    if (u->port && u->port != def)
        return snprintf(out, cap, "%s://%s:%u", u->scheme, u->host,
                        (unsigned)u->port) < (int)cap;
    return snprintf(out, cap, "%s://%s", u->scheme, u->host) < (int)cap;
}

/* ===================================================================
 * Parsing (design §8.2, decision D-11)
 * ===================================================================
 *
 * uriparser is RFC 3986. RFC 3986 is a GRAMMAR, not an HTTP client policy, so
 * it accepts several things that are syntactically valid URIs but unusable as
 * a request target. Everything uriparser hands back therefore goes through the
 * checks below before it becomes a zuh_uri:
 *
 *   scheme      must be http or https; lowercased.       (zuhttp is not a
 *               general URI library — a mailto: is a caller bug, not a request)
 *   host        must be non-empty, must not contain an empty DNS label
 *               ("example.com.." parses fine per RFC 3986); one trailing root
 *               dot is stripped so "example.com." and "example.com" compare
 *               equal in zuh_uri_same_origin (§19.2 credential stripping);
 *               lowercased.
 *   port        RFC 3986 allows DIGIT*, so ":65536" and ":0443" both parse.
 *               Range-checked into uint16_t — without this, 65536 would
 *               truncate to 0 and we would silently connect to the wrong port.
 *   NUL         rejected anywhere in the input. We hand these strings to
 *               getaddrinfo() and into the request line; an embedded NUL
 *               truncates one and not the other.
 *   fragment    dropped. It is never sent (RFC 7230 §5.3).
 *
 * uriparser is correspondingly STRICTER than a browser in ways we want: a
 * space, tab, newline or backslash in the authority is a syntax error, and
 * "https://good.com@evil.com/" yields host=evil.com, userinfo=good.com — the
 * origin-confusion case that governs whether credentials survive a redirect.
 */

#include "zuh_uriparser.h"
#include "zuh_buffer.h"

/* uriparser allocates through zuh_alloc so the OOM injection in §50.1 and the
 * leak accounting in zuh_alloc_stats cover the parser too. All five slots are
 * filled directly: uriCompleteMemoryManager() decorates a SEPARATE backend
 * struct via userData and self-recurses if handed one struct twice, and
 * zuh_alloc already size-headers its blocks, so decoration buys nothing. */
static void *zup_malloc(UriMemoryManager *m, size_t n) { (void)m; return zuh_alloc(n); }
static void *zup_calloc(UriMemoryManager *m, size_t nm, size_t sz) {
    size_t total; void *p;
    (void)m;
    if (!zuh_size_mul(nm, sz, &total)) return NULL;
    p = zuh_alloc(total);
    if (p) memset(p, 0, total);
    return p;
}
static void *zup_realloc(UriMemoryManager *m, void *p, size_t n) { (void)m; return zuh_realloc(p, n); }
static void  zup_free(UriMemoryManager *m, void *p) { (void)m; zuh_free(p); }

static void zup_mm(UriMemoryManager *mm) {
    memset(mm, 0, sizeof *mm);
    mm->malloc       = zup_malloc;
    mm->calloc       = zup_calloc;
    mm->realloc      = zup_realloc;
    mm->free         = zup_free;
    mm->reallocarray = uriEmulateReallocarray;  /* built on mm->realloc */
    mm->userData     = NULL;
}

static size_t rng_len(const UriTextRangeA *r) {
    if (!r || !r->first || !r->afterLast || r->afterLast < r->first) return 0;
    return (size_t)(r->afterLast - r->first);
}

/* Lowercased copy of a text range. NULL on allocation failure. */
static char *rng_dup_lower(const UriTextRangeA *r) {
    size_t n = rng_len(r), i;
    char *p = (char *)zuh_alloc(n + 1);
    if (!p) return NULL;
    for (i = 0; i < n; i++) {
        char c = r->first[i];
        p[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    }
    p[n] = '\0';
    return p;
}

static char *rng_dup(const UriTextRangeA *r) {
    size_t n = rng_len(r);
    char *p = (char *)zuh_alloc(n + 1);
    if (!p) return NULL;
    if (n) memcpy(p, r->first, n);
    p[n] = '\0';
    return p;
}

/* RFC 3986 permits DIGIT*; uint16_t does not. Returns 0 on overflow. */
static int port_from_range(const UriTextRangeA *r, uint16_t *out, int *explicit_)
{
    size_t n = rng_len(r), i;
    unsigned long v = 0;
    *out = 0;
    *explicit_ = 0;
    if (n == 0) return 1;                 /* "http://h:/" — empty port = default */
    for (i = 0; i < n; i++) {
        char c = r->first[i];
        if (c < '0' || c > '9') return 0;
        v = v * 10u + (unsigned long)(c - '0');
        if (v > 65535ul) return 0;         /* ":65536" must not truncate to 0 */
    }
    *out = (uint16_t)v;
    *explicit_ = 1;
    return 1;
}

/* Reject empty DNS labels; strip one trailing root dot. In place. */
static int host_ok(char *h, int is_ipv6)
{
    size_t n = strlen(h), i;
    if (n == 0) return 0;
    if (is_ipv6) return 1;                 /* "::1" is full of empty "labels" */
    /* Adjacency is checked BEFORE stripping: strip first and "example.com.."
     * becomes "example.com.", which has no adjacent dots left to find. */
    for (i = 1; i < n; i++)
        if (h[i] == '.' && h[i - 1] == '.') return 0;  /* "example.com.." */
    if (h[0] == '.') return 0;
    if (h[n - 1] == '.') { h[n - 1] = '\0'; n--; }   /* "example.com." */
    return n > 0;
}

/* origin-form target: "/" path segments, then "?" query. Fragment is dropped
 * (RFC 7230 §5.3 — it is never sent). Always begins with "/". */
static char *build_path_query(const UriUriA *u)
{
    zuh_buffer b;
    const UriPathSegmentA *s;
    const char *cstr = NULL;
    char *out = NULL;

    if (!zuh_buf_init(&b, 64, 64 * 1024)) return NULL;

    if (!u->pathHead) {
        if (!zuh_buf_append_byte(&b, '/')) goto done;
    } else {
        for (s = u->pathHead; s; s = s->next) {
            size_t n = rng_len(&s->text);
            if (!zuh_buf_append_byte(&b, '/')) goto done;
            if (n && !zuh_buf_append(&b, s->text.first, n)) goto done;
        }
    }
    if (u->query.first) {
        size_t n = rng_len(&u->query);
        if (!zuh_buf_append_byte(&b, '?')) goto done;
        if (n && !zuh_buf_append(&b, u->query.first, n)) goto done;
    }
    if (!zuh_buf_cstr(&b, &cstr)) goto done;
    out = dup_str(cstr);
done:
    zuh_buf_free(&b);
    return out;
}

/* Fill a zuh_uri from a parsed UriUriA, applying the policy above. */
static zuh_code from_uriparser(zuh_uri *out, const UriUriA *u)
{
    int is_ipv6;
    zuh_uri_init(out);

    if (!u->scheme.first || !u->hostText.first) return ZUH_ERR_URL;

    if (!(out->scheme = rng_dup_lower(&u->scheme))) return ZUH_ERR_NOMEM;
    if (strcmp(out->scheme, "http") && strcmp(out->scheme, "https")) goto bad;
    out->is_https = (strcmp(out->scheme, "https") == 0);

    /* RFC 3986 §3.2.2 allows IP-literal = IPv6address / IPvFuture, so
     * "http://[v7.xyz]/" and "http://[veee.0;;;;***UU:]/" are both valid URIs
     * and uriparser accepts them. zuhttp cannot connect to an IPvFuture —
     * there is nothing to resolve — and accepting one would put sub-delims
     * like ';' and '*' into the host that then reaches getaddrinfo() and the
     * Host header. Reject it here rather than downstream.
     *
     * Found by the S18 proxy fuzz target. */
    if (u->hostData.ipFuture.first != NULL) goto bad;

    if (!(out->host = rng_dup_lower(&u->hostText))) goto nomem;
    is_ipv6 = (u->hostData.ip6 != NULL) || (strchr(out->host, ':') != NULL);
    if (!host_ok(out->host, is_ipv6)) goto bad;

    if (!port_from_range(&u->portText, &out->port, &out->port_explicit)) goto bad;
    if (!out->port_explicit) out->port = zuh_uri_default_port(out->scheme);
    if (out->port == 0) goto bad;

    if (u->userInfo.first && !(out->userinfo = rng_dup(&u->userInfo))) goto nomem;

    if (!(out->path_query = build_path_query(u))) goto nomem;
    return ZUH_OK;
bad:
    zuh_uri_free(out);
    return ZUH_ERR_URL;
nomem:
    zuh_uri_free(out);
    return ZUH_ERR_NOMEM;
}

/* An embedded NUL would truncate one consumer and not another. */
static int range_has_nul(const char *first, const char *last)
{
    const char *p;
    for (p = first; p < last; p++) if (*p == '\0') return 1;
    return 0;
}

zuh_code zuh_uri_parse(zuh_uri *out, const char *first, const char *last)
{
    UriMemoryManager mm;
    UriUriA u;
    zuh_code rc;

    if (!out) return ZUH_ERR_URL;
    zuh_uri_init(out);
    if (!first || !last || last < first) return ZUH_ERR_URL;
    if (range_has_nul(first, last)) return ZUH_ERR_URL;

    zup_mm(&mm);
    /* An explicit end pointer is required: the Mm entry point rejects a NULL
     * afterLast with URI_ERROR_NULL despite what Uri.h documents. */
    {
        /* uriparser's own allocation failure is ours to report as such:
         * calling it an unusable URL blamed the caller for running out of
         * memory (found by the engine's allocation sweep). */
        int ur = uriParseSingleUriExMmA(&u, first, last, NULL, &mm);
        if (ur == URI_ERROR_MALLOC) return ZUH_ERR_NOMEM;
        if (ur != URI_SUCCESS)      return ZUH_ERR_URL;
    }

    rc = from_uriparser(out, &u);
    uriFreeUriMembersMmA(&u, &mm);
    return rc;
}

zuh_code zuh_uri_resolve(zuh_uri *out, const zuh_uri *base,
                       const char *ref, const char *ref_last)
{
    UriMemoryManager mm;
    UriUriA ubase, uref, uabs;
    zuh_buffer b;
    const char *base_str = NULL;
    zuh_code rc = ZUH_ERR_URL;
    int have_base = 0, have_ref = 0, have_abs = 0, ur;
    char portbuf[8];

    if (!out) return ZUH_ERR_URL;
    zuh_uri_init(out);
    if (!base || !base->scheme || !base->host || !base->path_query) return ZUH_ERR_URL;
    if (!ref || !ref_last || ref_last < ref) return ZUH_ERR_URL;
    if (range_has_nul(ref, ref_last)) return ZUH_ERR_URL;

    zup_mm(&mm);

    /* Rebuild the base as text. Deliberately WITHOUT userinfo: resolution must
     * not be able to carry credentials into the result (§19.2 handles who may
     * keep them, and it works on the struct). */
    if (!zuh_buf_init(&b, 128, 64 * 1024)) return ZUH_ERR_NOMEM;
    /* Until the reference is parsed, a failure here is the buffer's: the
     * base was a parsed URI, so rebuilding its text cannot be "unusable". */
    rc = ZUH_ERR_NOMEM;
    if (!zuh_buf_append_str(&b, base->scheme) || !zuh_buf_append_str(&b, "://")) goto done;
    if (strchr(base->host, ':')) {                    /* IPv6 literal needs brackets back */
        if (!zuh_buf_append_byte(&b, '[') || !zuh_buf_append_str(&b, base->host)
            || !zuh_buf_append_byte(&b, ']')) goto done;
    } else if (!zuh_buf_append_str(&b, base->host)) goto done;
    if (base->port_explicit) {
        int n = snprintf(portbuf, sizeof portbuf, ":%u", (unsigned)base->port);
        if (n < 0 || (size_t)n >= sizeof portbuf) goto done;
        if (!zuh_buf_append_str(&b, portbuf)) goto done;
    }
    if (!zuh_buf_append_str(&b, base->path_query)) goto done;
    if (!zuh_buf_cstr(&b, &base_str)) goto done;

    ur = uriParseSingleUriExMmA(&ubase, base_str, base_str + strlen(base_str), NULL, &mm);
    if (ur != URI_SUCCESS) { if (ur != URI_ERROR_MALLOC) rc = ZUH_ERR_URL; goto done; }
    have_base = 1;
    ur = uriParseSingleUriExMmA(&uref, ref, ref_last, NULL, &mm);
    if (ur != URI_SUCCESS) { rc = ur == URI_ERROR_MALLOC ? ZUH_ERR_NOMEM : ZUH_ERR_URL; goto done; }
    have_ref = 1;

    /* STRICTLY: a same-scheme absolute reference is NOT folded into the base
     * (RFC 3986 §5.2.2 strict mode). */
    ur = uriAddBaseUriExMmA(&uabs, &uref, &ubase, URI_RESOLVE_STRICTLY, &mm);
    if (ur != URI_SUCCESS) { rc = ur == URI_ERROR_MALLOC ? ZUH_ERR_NOMEM : ZUH_ERR_URL; goto done; }
    have_abs = 1;

    rc = from_uriparser(out, &uabs);
done:
    if (have_abs)  uriFreeUriMembersMmA(&uabs, &mm);
    if (have_ref)  uriFreeUriMembersMmA(&uref, &mm);
    if (have_base) uriFreeUriMembersMmA(&ubase, &mm);
    zuh_buf_free(&b);
    return rc;
}

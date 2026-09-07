#include "zu_uri.h"
#include "zu_alloc.h"
#include "zu_headers.h"   /* zu_ascii_casecmp */
#include <string.h>
#include <stdio.h>

void zu_uri_init(zu_uri *u) { memset(u, 0, sizeof *u); }

void zu_uri_free(zu_uri *u) {
    if (!u) return;
    zu_free(u->scheme); zu_free(u->host);
    zu_free(u->path_query); zu_free(u->userinfo);
    memset(u, 0, sizeof *u);
}

static char *dup_str(const char *s) {
    size_t n;
    char *p;
    if (!s) return NULL;
    n = strlen(s);
    p = (char *)zu_alloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n + 1);
    return p;
}

int zu_uri_copy(zu_uri *dst, const zu_uri *src) {
    if (!dst || !src) return 0;
    zu_uri_init(dst);
    dst->port = src->port;
    dst->is_https = src->is_https;
    dst->port_explicit = src->port_explicit;
    if (src->scheme     && !(dst->scheme     = dup_str(src->scheme)))     goto fail;
    if (src->host       && !(dst->host       = dup_str(src->host)))       goto fail;
    if (src->path_query && !(dst->path_query = dup_str(src->path_query))) goto fail;
    if (src->userinfo   && !(dst->userinfo   = dup_str(src->userinfo)))   goto fail;
    return 1;
fail:
    zu_uri_free(dst);
    return 0;
}

uint16_t zu_uri_default_port(const char *scheme) {
    if (!scheme) return 0;
    if (zu_ascii_casecmp(scheme, "https") == 0) return 443;
    if (zu_ascii_casecmp(scheme, "http")  == 0) return 80;
    return 0;
}

int zu_uri_same_origin(const zu_uri *a, const zu_uri *b) {
    uint16_t pa, pb;
    if (!a || !b) return 0;
    if (!a->scheme || !b->scheme || !a->host || !b->host) return 0;
    if (zu_ascii_casecmp(a->scheme, b->scheme) != 0) return 0;
    if (zu_ascii_casecmp(a->host, b->host) != 0) return 0;
    pa = a->port ? a->port : zu_uri_default_port(a->scheme);
    pb = b->port ? b->port : zu_uri_default_port(b->scheme);
    return pa == pb;
}

int zu_uri_origin_string(const zu_uri *u, char *out, size_t cap) {
    uint16_t def;
    if (!u || !out || cap == 0) return 0;
    if (!u->scheme || !u->host) { out[0] = '\0'; return 0; }
    def = zu_uri_default_port(u->scheme);
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
 * checks below before it becomes a zu_uri:
 *
 *   scheme      must be http or https; lowercased.       (zuhttp is not a
 *               general URI library — a mailto: is a caller bug, not a request)
 *   host        must be non-empty, must not contain an empty DNS label
 *               ("example.com.." parses fine per RFC 3986); one trailing root
 *               dot is stripped so "example.com." and "example.com" compare
 *               equal in zu_uri_same_origin (§19.2 credential stripping);
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

#include "zu_uriparser.h"
#include "zu_buffer.h"

/* uriparser allocates through zu_alloc so the OOM injection in §50.1 and the
 * leak accounting in zu_alloc_stats cover the parser too. All five slots are
 * filled directly: uriCompleteMemoryManager() decorates a SEPARATE backend
 * struct via userData and self-recurses if handed one struct twice, and
 * zu_alloc already size-headers its blocks, so decoration buys nothing. */
static void *zup_malloc(UriMemoryManager *m, size_t n) { (void)m; return zu_alloc(n); }
static void *zup_calloc(UriMemoryManager *m, size_t nm, size_t sz) {
    size_t total; void *p;
    (void)m;
    if (!zu_size_mul(nm, sz, &total)) return NULL;
    p = zu_alloc(total);
    if (p) memset(p, 0, total);
    return p;
}
static void *zup_realloc(UriMemoryManager *m, void *p, size_t n) { (void)m; return zu_realloc(p, n); }
static void  zup_free(UriMemoryManager *m, void *p) { (void)m; zu_free(p); }

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
    char *p = (char *)zu_alloc(n + 1);
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
    char *p = (char *)zu_alloc(n + 1);
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
    zu_buffer b;
    const UriPathSegmentA *s;
    const char *cstr = NULL;
    char *out = NULL;

    if (!zu_buf_init(&b, 64, 64 * 1024)) return NULL;

    if (!u->pathHead) {
        if (!zu_buf_append_byte(&b, '/')) goto done;
    } else {
        for (s = u->pathHead; s; s = s->next) {
            size_t n = rng_len(&s->text);
            if (!zu_buf_append_byte(&b, '/')) goto done;
            if (n && !zu_buf_append(&b, s->text.first, n)) goto done;
        }
    }
    if (u->query.first) {
        size_t n = rng_len(&u->query);
        if (!zu_buf_append_byte(&b, '?')) goto done;
        if (n && !zu_buf_append(&b, u->query.first, n)) goto done;
    }
    if (!zu_buf_cstr(&b, &cstr)) goto done;
    out = dup_str(cstr);
done:
    zu_buf_free(&b);
    return out;
}

/* Fill a zu_uri from a parsed UriUriA, applying the policy above. */
static zu_code from_uriparser(zu_uri *out, const UriUriA *u)
{
    int is_ipv6;
    zu_uri_init(out);

    if (!u->scheme.first || !u->hostText.first) return ZU_ERR_URL;

    if (!(out->scheme = rng_dup_lower(&u->scheme))) return ZU_ERR_NOMEM;
    if (strcmp(out->scheme, "http") && strcmp(out->scheme, "https")) goto bad;
    out->is_https = (strcmp(out->scheme, "https") == 0);

    if (!(out->host = rng_dup_lower(&u->hostText))) goto nomem;
    is_ipv6 = (u->hostData.ip6 != NULL) || (strchr(out->host, ':') != NULL);
    if (!host_ok(out->host, is_ipv6)) goto bad;

    if (!port_from_range(&u->portText, &out->port, &out->port_explicit)) goto bad;
    if (!out->port_explicit) out->port = zu_uri_default_port(out->scheme);
    if (out->port == 0) goto bad;

    if (u->userInfo.first && !(out->userinfo = rng_dup(&u->userInfo))) goto nomem;

    if (!(out->path_query = build_path_query(u))) goto nomem;
    return ZU_OK;
bad:
    zu_uri_free(out);
    return ZU_ERR_URL;
nomem:
    zu_uri_free(out);
    return ZU_ERR_NOMEM;
}

/* An embedded NUL would truncate one consumer and not another. */
static int range_has_nul(const char *first, const char *last)
{
    const char *p;
    for (p = first; p < last; p++) if (*p == '\0') return 1;
    return 0;
}

zu_code zu_uri_parse(zu_uri *out, const char *first, const char *last)
{
    UriMemoryManager mm;
    UriUriA u;
    zu_code rc;

    if (!out) return ZU_ERR_URL;
    zu_uri_init(out);
    if (!first || !last || last < first) return ZU_ERR_URL;
    if (range_has_nul(first, last)) return ZU_ERR_URL;

    zup_mm(&mm);
    /* An explicit end pointer is required: the Mm entry point rejects a NULL
     * afterLast with URI_ERROR_NULL despite what Uri.h documents. */
    if (uriParseSingleUriExMmA(&u, first, last, NULL, &mm) != URI_SUCCESS)
        return ZU_ERR_URL;

    rc = from_uriparser(out, &u);
    uriFreeUriMembersMmA(&u, &mm);
    return rc;
}

zu_code zu_uri_resolve(zu_uri *out, const zu_uri *base,
                       const char *ref, const char *ref_last)
{
    UriMemoryManager mm;
    UriUriA ubase, uref, uabs;
    zu_buffer b;
    const char *base_str = NULL;
    zu_code rc = ZU_ERR_URL;
    int have_base = 0, have_ref = 0, have_abs = 0;
    char portbuf[8];

    if (!out) return ZU_ERR_URL;
    zu_uri_init(out);
    if (!base || !base->scheme || !base->host || !base->path_query) return ZU_ERR_URL;
    if (!ref || !ref_last || ref_last < ref) return ZU_ERR_URL;
    if (range_has_nul(ref, ref_last)) return ZU_ERR_URL;

    zup_mm(&mm);

    /* Rebuild the base as text. Deliberately WITHOUT userinfo: resolution must
     * not be able to carry credentials into the result (§19.2 handles who may
     * keep them, and it works on the struct). */
    if (!zu_buf_init(&b, 128, 64 * 1024)) return ZU_ERR_NOMEM;
    if (!zu_buf_append_str(&b, base->scheme) || !zu_buf_append_str(&b, "://")) goto done;
    if (strchr(base->host, ':')) {                    /* IPv6 literal needs brackets back */
        if (!zu_buf_append_byte(&b, '[') || !zu_buf_append_str(&b, base->host)
            || !zu_buf_append_byte(&b, ']')) goto done;
    } else if (!zu_buf_append_str(&b, base->host)) goto done;
    if (base->port_explicit) {
        int n = snprintf(portbuf, sizeof portbuf, ":%u", (unsigned)base->port);
        if (n < 0 || (size_t)n >= sizeof portbuf) goto done;
        if (!zu_buf_append_str(&b, portbuf)) goto done;
    }
    if (!zu_buf_append_str(&b, base->path_query)) goto done;
    if (!zu_buf_cstr(&b, &base_str)) goto done;

    if (uriParseSingleUriExMmA(&ubase, base_str, base_str + strlen(base_str),
                               NULL, &mm) != URI_SUCCESS) goto done;
    have_base = 1;
    if (uriParseSingleUriExMmA(&uref, ref, ref_last, NULL, &mm) != URI_SUCCESS) goto done;
    have_ref = 1;

    /* STRICTLY: a same-scheme absolute reference is NOT folded into the base
     * (RFC 3986 §5.2.2 strict mode). */
    if (uriAddBaseUriExMmA(&uabs, &uref, &ubase, URI_RESOLVE_STRICTLY, &mm) != URI_SUCCESS)
        goto done;
    have_abs = 1;

    rc = from_uriparser(out, &uabs);
done:
    if (have_abs)  uriFreeUriMembersMmA(&uabs, &mm);
    if (have_ref)  uriFreeUriMembersMmA(&uref, &mm);
    if (have_base) uriFreeUriMembersMmA(&ubase, &mm);
    zu_buf_free(&b);
    return rc;
}

#include "zu_headers.h"
#include "zu_alloc.h"
#include <string.h>

static unsigned char lower(unsigned char c) {
    return (c >= 'A' && c <= 'Z') ? (unsigned char)(c + 32) : c;
}

int zu_ascii_ncasecmp(const char *a, size_t alen, const char *b, size_t blen) {
    size_t i;
    if (alen != blen) return alen < blen ? -1 : 1;
    for (i = 0; i < alen; i++) {
        unsigned char ca = lower((unsigned char)a[i]);
        unsigned char cb = lower((unsigned char)b[i]);
        if (ca != cb) return ca < cb ? -1 : 1;
    }
    return 0;
}

int zu_ascii_casecmp(const char *a, const char *b) {
    return zu_ascii_ncasecmp(a, strlen(a), b, strlen(b));
}

/* RFC 7230 tchar. Anything outside this set in a name is a protocol error. */
static int is_tchar(unsigned char c) {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
        return 1;
    switch (c) {
        case '!': case '#': case '$': case '%': case '&': case '\'': case '*':
        case '+': case '-': case '.': case '^': case '_': case '`': case '|':
        case '~':
            return 1;
        default:
            return 0;
    }
}

int zu_header_name_valid(const char *name, size_t len) {
    size_t i;
    if (!name || len == 0) return 0;
    for (i = 0; i < len; i++)
        if (!is_tchar((unsigned char)name[i])) return 0;
    return 1;
}

int zu_header_value_valid(const char *value, size_t len) {
    size_t i;
    if (!value) return len == 0;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)value[i];
        /* CR/LF/NUL are the injection vector (§17.1). Everything else that is
         * printable, HTAB, SP, or obs-text is permitted. */
        if (c == '\r' || c == '\n' || c == '\0') return 0;
        if (c < 0x20 && c != '\t') return 0;
        if (c == 0x7F) return 0;
    }
    return 1;
}

void zu_headers_init_limited(zu_headers *h, size_t max_count, size_t max_name,
                             size_t max_value, size_t max_bytes) {
    memset(h, 0, sizeof *h);
    h->max_count = max_count;
    h->max_name  = max_name;
    h->max_value = max_value;
    h->max_bytes = max_bytes;
}

void zu_headers_init(zu_headers *h) {
    zu_headers_init_limited(h, ZU_DEFAULT_MAX_HEADER_COUNT, ZU_DEFAULT_MAX_HEADER_NAME,
                            ZU_DEFAULT_MAX_HEADER_VALUE, ZU_DEFAULT_MAX_HEADER_BYTES);
}

void zu_headers_free(zu_headers *h) {
    size_t i;
    if (!h) return;
    for (i = 0; i < h->n; i++) { zu_free(h->items[i].name); zu_free(h->items[i].value); }
    zu_free(h->items);
    h->items = NULL; h->n = 0; h->cap = 0; h->bytes = 0;
}

static char *dup_n(const char *s, size_t len) {
    char *p;
    size_t total;
    if (!zu_size_add(len, 1, &total)) return NULL;
    p = (char *)zu_alloc(total);
    if (!p) return NULL;
    if (len) memcpy(p, s, len);
    p[len] = '\0';
    return p;
}

static int reserve_one(zu_headers *h) {
    size_t cap, bytes;
    zu_header *items;
    if (h->n < h->cap) return 1;
    cap = h->cap ? h->cap * 2 : 8;
    if (!zu_size_mul(cap, sizeof *items, &bytes)) return 0;
    items = (zu_header *)zu_realloc(h->items, bytes);
    if (!items) return 0;
    h->items = items;
    h->cap = cap;
    return 1;
}

zu_code zu_headers_add(zu_headers *h, const char *name, size_t nlen,
                       const char *value, size_t vlen) {
    size_t add, newbytes;
    if (!h) return ZU_ERR_PARSE;

    if (!zu_header_name_valid(name, nlen))   return ZU_ERR_PARSE;
    if (!zu_header_value_valid(value, vlen)) return ZU_ERR_PARSE;

    if (h->max_count && h->n >= h->max_count)   return ZU_ERR_BODY_LIMIT;
    if (h->max_name  && nlen > h->max_name)     return ZU_ERR_BODY_LIMIT;
    if (h->max_value && vlen > h->max_value)    return ZU_ERR_BODY_LIMIT;

    /* name + ": " + value + CRLF, as it will appear on the wire. */
    if (!zu_size_add(nlen, vlen, &add))     return ZU_ERR_OVERFLOW;
    if (!zu_size_add(add, 4, &add))         return ZU_ERR_OVERFLOW;
    if (!zu_size_add(h->bytes, add, &newbytes)) return ZU_ERR_OVERFLOW;
    if (h->max_bytes && newbytes > h->max_bytes) return ZU_ERR_BODY_LIMIT;

    if (!reserve_one(h)) return ZU_ERR_NOMEM;

    h->items[h->n].name  = dup_n(name, nlen);
    h->items[h->n].value = dup_n(value ? value : "", vlen);
    if (!h->items[h->n].name || !h->items[h->n].value) {
        zu_free(h->items[h->n].name);
        zu_free(h->items[h->n].value);
        return ZU_ERR_NOMEM;
    }
    h->items[h->n].nlen = nlen;
    h->items[h->n].vlen = vlen;
    h->n++;
    h->bytes = newbytes;
    return ZU_OK;
}

zu_code zu_headers_add_str(zu_headers *h, const char *name, const char *value) {
    return zu_headers_add(h, name, name ? strlen(name) : 0,
                          value, value ? strlen(value) : 0);
}

size_t zu_headers_remove(zu_headers *h, const char *name) {
    size_t i = 0, removed = 0, nlen;
    if (!h || !name) return 0;
    nlen = strlen(name);
    while (i < h->n) {
        if (zu_ascii_ncasecmp(h->items[i].name, h->items[i].nlen, name, nlen) == 0) {
            size_t sub = h->items[i].nlen + h->items[i].vlen + 4;
            zu_free(h->items[i].name);
            zu_free(h->items[i].value);
            memmove(&h->items[i], &h->items[i + 1], (h->n - i - 1) * sizeof *h->items);
            h->n--;
            h->bytes = h->bytes >= sub ? h->bytes - sub : 0;
            removed++;
            continue;   /* re-examine this index */
        }
        i++;
    }
    return removed;
}

zu_code zu_headers_set(zu_headers *h, const char *name, const char *value) {
    if (!h || !name) return ZU_ERR_PARSE;
    /* Validate before removing, so a rejected set does not destroy the old
     * value as a side effect. */
    if (!zu_header_name_valid(name, strlen(name))) return ZU_ERR_PARSE;
    if (!zu_header_value_valid(value, value ? strlen(value) : 0)) return ZU_ERR_PARSE;
    zu_headers_remove(h, name);
    return zu_headers_add_str(h, name, value);
}

size_t zu_headers_count(const zu_headers *h, const char *name) {
    size_t i, nlen, c = 0;
    if (!h || !name) return 0;
    nlen = strlen(name);
    for (i = 0; i < h->n; i++)
        if (zu_ascii_ncasecmp(h->items[i].name, h->items[i].nlen, name, nlen) == 0) c++;
    return c;
}

const char *zu_headers_get_at(const zu_headers *h, const char *name, size_t idx) {
    size_t i, nlen, c = 0;
    if (!h || !name) return NULL;
    nlen = strlen(name);
    for (i = 0; i < h->n; i++) {
        if (zu_ascii_ncasecmp(h->items[i].name, h->items[i].nlen, name, nlen) == 0) {
            if (c == idx) return h->items[i].value;
            c++;
        }
    }
    return NULL;
}

const char *zu_headers_get(const zu_headers *h, const char *name) {
    return zu_headers_get_at(h, name, 0);
}

int zu_headers_has(const zu_headers *h, const char *name) {
    return zu_headers_get(h, name) != NULL;
}

int zu_headers_write(const zu_headers *h, zu_buffer *out) {
    size_t i;
    if (!h || !out) return 0;
    for (i = 0; i < h->n; i++) {
        if (!zu_buf_append(out, h->items[i].name, h->items[i].nlen)) return 0;
        if (!zu_buf_append(out, ": ", 2)) return 0;
        if (!zu_buf_append(out, h->items[i].value, h->items[i].vlen)) return 0;
        if (!zu_buf_append(out, "\r\n", 2)) return 0;
    }
    return 1;
}

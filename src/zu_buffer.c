#include "zu_buffer.h"
#include "zu_alloc.h"
#include <string.h>

int zu_buf_hit_limit(const zu_buffer *b) { return b ? b->hit_limit : 0; }

static int grow_to(zu_buffer *b, size_t need) {
    size_t cap, total;
    unsigned char *p;

    if (need <= b->cap) return 1;

    if (b->max != 0 && need > b->max) {
        b->hit_limit = 1;
        return 0;
    }

    cap = b->cap ? b->cap : 64;
    while (cap < need) {
        /* 1.5x growth, overflow-checked. Doubling wastes more on large bodies. */
        size_t half = cap / 2;
        if (!zu_size_add(cap, half, &total)) { cap = need; break; }
        cap = total;
        if (b->max != 0 && cap > b->max) { cap = b->max; break; }
    }
    if (cap < need) cap = need;
    if (b->max != 0 && cap > b->max) cap = b->max;

    p = (unsigned char *)zu_realloc(b->data, cap);
    if (!p) return 0;
    b->data = p;
    b->cap = cap;
    return 1;
}

int zu_buf_init(zu_buffer *b, size_t initial_cap, size_t max) {
    if (!b) return 0;
    b->data = NULL; b->len = 0; b->cap = 0; b->max = max; b->hit_limit = 0;
    if (max != 0 && initial_cap > max) initial_cap = max;
    if (initial_cap == 0) return 1;
    return grow_to(b, initial_cap);
}

void zu_buf_free(zu_buffer *b) {
    if (!b) return;
    zu_free(b->data);
    b->data = NULL; b->len = 0; b->cap = 0;
}

void zu_buf_reset(zu_buffer *b) { if (b) b->len = 0; }

int zu_buf_reserve(zu_buffer *b, size_t extra) {
    size_t need;
    if (!b) return 0;
    if (!zu_size_add(b->len, extra, &need)) return 0;
    return grow_to(b, need);
}

int zu_buf_append(zu_buffer *b, const void *src, size_t n) {
    size_t need;
    if (!b) return 0;
    if (n == 0) return 1;
    if (!src) return 0;
    if (!zu_size_add(b->len, n, &need)) return 0;
    if (!grow_to(b, need)) return 0;
    memcpy(b->data + b->len, src, n);
    b->len = need;
    return 1;
}

int zu_buf_append_str(zu_buffer *b, const char *s) {
    if (!s) return 0;
    return zu_buf_append(b, s, strlen(s));
}

int zu_buf_append_byte(zu_buffer *b, unsigned char c) {
    return zu_buf_append(b, &c, 1);
}

int zu_buf_append_u64(zu_buffer *b, uint64_t v) {
    /* 2^64-1 is 20 digits. Build backwards into a fixed buffer: no division
     * by an attacker-controlled value, no allocation, no format string. */
    char tmp[20];
    int i = (int)sizeof tmp;
    if (v == 0) return zu_buf_append_byte(b, '0');
    while (v > 0 && i > 0) {
        tmp[--i] = (char)('0' + (int)(v % 10u));
        v /= 10u;
    }
    return zu_buf_append(b, tmp + i, sizeof tmp - (size_t)i);
}

void zu_buf_consume(zu_buffer *b, size_t n) {
    if (!b) return;
    if (n >= b->len) { b->len = 0; return; }
    memmove(b->data, b->data + n, b->len - n);
    b->len -= n;
}

int zu_buf_cstr(zu_buffer *b, const char **out) {
    size_t need;
    if (!b || !out) return 0;
    if (!zu_size_add(b->len, 1, &need)) return 0;
    if (!grow_to(b, need)) return 0;
    b->data[b->len] = '\0';
    *out = (const char *)b->data;
    return 1;
}

/* zuhttp — header list.
 *
 * Design §17.1 (injection rejection), §18.3 (duplicate semantics: a vector,
 * never a comma-joined scalar), §40 (count/size limits enforced on insert).
 *
 * Order and repetition are preserved because Set-Cookie requires it and
 * because a client that reorders headers cannot be used to reproduce a bug.
 */
#ifndef ZUHTTP_HEADERS_H
#define ZUHTTP_HEADERS_H

#include "zuh_platform.h"
#include "zuh_error.h"
#include "zuh_buffer.h"

typedef struct {
    char  *name;    /* owned; original case preserved for output */
    char  *value;   /* owned */
    size_t nlen;
    size_t vlen;
} zuh_header;

typedef struct {
    zuh_header *items;
    size_t     n;
    size_t     cap;
    size_t     bytes;       /* running total of name+value+4 per field */
    /* §40 limits; 0 disables an individual limit. */
    size_t     max_count;
    size_t     max_name;
    size_t     max_value;
    size_t     max_bytes;
} zuh_headers;

/* Sensible defaults for §40. */
#define ZUH_DEFAULT_MAX_HEADER_COUNT  100
#define ZUH_DEFAULT_MAX_HEADER_NAME   256
#define ZUH_DEFAULT_MAX_HEADER_VALUE  8192
#define ZUH_DEFAULT_MAX_HEADER_BYTES  65536

void zuh_headers_init(zuh_headers *h);
void zuh_headers_init_limited(zuh_headers *h, size_t max_count, size_t max_name,
                             size_t max_value, size_t max_bytes);
void zuh_headers_free(zuh_headers *h);

/* Validation (§17.1). A name must be a non-empty RFC 7230 token. A value must
 * contain no CR, LF or NUL. Rejection is an error, never silent stripping:
 * stripping turns an injection attempt into a subtly different request. */
int zuh_header_name_valid(const char *name, size_t len);
int zuh_header_value_valid(const char *value, size_t len);

/* Append. Returns ZUH_OK, ZUH_ERR_PARSE (invalid), ZUH_ERR_BODY_LIMIT (a §40
 * limit), or ZUH_ERR_NOMEM. Appending preserves duplicates. */
zuh_code zuh_headers_add(zuh_headers *h, const char *name, size_t nlen,
                       const char *value, size_t vlen);
zuh_code zuh_headers_add_str(zuh_headers *h, const char *name, const char *value);

/* Replace every field with this name (case-insensitive), or append if absent. */
zuh_code zuh_headers_set(zuh_headers *h, const char *name, const char *value);

/* Remove every field with this name. Returns how many were removed. */
size_t zuh_headers_remove(zuh_headers *h, const char *name);

/* §18.3 lookup. Case-insensitive. count() is the number of fields with that
 * name; get_at() returns the i-th, NULL when out of range. */
size_t      zuh_headers_count(const zuh_headers *h, const char *name);
const char *zuh_headers_get_at(const zuh_headers *h, const char *name, size_t i);
const char *zuh_headers_get(const zuh_headers *h, const char *name); /* first, or NULL */
int         zuh_headers_has(const zuh_headers *h, const char *name);

/* Iteration in wire order, for callers that must present every field —
 * printing, tracing, and the R accessor. Duplicates appear separately,
 * because §18.3 keeps them addressable rather than joining them.
 * zuh_headers_at() returns 0 when `i` is out of range. */
size_t zuh_headers_total(const zuh_headers *h);
int    zuh_headers_at(const zuh_headers *h, size_t i,
                     const char **name, const char **value);

/* ASCII case-insensitive compare, locale-independent. Header names are ASCII
 * by definition, and strcasecmp() is locale-sensitive and not C99. */
int zuh_ascii_casecmp(const char *a, const char *b);
int zuh_ascii_ncasecmp(const char *a, size_t alen, const char *b, size_t blen);

/* Serialise as "Name: value\r\n" for each field, in insertion order. */
int zuh_headers_write(const zuh_headers *h, zuh_buffer *out);

#endif /* ZUHTTP_HEADERS_H */

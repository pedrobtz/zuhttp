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

#include "zu_platform.h"
#include "zu_error.h"
#include "zu_buffer.h"

typedef struct {
    char  *name;    /* owned; original case preserved for output */
    char  *value;   /* owned */
    size_t nlen;
    size_t vlen;
} zu_header;

typedef struct {
    zu_header *items;
    size_t     n;
    size_t     cap;
    size_t     bytes;       /* running total of name+value+4 per field */
    /* §40 limits; 0 disables an individual limit. */
    size_t     max_count;
    size_t     max_name;
    size_t     max_value;
    size_t     max_bytes;
} zu_headers;

/* Sensible defaults for §40. */
#define ZU_DEFAULT_MAX_HEADER_COUNT  100
#define ZU_DEFAULT_MAX_HEADER_NAME   256
#define ZU_DEFAULT_MAX_HEADER_VALUE  8192
#define ZU_DEFAULT_MAX_HEADER_BYTES  65536

void zu_headers_init(zu_headers *h);
void zu_headers_init_limited(zu_headers *h, size_t max_count, size_t max_name,
                             size_t max_value, size_t max_bytes);
void zu_headers_free(zu_headers *h);

/* Validation (§17.1). A name must be a non-empty RFC 7230 token. A value must
 * contain no CR, LF or NUL. Rejection is an error, never silent stripping:
 * stripping turns an injection attempt into a subtly different request. */
int zu_header_name_valid(const char *name, size_t len);
int zu_header_value_valid(const char *value, size_t len);

/* Append. Returns ZU_OK, ZU_ERR_PARSE (invalid), ZU_ERR_BODY_LIMIT (a §40
 * limit), or ZU_ERR_NOMEM. Appending preserves duplicates. */
zu_code zu_headers_add(zu_headers *h, const char *name, size_t nlen,
                       const char *value, size_t vlen);
zu_code zu_headers_add_str(zu_headers *h, const char *name, const char *value);

/* Replace every field with this name (case-insensitive), or append if absent. */
zu_code zu_headers_set(zu_headers *h, const char *name, const char *value);

/* Remove every field with this name. Returns how many were removed. */
size_t zu_headers_remove(zu_headers *h, const char *name);

/* §18.3 lookup. Case-insensitive. count() is the number of fields with that
 * name; get_at() returns the i-th, NULL when out of range. */
size_t      zu_headers_count(const zu_headers *h, const char *name);
const char *zu_headers_get_at(const zu_headers *h, const char *name, size_t i);
const char *zu_headers_get(const zu_headers *h, const char *name); /* first, or NULL */
int         zu_headers_has(const zu_headers *h, const char *name);

/* Iteration in wire order, for callers that must present every field —
 * printing, tracing, and the R accessor. Duplicates appear separately,
 * because §18.3 keeps them addressable rather than joining them.
 * zu_headers_at() returns 0 when `i` is out of range. */
size_t zu_headers_total(const zu_headers *h);
int    zu_headers_at(const zu_headers *h, size_t i,
                     const char **name, const char **value);

/* ASCII case-insensitive compare, locale-independent. Header names are ASCII
 * by definition, and strcasecmp() is locale-sensitive and not C99. */
int zu_ascii_casecmp(const char *a, const char *b);
int zu_ascii_ncasecmp(const char *a, size_t alen, const char *b, size_t blen);

/* Serialise as "Name: value\r\n" for each field, in insertion order. */
int zu_headers_write(const zu_headers *h, zu_buffer *out);

#endif /* ZUHTTP_HEADERS_H */

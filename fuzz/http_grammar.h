/* A second reading of the HTTP/1.1 grammar, for the fuzz oracles (design
 * §43, #239).
 *
 * zuhttp parses a response head and chunked framing with picohttpparser and
 * validates fields in zuh_headers.c. The three harnesses that drive those
 * paths (fuzz_response, fuzz_chunked, fuzz_headers) used to fail only on a
 * crash, and a parser that accepts a bare CR or drops a byte at a chunk
 * boundary crashes nothing. This file is the other side of the comparison:
 * the RFC 9110 / RFC 9112 rules written out again, byte by byte, sharing no
 * code with src/, so that the harnesses can ask whether zuhttp's answer is
 * the grammar's answer.
 *
 * It is the grammar plus the leniencies RFC 9112 lets a recipient choose,
 * each named where it is taken, plus the §40 limits zuhttp documents. Every
 * place it is less strict than the ABNF is a decision zuhttp has made and
 * the comment says which; anywhere else, a disagreement is a finding.
 *
 * Results are three-valued, as a parser fed a prefix must be: G_OK (a whole
 * element, and where it ends), G_MORE (a proper prefix of something valid)
 * and G_BAD (no continuation can make it valid).
 */
#ifndef ZUH_FUZZ_HTTP_GRAMMAR_H
#define ZUH_FUZZ_HTTP_GRAMMAR_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { G_OK = 0, G_MORE = 1, G_BAD = 2 };

/* An oracle that fails says which, so a replay without a debugger, on any
 * CI platform, names the comparison that broke. */
#define G_CHECK(cond)                                                          \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "%s:%d: oracle failed: %s\n", __FILE__, __LINE__, \
                    #cond);                                                    \
            abort();                                                           \
        }                                                                      \
    } while (0)

/* §40's defaults, which zuh_headers_init() applies and the response parser
 * and the trailer section both use. */
#define G_MAX_FIELDS 100
#define G_MAX_NAME   256
#define G_MAX_VALUE  8192
#define G_MAX_BYTES  65536

/* RFC 9110 §5.6.2: tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" /
 * "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA */
static int g_tchar(unsigned char c) {
    if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
        return 1;
    return c != 0 && strchr("!#$%&'*+-.^_`|~", (int)c) != NULL;
}

/* RFC 9110 §5.5: field-vchar = VCHAR / obs-text */
static int g_field_vchar(unsigned char c) { return (c >= 0x21 && c <= 0x7E) || c >= 0x80; }
static int g_ws(unsigned char c) { return c == ' ' || c == '\t'; }
static int g_digit(unsigned char c) { return c >= '0' && c <= '9'; }
static int g_hex(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* field-name = token = 1*tchar */
static int g_token(const unsigned char *p, size_t n) {
    size_t i;
    if (n == 0) return 0;
    for (i = 0; i < n; i++)
        if (!g_tchar(p[i])) return 0;
    return 1;
}

/* The octets a field value may carry: field-vchar, SP and HTAB. The ABNF
 * (field-value = *field-content) also forbids a leading or trailing SP or
 * HTAB, which this does not check: on the wire that whitespace is OWS, which
 * every recipient strips (RFC 9112 §5.1), so a value sent with it arrives as
 * the value without it; nothing else is read into the message. zuhttp
 * accepts such a value, and fuzz_headers asserts that the re-parse strips
 * it rather than that it is refused. */
static int g_value_octets(const unsigned char *p, size_t n) {
    size_t i;
    for (i = 0; i < n; i++)
        if (!g_ws(p[i]) && !g_field_vchar(p[i])) return 0;
    return 1;
}

static int g_lower(unsigned char c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }

static int g_name_is(const unsigned char *p, size_t n, const char *lit) {
    size_t i, k = strlen(lit);
    if (n != k) return 0;
    for (i = 0; i < n; i++)
        if (g_lower(p[i]) != g_lower((unsigned char)lit[i])) return 0;
    return 1;
}

/* At a CR or LF: the line terminator. RFC 9112 §2.2 lets a recipient take a
 * bare LF as one in the start-line and in fields, and picohttpparser does;
 * a bare CR is invalid ("MUST consider that element to be invalid"). */
static int g_eol(const unsigned char *b, size_t len, size_t *i) {
    if (b[*i] == '\n') { (*i)++; return G_OK; }
    if (*i + 1 >= len) return G_MORE;
    if (b[*i + 1] != '\n') return G_BAD;
    *i += 2;
    return G_OK;
}

typedef struct {
    const unsigned char *name;      /* NULL for an obs-fold line */
    size_t nlen;
    const unsigned char *value;     /* OWS stripped both ends */
    size_t vlen;
} g_field;

typedef struct {
    int     rc;
    size_t  end;                    /* just past the empty line, when G_OK */
    size_t  n;
    g_field f[G_MAX_FIELDS];
} g_fields;

/* *( field-line CRLF ) CRLF from offset i, with field-line = field-name ":"
 * OWS field-value OWS (RFC 9112 §5). Two §40 rules are part of the syntax
 * here because picohttpparser applies them while it parses: a 101st field
 * line is refused as soon as it starts, and an obs-fold line counts as one.
 * Everything else zuhttp refuses only once the block is whole; that is
 * g_fields_acceptable(). */
static int g_parse_fields(const unsigned char *b, size_t len, size_t i, g_fields *o) {
    o->n = 0;
    o->end = 0;
    for (;;) {
        const unsigned char *name = NULL, *value;
        size_t nlen = 0, vlen;
        int r;
        if (i >= len) return o->rc = G_MORE;
        if (b[i] == '\r' || b[i] == '\n') {
            r = g_eol(b, len, &i);
            if (r == G_OK) o->end = i;
            return o->rc = r;
        }
        if (o->n == G_MAX_FIELDS) return o->rc = G_BAD;
        if (g_ws(b[i])) {
            /* RFC 9112 §2.2: whitespace before the first field line is
             * refused; §5.2: later, it is obs-fold, kept here for
             * g_fields_acceptable() to refuse (§18.1). */
            if (o->n == 0) return o->rc = G_BAD;
        } else {
            name = b + i;
            while (i < len && b[i] != ':') {
                if (!g_tchar(b[i])) return o->rc = G_BAD;   /* incl. SP before ':' */
                i++;
            }
            if (i >= len) return o->rc = G_MORE;
            nlen = (size_t)(b + i - name);
            if (nlen == 0) return o->rc = G_BAD;
            i++;
        }
        while (i < len && g_ws(b[i])) i++;
        if (i >= len) return o->rc = G_MORE;
        value = b + i;
        while (i < len && b[i] != '\r' && b[i] != '\n') {
            if (!g_ws(b[i]) && !g_field_vchar(b[i])) return o->rc = G_BAD;
            i++;
        }
        if (i >= len) return o->rc = G_MORE;
        vlen = (size_t)(b + i - value);
        while (vlen && g_ws(value[vlen - 1])) vlen--;
        r = g_eol(b, len, &i);
        if (r != G_OK) return o->rc = r;
        o->f[o->n].name = name;
        o->f[o->n].nlen = nlen;
        o->f[o->n].value = value;
        o->f[o->n].vlen = vlen;
        o->n++;
    }
}

/* What zuhttp refuses in a syntactically whole field block: obs-fold
 * (§18.1) and the §40 name, value and total limits, where the total counts
 * name + ": " + value + CRLF per field. */
static int g_fields_acceptable(const g_fields *o) {
    size_t i, bytes = 0;
    for (i = 0; i < o->n; i++) {
        if (!o->f[i].name) return 0;
        if (o->f[i].nlen > G_MAX_NAME || o->f[i].vlen > G_MAX_VALUE) return 0;
        bytes += o->f[i].nlen + o->f[i].vlen + 4;
        if (bytes > G_MAX_BYTES) return 0;
    }
    return 1;
}

/* --- the response head (RFC 9112 §4) ------------------------------------- */

typedef struct {
    int      rc;
    int      early;     /* see below */
    int      minor, status;
    const unsigned char *reason;
    size_t   rlen;
    g_fields h;
} g_head;

/* status-line = HTTP-version SP status-code SP [ reason-phrase ] CRLF, then
 * the field block. Leniencies, all picohttpparser's and all ones RFC 9112
 * §4 allows a recipient: any run of SP separates the elements; the SP after
 * the status code may be missing when the reason is empty; a bare LF ends
 * the line (§2.2). The major version must be 1 (an HTTP/2 or HTTP/0.9 reply
 * is not this parser's), the minor version 0 or 1 (§18), the status 100 to
 * 599 (RFC 9110 §15).
 *
 * `early`: picohttpparser asks for more input, rather than judging, until it
 * has 9 bytes for "HTTP/1.x " and 4 from the status code on, and it judges
 * what follows the status code ("2000") only at the end of the line. A
 * G_BAD that is early may come back from zuhttp as ZUH_ERR_WOULDBLOCK; any
 * other G_BAD must be refused, and a G_MORE must not be. */
static void g_parse_head(const unsigned char *b, size_t len, g_head *o) {
    static const char ver[] = "HTTP/1.";
    size_t i, s;
    int garbage = 0;
    memset(o, 0, sizeof *o);
    o->early = len < 9;
    for (i = 0; i < 7; i++) {
        if (i >= len) { o->rc = G_MORE; return; }
        if (b[i] != (unsigned char)ver[i]) { o->rc = G_BAD; return; }
    }
    if (i >= len) { o->rc = G_MORE; return; }
    if (!g_digit(b[i])) { o->rc = G_BAD; return; }
    o->minor = b[i++] - '0';
    if (i >= len) { o->rc = G_MORE; return; }
    if (b[i] != ' ') { o->rc = G_BAD; return; }
    while (i < len && b[i] == ' ') i++;
    s = i;
    if (len - s < 4) o->early = 1;
    for (; i < s + 3; i++) {
        if (i >= len) { o->rc = G_MORE; return; }
        if (!g_digit(b[i])) { o->rc = G_BAD; return; }
        o->status = o->status * 10 + (b[i] - '0');
    }
    if (i >= len) { o->rc = G_MORE; return; }
    /* "2000", "200\t": not a status code. Refused, but picohttpparser only
     * says so at the end of the line, so until then that is early. */
    if (b[i] == ' ') {
        while (i < len && b[i] == ' ') i++;
    } else if (b[i] != '\r' && b[i] != '\n') {
        garbage = 1;
    }
    /* reason-phrase = 1*( HTAB / SP / VCHAR / obs-text ) */
    o->reason = b + i;
    while (i < len && b[i] != '\r' && b[i] != '\n') {
        if (!g_ws(b[i]) && !g_field_vchar(b[i])) { o->rc = G_BAD; return; }
        i++;
    }
    if (i >= len) {
        if (garbage) o->early = 1;
        o->rc = garbage ? G_BAD : G_MORE;
        return;
    }
    o->rlen = (size_t)(b + i - o->reason);
    o->rc = g_eol(b, len, &i);
    if (o->rc == G_MORE && garbage) { o->early = 1; o->rc = G_BAD; }
    if (garbage && o->rc == G_OK) o->rc = G_BAD;
    if (o->rc != G_OK) return;
    o->rc = g_parse_fields(b, len, i, &o->h);
    if (o->rc == G_OK &&
        (o->minor > 1 || o->status < 100 || o->status > 599 || !g_fields_acceptable(&o->h)))
        o->rc = G_BAD;
}

/* --- chunked framing (RFC 9112 §7.1) -------------------------------------- */

/* chunk-ext = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] ),
 * chunk-ext-val = token / quoted-string. On G_OK, *i is at the CR. */
static int g_ext_strict(const unsigned char *b, size_t len, size_t *i) {
    size_t j = *i;
    for (;;) {
        size_t k = j, start;
        while (k < len && g_ws(b[k])) k++;
        if (k >= len) return G_MORE;
        if (b[k] != ';') break;
        k++;
        while (k < len && g_ws(b[k])) k++;
        start = k;
        while (k < len && g_tchar(b[k])) k++;
        if (k >= len) return G_MORE;
        if (k == start) return G_BAD;
        j = k;
        while (k < len && g_ws(b[k])) k++;
        if (k >= len) return G_MORE;
        if (b[k] != '=') continue;
        k++;
        while (k < len && g_ws(b[k])) k++;
        if (k >= len) return G_MORE;
        if (b[k] == '"') {
            /* quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE */
            k++;
            for (;;) {
                if (k >= len) return G_MORE;
                if (b[k] == '"') { k++; break; }
                if (b[k] == '\\') {
                    if (k + 1 >= len) return G_MORE;
                    if (!g_ws(b[k + 1]) && !g_field_vchar(b[k + 1])) return G_BAD;
                    k += 2;
                    continue;
                }
                if (!g_ws(b[k]) && !g_field_vchar(b[k])) return G_BAD;
                k++;
            }
        } else {
            start = k;
            while (k < len && g_tchar(b[k])) k++;
            if (k >= len) return G_MORE;
            if (k == start) return G_BAD;
        }
        j = k;
    }
    *i = j;
    return G_OK;
}

/* picohttpparser does not parse a chunk extension. After the size it takes
 * SP, HTAB or ";" as its start and skips to the CR, refusing only a LF on
 * the way; "5 junk" and "5;" pass. That is less strict than the ABNF, and
 * accepted: RFC 9112 §7.1.1 has a recipient ignore an extension it does not
 * understand, zuhttp understands none, and a line terminator, the one thing
 * in it that would change the framing, is still refused. fuzz_chunked runs
 * both readings and holds zuhttp to this one exactly and to the strict one
 * in one direction: whatever the ABNF accepts, zuhttp accepts. */
static int g_ext_lax(const unsigned char *b, size_t len, size_t *i) {
    size_t j = *i;
    if (j >= len) return G_MORE;
    if (b[j] == '\r') return G_OK;
    if (!g_ws(b[j]) && b[j] != ';') return G_BAD;
    for (; j < len; j++) {
        if (b[j] == '\r') { *i = j; return G_OK; }
        if (b[j] == '\n') return G_BAD;
    }
    return G_MORE;
}

typedef struct {
    int      rc;
    size_t   outlen;        /* chunk-data bytes, so far when not G_OK */
    g_fields t;             /* the trailer section, when G_OK */
    size_t   surplus;       /* bytes after the message, when G_OK */
} g_chunked;

/* chunked-body = *chunk last-chunk trailer-section CRLF, decoded into `out`
 * (at least `len` bytes). The chunk lines themselves need CRLF: §2.2's bare
 * LF leniency is for the start-line and fields, and the trailer section is
 * fields, so it gets it. One limit is zuhttp's: a chunk-size of more than 16
 * hex digits is refused, leading zeros or not, because it does not fit the
 * 64-bit count picohttpparser keeps (§18.1). */
static void g_decode_chunked(const unsigned char *b, size_t len, int strict_ext,
                             unsigned char *out, g_chunked *o) {
    size_t i = 0;
    memset(o, 0, sizeof *o);
    for (;;) {
        uint64_t size = 0;
        int digits = 0, v, r;
        while (i < len && (v = g_hex(b[i])) >= 0) {
            if (digits == 16) { o->rc = G_BAD; return; }
            size = size * 16 + (uint64_t)v;
            digits++;
            i++;
        }
        if (i >= len) { o->rc = G_MORE; return; }
        if (digits == 0) { o->rc = G_BAD; return; }
        r = strict_ext ? g_ext_strict(b, len, &i) : g_ext_lax(b, len, &i);
        if (r != G_OK) { o->rc = r; return; }
        if (i >= len) { o->rc = G_MORE; return; }
        if (b[i] != '\r') { o->rc = G_BAD; return; }
        if (++i >= len) { o->rc = G_MORE; return; }
        if (b[i] != '\n') { o->rc = G_BAD; return; }
        i++;
        if (size == 0) break;                       /* last-chunk */
        if ((uint64_t)(len - i) < size) {
            memcpy(out + o->outlen, b + i, len - i);
            o->outlen += len - i;
            o->rc = G_MORE;
            return;
        }
        memcpy(out + o->outlen, b + i, (size_t)size);
        o->outlen += (size_t)size;
        i += (size_t)size;
        if (i >= len) { o->rc = G_MORE; return; }
        if (b[i] != '\r') { o->rc = G_BAD; return; }
        if (++i >= len) { o->rc = G_MORE; return; }
        if (b[i] != '\n') { o->rc = G_BAD; return; }
        i++;
    }
    o->rc = g_parse_fields(b, len, i, &o->t);
    if (o->rc == G_OK) {
        if (!g_fields_acceptable(&o->t)) o->rc = G_BAD;
        else o->surplus = len - o->t.end;
    }
}

#endif /* ZUH_FUZZ_HTTP_GRAMMAR_H */

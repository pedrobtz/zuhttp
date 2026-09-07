/* zuhttp — R entry points.
 *
 * Design §11: this is the ONLY file permitted to include R headers. Every
 * other translation unit under src/ is plain C, which is what allows the core
 * to link into ctest/ and a fuzz harness with no R runtime present. If you
 * find yourself adding <R.h> to another file, the layering is wrong.
 *
 * S12 registers the first routines: the §34.1 condition hierarchy and the
 * §42 redaction policy. Both are deliberately C-side rather than
 * reimplemented in R, so there is one definition of each (see zu_error.c and
 * zu_redact.c for why).
 */
#include <R.h>
#include <Rinternals.h>
#include <R_ext/Rdynload.h>
#include <R_ext/Visibility.h>

#include "zu_error.h"
#include "zu_redact.h"
#include "zu_buffer.h"

/* Anything a caller could make arbitrarily large is bounded here rather than
 * in the R layer, so the bound cannot be bypassed by a different caller. */
#define ZU_R_TEXT_MAX (1u << 20)

/* --- §34.1 conditions ----------------------------------------------------- */

/* The class chain for one code, most specific first, with "error" and
 * "condition" appended — those two are R's names, so R is where they belong. */
static SEXP C_zu_condition_classes(SEXP code_sexp) {
    const char *chain[ZU_CLASS_CHAIN_MAX];
    int n, i;
    SEXP out;

    if (!Rf_isInteger(code_sexp) || Rf_length(code_sexp) != 1)
        Rf_error("code must be a single integer");

    n = zu_code_class_chain((zu_code)INTEGER(code_sexp)[0], chain, ZU_CLASS_CHAIN_MAX);
    if (n == 0) Rf_error("unknown zuhttp error code: %d", INTEGER(code_sexp)[0]);

    out = PROTECT(Rf_allocVector(STRSXP, n + 2));
    for (i = 0; i < n; i++)
        SET_STRING_ELT(out, i, Rf_mkChar(chain[i]));
    SET_STRING_ELT(out, n,     Rf_mkChar("error"));
    SET_STRING_ELT(out, n + 1, Rf_mkChar("condition"));
    UNPROTECT(1);
    return out;
}

/* Every code, as a named integer vector: names are the leaf class, values the
 * stable zu_code. Lets the R layer build its constants from the C enum rather
 * than restating it. */
static SEXP C_zu_error_codes(void) {
    int i, n = (int)ZU_CODE_COUNT;
    SEXP out = PROTECT(Rf_allocVector(INTSXP, n));
    SEXP nms = PROTECT(Rf_allocVector(STRSXP, n));
    for (i = 0; i < n; i++) {
        INTEGER(out)[i] = i;
        SET_STRING_ELT(nms, i, Rf_mkChar(zu_code_class((zu_code)i)));
    }
    Rf_setAttrib(out, R_NamesSymbol, nms);
    UNPROTECT(2);
    return out;
}

static SEXP C_zu_code_retryable(SEXP code_sexp) {
    if (!Rf_isInteger(code_sexp) || Rf_length(code_sexp) != 1)
        Rf_error("code must be a single integer");
    return Rf_ScalarLogical(zu_code_retryable((zu_code)INTEGER(code_sexp)[0]));
}

/* --- §42 redaction -------------------------------------------------------- */

/* Build a NULL-terminated array of C strings from a character vector. The
 * pointers borrow R's storage, which is fine because the array never outlives
 * the call. Returns NULL for an empty vector. */
static const char **str_list(SEXP v, int *n_out) {
    int i, n;
    const char **list;
    if (v == R_NilValue) { *n_out = 0; return NULL; }
    if (!Rf_isString(v)) Rf_error("expected a character vector");
    n = Rf_length(v);
    *n_out = n;
    if (n == 0) return NULL;
    list = (const char **)R_alloc((size_t)n + 1, sizeof(char *));
    for (i = 0; i < n; i++) {
        SEXP e = STRING_ELT(v, i);
        if (e == NA_STRING) Rf_error("NA is not a valid name");
        list[i] = CHAR(e);
    }
    list[n] = NULL;
    return list;
}

static void policy_from(SEXP extra_headers, SEXP extra_params, zu_redact_policy *p) {
    int nh = 0, np = 0;
    zu_redact_policy_init(p);
    p->extra_headers = str_list(extra_headers, &nh);
    p->extra_params  = str_list(extra_params,  &np);
}

/* One scalar string in, one scalar string out, through a zu_buffer. */
static SEXP redact_one(SEXP text, SEXP extra_headers, SEXP extra_params,
                       int (*fn)(const zu_redact_policy *, const char *, size_t,
                                 zu_buffer *)) {
    zu_redact_policy p;
    zu_buffer b;
    SEXP e, out;
    const char *s;
    size_t n;

    if (!Rf_isString(text) || Rf_length(text) != 1)
        Rf_error("expected a single string");
    e = STRING_ELT(text, 0);
    if (e == NA_STRING) return Rf_ScalarString(NA_STRING);

    /* Redaction runs on UTF-8 bytes: a URL or form body is bytes, and
     * translating to the native encoding could mangle what we must show. */
    s = Rf_translateCharUTF8(e);
    n = strlen(s);
    if (n > ZU_R_TEXT_MAX) Rf_error("input is too long to redact (%lu bytes)",
                                    (unsigned long)n);

    policy_from(extra_headers, extra_params, &p);
    if (!zu_buf_init(&b, n + 32, ZU_R_TEXT_MAX * 2)) Rf_error("out of memory");
    if (!fn(&p, s, n, &b)) { zu_buf_free(&b); Rf_error("redaction failed"); }

    out = PROTECT(Rf_allocVector(STRSXP, 1));
    SET_STRING_ELT(out, 0, Rf_mkCharLenCE((const char *)b.data, (int)b.len, CE_UTF8));
    zu_buf_free(&b);
    UNPROTECT(1);
    return out;
}

static SEXP C_zu_redact_url(SEXP url, SEXP extra_params) {
    return redact_one(url, R_NilValue, extra_params, zu_redact_url);
}

static SEXP C_zu_redact_form(SEXP body, SEXP extra_params) {
    return redact_one(body, R_NilValue, extra_params, zu_redact_form_body);
}

/* Vectorised: which of these header names carry a secret value? */
static SEXP C_zu_is_secret_header(SEXP names, SEXP extra_headers) {
    zu_redact_policy p;
    int i, n;
    SEXP out;

    if (!Rf_isString(names)) Rf_error("names must be a character vector");
    policy_from(extra_headers, R_NilValue, &p);
    n = Rf_length(names);
    out = PROTECT(Rf_allocVector(LGLSXP, n));
    for (i = 0; i < n; i++) {
        SEXP e = STRING_ELT(names, i);
        if (e == NA_STRING) { LOGICAL(out)[i] = NA_LOGICAL; continue; }
        {
            const char *s = Rf_translateCharUTF8(e);
            LOGICAL(out)[i] = zu_redact_is_secret_header(&p, s, strlen(s));
        }
    }
    UNPROTECT(1);
    return out;
}

static SEXP C_zu_is_secret_param(SEXP names, SEXP extra_params) {
    zu_redact_policy p;
    int i, n;
    SEXP out;

    if (!Rf_isString(names)) Rf_error("names must be a character vector");
    policy_from(R_NilValue, extra_params, &p);
    n = Rf_length(names);
    out = PROTECT(Rf_allocVector(LGLSXP, n));
    for (i = 0; i < n; i++) {
        SEXP e = STRING_ELT(names, i);
        if (e == NA_STRING) { LOGICAL(out)[i] = NA_LOGICAL; continue; }
        {
            const char *s = Rf_translateCharUTF8(e);
            LOGICAL(out)[i] = zu_redact_is_secret_param(&p, s, strlen(s));
        }
    }
    UNPROTECT(1);
    return out;
}

/* --- registration --------------------------------------------------------- */

static const R_CallMethodDef call_methods[] = {
    {"C_zu_condition_classes", (DL_FUNC) &C_zu_condition_classes, 1},
    {"C_zu_error_codes",       (DL_FUNC) &C_zu_error_codes,       0},
    {"C_zu_code_retryable",    (DL_FUNC) &C_zu_code_retryable,    1},
    {"C_zu_redact_url",        (DL_FUNC) &C_zu_redact_url,        2},
    {"C_zu_redact_form",       (DL_FUNC) &C_zu_redact_form,       2},
    {"C_zu_is_secret_header",  (DL_FUNC) &C_zu_is_secret_header,  2},
    {"C_zu_is_secret_param",   (DL_FUNC) &C_zu_is_secret_param,   2},
    {NULL, NULL, 0}
};

void attribute_visible R_init_zuhttp(DllInfo *dll) {
    R_registerRoutines(dll, NULL, call_methods, NULL, NULL);
    R_useDynamicSymbols(dll, FALSE);
    R_forceSymbols(dll, TRUE);
}

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
#include "zu_engine.h"
#include "zu_headers.h"
#include "zu_tls.h"
#include <string.h>

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

/* --- §25 cancellation ------------------------------------------------------
 *
 * §25.2 is the whole problem: R_CheckUserInterrupt() does not RETURN when an
 * interrupt is pending, it longjmps past every C frame between it and the
 * enclosing tryCatch — abandoning sockets, TLS contexts, zlib streams and
 * buffers held in C locals.
 *
 * So the tick never calls it directly. R_ToplevelExec runs a function and
 * returns FALSE if that function longjmped, catching the unwind at a frame
 * where nothing of ours is live. The tick then returns 1, the poll loop in
 * zu_net.c gives up, and the engine unwinds through its OWN error paths,
 * closing the socket and freeing every buffer on the way out.
 *
 * That is §25.2's discipline (b) — no native allocation lives only in a C
 * local across a checkpoint — enforced by never letting a longjmp cross one. */
static void check_interrupt_inner(void *ignored) {
    (void)ignored;
    R_CheckUserInterrupt();
}

static int r_interrupt_tick(void *ctx) {
    (void)ctx;
#if defined(_WIN32)
    /* §25.4: in Rgui and RStudio the interrupt is delivered through the event
     * loop, so it is never observed unless the loop is pumped. */
    R_ProcessEvents();
#endif
    return R_ToplevelExec(check_interrupt_inner, NULL) ? 0 : 1;
}

/* --- §63.2 the vertical slice --------------------------------------------- */

static SEXP build_response(void *data);

/* Runs whether build_response returned or longjmped (§25.2 mechanism (a)).
 * `jump` is TRUE only on the unwind path; the work is identical either way,
 * so it is deliberately not branched on. */
static void free_result_on_unwind(void *data, Rboolean jump) {
    (void)jump;
    zu_result_free((zu_result *)data);
}

/* Raise the §34.1 condition for a zu_error by calling back into R. Building
 * the condition in R rather than in C keeps the class hierarchy in one place
 * (zu_condition()) and keeps this file free of condition construction. */
static void raise_zu_error(const zu_error *e, const char *url) {
    /* zuhttp:::zu_stop_from_c(code, message, url, phase, backend, backend_code)
     *
     * Six arguments, and R only provides Rf_lang1..Rf_lang6 (function plus
     * five), so the call is built by hand rather than trimmed to fit. */
    SEXP fn     = PROTECT(Rf_install("zu_stop_from_c"));
    /* The name MUST be protected across R_FindNamespace: that call allocates
     * (it evaluates getNamespace), and an unprotected mkString result can be
     * collected underneath it. Writing it as
     *     R_FindNamespace(Rf_mkString("zuhttp"))
     * is the classic form of this bug, and it is timing-dependent — it ran
     * clean on macOS and Linux and segfaulted on Windows. */
    SEXP nsname = PROTECT(Rf_mkString("zuhttp"));
    SEXP ns     = PROTECT(R_FindNamespace(nsname));
    SEXP args   = PROTECT(Rf_allocList(6));
    SEXP call   = PROTECT(Rf_lcons(fn, args));   /* lcons yields a LANGSXP */
    SEXP p      = args;

    SETCAR(p, Rf_ScalarInteger((int)e->code));                          p = CDR(p);
    SETCAR(p, Rf_mkString(e->message[0] ? e->message : "request failed")); p = CDR(p);
    SETCAR(p, url ? Rf_mkString(url) : R_NilValue);                     p = CDR(p);
    SETCAR(p, Rf_mkString(zu_phase_name(e->phase)));                    p = CDR(p);
    SETCAR(p, e->backend[0] ? Rf_mkString(e->backend) : R_NilValue);    p = CDR(p);
    SETCAR(p, Rf_ScalarInteger(e->backend_code));

    Rf_eval(call, ns);           /* zu_stop_from_c() does not return */
    UNPROTECT(5);
}

static SEXP headers_to_r(const zu_headers *h) {
    size_t n = zu_headers_total(h), i;
    SEXP out = PROTECT(Rf_allocVector(STRSXP, (R_xlen_t)n));
    SEXP nms = PROTECT(Rf_allocVector(STRSXP, (R_xlen_t)n));
    for (i = 0; i < n; i++) {
        const char *name = NULL, *value = NULL;
        zu_headers_at(h, i, &name, &value);
        SET_STRING_ELT(nms, (R_xlen_t)i, Rf_mkChar(name ? name : ""));
        SET_STRING_ELT(out, (R_xlen_t)i, Rf_mkCharCE(value ? value : "", CE_UTF8));
    }
    Rf_setAttrib(out, R_NamesSymbol, nms);
    UNPROTECT(2);
    return out;
}

/* One entry point for every method. The R layer owns argument shaping; this
 * function's job is to translate and to own nothing across a longjmp. */
static SEXP C_zu_perform(SEXP method, SEXP url, SEXP header_names,
                         SEXP header_values, SEXP body, SEXP timeout_ms,
                         SEXP max_redirects, SEXP verify, SEXP max_body,
                         SEXP user_agent, SEXP decode) {
    zu_get_opts o;
    zu_req_spec spec;
    zu_result r;
    zu_error e;
    zu_code rc;
    const char *u;
    int nh = 0, i;

    if (!Rf_isString(url) || Rf_length(url) != 1 || STRING_ELT(url, 0) == NA_STRING)
        Rf_error("url must be a single non-NA string");
    u = Rf_translateCharUTF8(STRING_ELT(url, 0));

    memset(&spec, 0, sizeof spec);
    if (Rf_isString(method) && Rf_length(method) == 1)
        spec.method = Rf_translateCharUTF8(STRING_ELT(method, 0));

    if (header_names != R_NilValue) {
        if (!Rf_isString(header_names) || !Rf_isString(header_values) ||
            Rf_length(header_names) != Rf_length(header_values))
            Rf_error("header names and values must be character vectors of equal length");
        nh = Rf_length(header_names);
    }
    if (nh > 0) {
        /* R_alloc storage is released when the .Call returns, including on a
         * longjmp, so these borrowed pointers cannot outlive their memory. */
        const char **hn = (const char **)R_alloc((size_t)nh, sizeof(char *));
        const char **hv = (const char **)R_alloc((size_t)nh, sizeof(char *));
        for (i = 0; i < nh; i++) {
            SEXP n = STRING_ELT(header_names, i), v = STRING_ELT(header_values, i);
            if (n == NA_STRING || v == NA_STRING)
                Rf_error("header names and values must not be NA");
            hn[i] = Rf_translateCharUTF8(n);
            hv[i] = Rf_translateCharUTF8(v);
        }
        spec.header_names  = hn;
        spec.header_values = hv;
        spec.n_headers     = (size_t)nh;
    }

    if (body != R_NilValue) {
        if (TYPEOF(body) != RAWSXP)
            Rf_error("body must be a raw vector; the R layer serialises everything else");
        spec.body     = RAW(body);
        spec.body_len = (size_t)Rf_xlength(body);
    }

    zu_get_opts_init(&o);
    o.timeout_ms    = (long)Rf_asInteger(timeout_ms);
    o.max_redirects = Rf_asInteger(max_redirects);
    o.verify        = Rf_asLogical(verify) == TRUE;
    o.max_body      = (uint64_t)Rf_asReal(max_body);
    o.no_decode     = Rf_asLogical(decode) != TRUE;
    if (Rf_isString(user_agent) && Rf_length(user_agent) == 1)
        o.user_agent = Rf_translateCharUTF8(STRING_ELT(user_agent, 0));

    /* §25.1: a checkpoint at most one tick apart, and never inside a blocking
     * call. 100 ms is the design's ceiling. */
    o.tick     = r_interrupt_tick;
    o.tick_ctx = NULL;

    zu_error_clear(&e);
    rc = zu_engine_perform(&r, u, &spec, &o, &e);
    if (rc != ZU_OK) {
        /* Our tick returns 1 only for a pending user interrupt, so a
         * cancellation reaching here is always that (§34.1 separates
         * zu_interrupted_error from zu_cancelled_error because a person
         * pressing Ctrl-C and a programmatic stop want different handling). */
        if (rc == ZU_ERR_CANCELLED) {
            zu_error err2 = e;
            err2.code = ZU_ERR_INTERRUPTED;
            snprintf(err2.message, sizeof err2.message,
                     "request interrupted by the user");
            raise_zu_error(&err2, u);
            return R_NilValue;   /* not reached */
        }
        /* No C resources are live here: zu_engine_get frees everything it
         * owns before returning non-OK, which is what makes it safe to raise
         * an R condition (and longjmp) from this point. */
        raise_zu_error(&e, u);
        return R_NilValue;   /* not reached */
    }

    /* The continuation token must be NULL, not R_NilValue. R checks
     * `cont == NULL` and allocates its own token in that case; R_NilValue is a
     * perfectly valid SEXP, so it passes that check and is then used as a
     * continuation it is not, which fails with "bad value" on every call. */
    return R_UnwindProtect(build_response, &r, free_result_on_unwind, &r, NULL);
}

/* Everything below runs with `r` still owning C memory, and every R allocation
 * here can longjmp on failure. R_UnwindProtect guarantees free_result_on_unwind
 * runs either way — §25.2's mechanism (a), used to release promptly rather
 * than at the next GC. */
static SEXP build_response(void *data) {
    zu_result *rp = (zu_result *)data;
    zu_result r = *rp;
    SEXP out, nms, body;

    body = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t)r.body.len));
    if (r.body.len) memcpy(RAW(body), r.body.data, r.body.len);

    out = PROTECT(Rf_allocVector(VECSXP, 6));
    nms = PROTECT(Rf_allocVector(STRSXP, 6));
    SET_VECTOR_ELT(out, 0, Rf_ScalarInteger(r.status));
    SET_STRING_ELT(nms, 0, Rf_mkChar("status"));
    SET_VECTOR_ELT(out, 1, headers_to_r(&r.headers));
    SET_STRING_ELT(nms, 1, Rf_mkChar("headers"));
    SET_VECTOR_ELT(out, 2, body);
    SET_STRING_ELT(nms, 2, Rf_mkChar("body"));
    SET_VECTOR_ELT(out, 3, r.final_url ? Rf_mkString(r.final_url) : R_NilValue);
    SET_STRING_ELT(nms, 3, Rf_mkChar("url"));
    SET_VECTOR_ELT(out, 4, r.tls_version ? Rf_mkString(r.tls_version) : R_NilValue);
    SET_STRING_ELT(nms, 4, Rf_mkChar("tls_version"));
    SET_VECTOR_ELT(out, 5, Rf_ScalarInteger(r.redirects));
    SET_STRING_ELT(nms, 5, Rf_mkChar("redirects"));
    Rf_setAttrib(out, R_NamesSymbol, nms);

    UNPROTECT(3);
    return out;
}

static SEXP C_zu_tls_backend(void) {
    return Rf_mkString(zu_tls_backend_name());
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
    {"C_zu_perform",           (DL_FUNC) &C_zu_perform,          11},
    {"C_zu_tls_backend",       (DL_FUNC) &C_zu_tls_backend,       0},
    {NULL, NULL, 0}
};

void attribute_visible R_init_zuhttp(DllInfo *dll) {
    R_registerRoutines(dll, NULL, call_methods, NULL, NULL);
    R_useDynamicSymbols(dll, FALSE);
    R_forceSymbols(dll, TRUE);
}

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
#include "zu_pool.h"
#include "zu_sink.h"
#include "zu_trace.h"
#include <string.h>

/* Anything a caller could make arbitrarily large is bounded here rather than
 * in the R layer, so the bound cannot be bypassed by a different caller. */
#define ZU_R_TEXT_MAX (1u << 20)

/* --- §27 the R callback sink ----------------------------------------------
 *
 * §27.3 is the whole difficulty. A user callback can raise an R error, and
 * that error longjmps out of the middle of the C read loop — past the socket,
 * the TLS context and the inflate stream, all of which are C allocations with
 * no R finalizer. The identical hazard to §25.2, and it takes the identical
 * mechanism:
 *
 *   1. call through R_tryCatch(), never a bare Rf_eval();
 *   2. on a caught condition, record it, let the native loop unwind NORMALLY
 *      so every C resource is released, and only then re-signal the original
 *      condition — so the user sees THEIR error, not a zu_* error that
 *      swallowed it.
 *
 * The re-signal is the part that is easy to get subtly wrong: wrapping the
 * condition, or reporting a cancellation, turns a clear "object 'x' not
 * found" in the user's own callback into a mysterious transport failure.
 */
typedef struct {
    SEXP fn;
    SEXP caught;     /* preserved condition, or NULL */
    int  stopped;    /* the callback asked to stop (§27.2 sentinel) */
} cb_ctx;

typedef struct { cb_ctx *c; SEXP chunk; } cb_call;

static SEXP cb_body(void *data) {
    cb_call *cc = (cb_call *)data;
    SEXP call = PROTECT(Rf_lang2(cc->c->fn, cc->chunk));
    SEXP res  = Rf_eval(call, R_GlobalEnv);
    UNPROTECT(1);
    return res;
}

static SEXP cb_handler(SEXP cond, void *data) {
    cb_ctx *c = (cb_ctx *)data;
    /* Preserved rather than PROTECTed: this has to survive until after the
     * engine has unwound, which is past the end of any protection frame we
     * could open here. */
    if (!c->caught) { R_PreserveObject(cond); c->caught = cond; }
    return R_NilValue;
}

static zu_code cb_write(zu_sink *s, const unsigned char *d, size_t n,
                        zu_error *err) {
    cb_ctx *c = (cb_ctx *)s->ctx;
    cb_call cc;
    SEXP classes, res;

    if (c->caught || c->stopped) return ZU_ERR_CANCELLED;

    cc.c = c;
    cc.chunk = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t)n));
    memcpy(RAW(cc.chunk), d, n);

    /* "error" and "interrupt", NOT "condition".
     *
     * §27.3 says to catch a condition, but catching every condition class is
     * too broad and actively wrong: warning() and message() signal conditions
     * and then INVOKE A RESTART to carry on, so they never unwind past C and
     * never threaten the socket. Swallowing them would turn an informational
     * message inside someone's callback into a fatal transport error. Worse,
     * testthat signals its own expectation class as a condition, so a plain
     * expect_true() inside a callback would be caught here and re-signalled
     * as an error — which is exactly how this was found.
     *
     * Errors and interrupts are the two that longjmp, and they are the two
     * this exists to intercept. */
    classes = PROTECT(Rf_allocVector(STRSXP, 2));
    SET_STRING_ELT(classes, 0, Rf_mkChar("error"));
    SET_STRING_ELT(classes, 1, Rf_mkChar("interrupt"));
    res = R_tryCatch(cb_body, &cc, classes, cb_handler, c, NULL, NULL);
    UNPROTECT(2);

    if (c->caught) {
        /* Not reported as a transport error: the caller gets the original
         * condition re-signalled once the loop has unwound (§27.3). */
        zu_error_set(err, ZU_ERR_CANCELLED, ZU_PHASE_READ,
                     "the body callback raised a condition");
        return ZU_ERR_CANCELLED;
    }
    /* §27.2: "the callback's return value controls flow: a sentinel return
     * stops the transfer cleanly", which then makes the connection
     * unpoolable (§26.3) — zu_reuse_decide() maps ZU_ERR_CANCELLED to
     * ZU_NOREUSE_CANCELLED, so that happens without a special case. */
    if (res != R_NilValue && TYPEOF(res) == LGLSXP && Rf_length(res) == 1 &&
        LOGICAL(res)[0] == FALSE) {
        c->stopped = 1;
        s->stopped = 1;
        zu_error_set(err, ZU_ERR_CANCELLED, ZU_PHASE_READ,
                     "the body callback stopped the transfer");
        return ZU_ERR_CANCELLED;
    }
    return ZU_OK;
}

/* --- §26 the connection pool, as an R object ------------------------------
 *
 * §26.5: "a zu_client is an ordinary R object holding an external pointer to
 * native pool state", and a client restored from saveRDS() must lazily
 * re-create its pool rather than erroring. Two things make that work:
 *
 *   - the pointer is TAGGED. A restored external pointer comes back with a
 *     NULL address, and R will happily hand any other package's external
 *     pointer to .Call, so "is this ours and is it alive" is one question
 *     answered in one place (pool_ptr_get).
 *   - a finalizer frees the pool when the client is collected. §26.4 requires
 *     the PID guard in every finalizer; zu_pool_free() runs it, which is why
 *     the finalizer body is just that call and not a hand-rolled teardown.
 */
static SEXP zu_pool_tag = NULL;   /* install()ed once in R_init_zuhttp */

static void pool_finalizer(SEXP ptr) {
    zu_pool *p = (zu_pool *)R_ExternalPtrAddr(ptr);
    if (!p) return;
    /* Runs the §26.4 fork guard internally: a finalizer in a forked child
     * must not gracefully close sockets the parent still owns. */
    zu_pool_free(p);
    R_ClearExternalPtr(ptr);
}

/* The pool behind `ptr`, or NULL if there is none, it is not ours, or it did
 * not survive serialization. NULL is not an error here — it is the signal the
 * R layer turns into "create one now" (§26.5). */
static zu_pool *pool_ptr_get(SEXP ptr) {
    if (TYPEOF(ptr) != EXTPTRSXP) return NULL;
    if (R_ExternalPtrTag(ptr) != zu_pool_tag) return NULL;
    return (zu_pool *)R_ExternalPtrAddr(ptr);
}

static SEXP C_zu_pool_new(SEXP max_idle, SEXP max_per_host, SEXP idle_timeout_ms) {
    zu_pool_config cfg;
    zu_pool *p;
    SEXP ptr;

    zu_pool_config_init(&cfg);
    if (Rf_asInteger(max_idle) > 0)     cfg.max_idle        = (size_t)Rf_asInteger(max_idle);
    if (Rf_asInteger(max_per_host) > 0) cfg.max_per_host    = (size_t)Rf_asInteger(max_per_host);
    if (Rf_asInteger(idle_timeout_ms) > 0)
        cfg.idle_timeout_ms = (long)Rf_asInteger(idle_timeout_ms);

    p = zu_pool_new(&cfg);
    if (!p) Rf_error("could not allocate a connection pool");

    ptr = PROTECT(R_MakeExternalPtr(p, zu_pool_tag, R_NilValue));
    R_RegisterCFinalizerEx(ptr, pool_finalizer, TRUE);
    UNPROTECT(1);
    return ptr;
}

/* Is this pointer a live pool of ours? The R layer asks before every use, and
 * a FALSE means "restored from a file, or never made" — both of which lead to
 * the same lazy re-creation (§26.5). */
static SEXP C_zu_pool_valid(SEXP ptr) {
    return Rf_ScalarLogical(pool_ptr_get(ptr) != NULL);
}

/* §26.2 counters. These exist so a test can prove a connection was REUSED
 * rather than merely that two requests both succeeded — without them, pooling
 * is indistinguishable from not pooling from R. */
static SEXP C_zu_pool_stats(SEXP ptr) {
    static const char *nm[] = {
        "idle", "hits", "misses", "discarded_stale", "discarded_expired",
        "discarded_capacity", "discarded_unusable", "discarded_fork",
        "forks_detected", NULL
    };
    zu_pool *p = pool_ptr_get(ptr);
    zu_pool_stats st;
    SEXP out, names;
    int i, n = 0;

    while (nm[n]) n++;
    if (!p) return R_NilValue;
    zu_pool_stats_get(p, &st);

    out = PROTECT(Rf_allocVector(REALSXP, n));
    REAL(out)[0] = (double)st.idle;
    REAL(out)[1] = (double)st.hits;
    REAL(out)[2] = (double)st.misses;
    REAL(out)[3] = (double)st.discarded_stale;
    REAL(out)[4] = (double)st.discarded_expired;
    REAL(out)[5] = (double)st.discarded_capacity;
    REAL(out)[6] = (double)st.discarded_unusable;
    REAL(out)[7] = (double)st.discarded_fork;
    REAL(out)[8] = (double)st.forks_detected;

    names = PROTECT(Rf_allocVector(STRSXP, n));
    for (i = 0; i < n; i++) SET_STRING_ELT(names, i, Rf_mkChar(nm[i]));
    Rf_setAttrib(out, R_NamesSymbol, names);
    UNPROTECT(2);
    return out;
}

static SEXP C_zu_pool_clear(SEXP ptr) {
    zu_pool *p = pool_ptr_get(ptr);
    if (p) zu_pool_clear(p);
    return R_NilValue;
}

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

/* build_response needs the trace as well as the result, and R_UnwindProtect
 * passes one pointer. Bundling them beats a file-scope pointer, which would
 * be wrong the moment a callback issued a nested request (§27.4 permits that
 * on a different client). */
typedef struct { zu_result *r; zu_trace *t; } resp_ctx;

static SEXP build_response(void *data);
static SEXP timings_to_r(const zu_timings *t);
static SEXP trace_to_r(const zu_trace *t);

/* Runs whether build_response returned or longjmped (§25.2 mechanism (a)).
 * `jump` is TRUE only on the unwind path; the work is identical either way,
 * so it is deliberately not branched on. */
static void free_result_on_unwind(void *data, Rboolean jump) {
    (void)jump;
    zu_result_free(((resp_ctx *)data)->r);
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
                         SEXP user_agent, SEXP decode, SEXP pool,
                         SEXP path, SEXP callback, SEXP proxy, SEXP tls,
                         SEXP trace, SEXP redact_params) {
    zu_get_opts o;
    zu_req_spec spec;
    cb_ctx cb;
    zu_sink cb_sink;
    zu_tls_config tlscfg;
    zu_trace tracebuf;
    zu_redact_policy redact;
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
    /* §26. NULL, a foreign pointer, or one that did not survive saveRDS() all
     * mean "no pool for this request" — the engine then opens and closes its
     * own connection, which is correct rather than merely tolerable. The R
     * layer re-creates the pool before the next call (§26.5). */
    o.pool = pool_ptr_get(pool);

    /* §20.1 three states, and they are genuinely three. NULL means "consult
     * the environment"; a string overrides it; FALSE disables proxying
     * outright, which is not the same thing as being unconfigured — a caller
     * who asked for a direct connection must not get whatever http_proxy
     * happens to say. */
    if (Rf_isString(proxy) && Rf_length(proxy) == 1 && STRING_ELT(proxy, 0) != NA_STRING) {
        o.proxy     = Rf_translateCharUTF8(STRING_ELT(proxy, 0));
        o.proxy_set = 1;
    } else if (Rf_isLogical(proxy) && Rf_length(proxy) == 1 &&
               LOGICAL(proxy)[0] == FALSE) {
        o.proxy     = NULL;
        o.proxy_set = 1;
    }

    /* §27.1: a download goes to a temporary file beside the destination and
     * is renamed only once the body has arrived whole, so an interrupted or
     * failed transfer never leaves a truncated file at the target path. The
     * engine deliberately does not own this sink — committing or discarding
     * depends on the outcome, and only this frame sees it. */
    /* §14. Built here rather than in R so there is one definition of what a
     * TLS configuration is; the R layer validates paths, where the error can
     * name which of ca_file and ca_extra was wrong. */
    if (tls != R_NilValue && Rf_isVectorList(tls)) {
        SEXP names = Rf_getAttrib(tls, R_NamesSymbol);
        R_xlen_t i, n = Rf_xlength(tls);
        zu_tls_config_init(&tlscfg);
        for (i = 0; i < n; i++) {
            const char *nm = (names == R_NilValue) ? ""
                             : Rf_translateCharUTF8(STRING_ELT(names, i));
            SEXP v = VECTOR_ELT(tls, i);
            if (v == R_NilValue) continue;
            if (strcmp(nm, "ca_file") == 0 && Rf_isString(v) && Rf_length(v) == 1) {
                tlscfg.ca_file = Rf_translateCharUTF8(STRING_ELT(v, 0));
                tlscfg.source  = ZU_TRUST_FILE;   /* §14.2: REPLACES */
            } else if (strcmp(nm, "ca_extra") == 0 && Rf_isString(v) && Rf_length(v) == 1) {
                /* §14.2: ADDS. Deliberately does NOT touch `source`, which is
                 * the whole difference between the two arguments. */
                tlscfg.ca_extra_file = Rf_translateCharUTF8(STRING_ELT(v, 0));
            } else if (strcmp(nm, "pins") == 0 && Rf_isString(v) && Rf_length(v) > 0) {
                R_xlen_t j, np = Rf_xlength(v);
                const char **pins = (const char **)R_alloc((size_t)np, sizeof(char *));
                for (j = 0; j < np; j++)
                    pins[j] = Rf_translateCharUTF8(STRING_ELT(v, j));
                tlscfg.pins   = pins;
                tlscfg.n_pins = (size_t)np;
            } else if (strcmp(nm, "revocation") == 0) {
                tlscfg.revocation = (Rf_asLogical(v) == TRUE);
            } else if (strcmp(nm, "min_version") == 0) {
                int mv = Rf_asInteger(v);
                if (mv == 12 || mv == 13) tlscfg.min_version = mv;
            }
        }
        o.tls = &tlscfg;
        /* One place names a replacement CA (§26.1's key reads it from here). */
        if (tlscfg.ca_file) o.ca_file = tlscfg.ca_file;
    }

    /* §42. The engine redacts the URLs it traces, so the caller's extra
     * parameter names have to reach it. Set unconditionally rather than only
     * when tracing: a policy that depends on another option is one an added
     * egress can silently miss. The R_alloc storage behind the lists lives
     * until this .Call returns, which outlasts the engine call. */
    policy_from(R_NilValue, redact_params, &redact);
    o.redact = &redact;

    /* §35: opt-in. Without this the trace pointer stays NULL and every
     * zu_trace_add() in the connect, handshake and read paths is one branch. */
    if (Rf_asLogical(trace) == TRUE) {
        zu_trace_init(&tracebuf);
        o.trace = &tracebuf;
    }

    memset(&cb, 0, sizeof cb);
    if (Rf_isFunction(callback)) {
        memset(&cb_sink, 0, sizeof cb_sink);
        cb.fn         = callback;
        cb_sink.write = cb_write;
        cb_sink.ctx   = &cb;
        o.sink        = &cb_sink;
    } else if (Rf_isString(path) && Rf_length(path) == 1 &&
               STRING_ELT(path, 0) != NA_STRING) {
        const char *dest = Rf_translateCharUTF8(STRING_ELT(path, 0));
        o.sink = zu_sink_file(dest, &e);
        if (!o.sink) { raise_zu_error(&e, u); return R_NilValue; }
    }

    /* §25.1: a checkpoint at most one tick apart, and never inside a blocking
     * call. 100 ms is the design's ceiling. */
    o.tick     = r_interrupt_tick;
    o.tick_ctx = NULL;

    zu_error_clear(&e);
    rc = zu_engine_perform(&r, u, &spec, &o, &e);

    /* §27.3: the loop has unwound and every C resource it held is released,
     * so this is the first point at which raising is safe. Re-signal the
     * USER's condition — wrapping it here would turn "object 'x' not found"
     * inside their callback into a mysterious transport failure. */
    if (cb.caught) {
        SEXP cond = cb.caught;
        SEXP call;
        cb.caught = NULL;
        zu_result_free(&r);
        PROTECT(cond);
        R_ReleaseObject(cond);
        call = PROTECT(Rf_lang2(Rf_install("stop"), cond));
        Rf_eval(call, R_GlobalEnv);
        UNPROTECT(2);
        return R_NilValue;   /* not reached */
    }
    if (o.sink && o.sink != &cb_sink) {
        /* Commit or discard, then release. A failure to rename is a failure
         * of the request: the caller asked for a file at that path and there
         * is not one, so reporting success would be a lie. */
        if (rc == ZU_OK) rc = zu_sink_finish(o.sink, &e);
        else             zu_sink_abort(o.sink);
        if (rc != ZU_OK) zu_sink_abort(o.sink);
        r.body.len = 0;              /* the bytes went to the file, not here */
        zu_sink_free(o.sink);
        o.sink = NULL;
    }
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
    {
        resp_ctx ctx;
        ctx.r = &r;
        ctx.t = o.trace;
        return R_UnwindProtect(build_response, &ctx, free_result_on_unwind, &ctx, NULL);
    }
}

/* Everything below runs with `r` still owning C memory, and every R allocation
 * here can longjmp on failure. R_UnwindProtect guarantees free_result_on_unwind
 * runs either way — §25.2's mechanism (a), used to release promptly rather
 * than at the next GC. */
static SEXP build_response(void *data) {
    resp_ctx  *ctx = (resp_ctx *)data;
    zu_result *rp = ctx->r;
    zu_result r = *rp;
    SEXP out, nms, body;

    body = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t)r.body.len));
    if (r.body.len) memcpy(RAW(body), r.body.data, r.body.len);

    /* §35.2's connection metadata rides on the response rather than being a
     * second call, because it describes the connection THIS response came
     * over — asking again later would answer about a different one. */
    out = PROTECT(Rf_allocVector(VECSXP, 14));
    nms = PROTECT(Rf_allocVector(STRSXP, 14));
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
    SET_VECTOR_ELT(out, 6, r.tls_cipher ? Rf_mkString(r.tls_cipher) : R_NilValue);
    SET_STRING_ELT(nms, 6, Rf_mkChar("tls_cipher"));
    SET_VECTOR_ELT(out, 7, r.remote_ip ? Rf_mkString(r.remote_ip) : R_NilValue);
    SET_STRING_ELT(nms, 7, Rf_mkChar("remote_ip"));
    SET_VECTOR_ELT(out, 8, r.trust_backend ? Rf_mkString(r.trust_backend) : R_NilValue);
    SET_STRING_ELT(nms, 8, Rf_mkChar("trust_backend"));
    SET_VECTOR_ELT(out, 9, Rf_ScalarLogical(r.reused_connection));
    SET_STRING_ELT(nms, 9, Rf_mkChar("reused_connection"));
    SET_VECTOR_ELT(out, 10, Rf_ScalarLogical(r.proxy_used));
    SET_STRING_ELT(nms, 10, Rf_mkChar("proxy_used"));
    SET_VECTOR_ELT(out, 11, Rf_ScalarInteger(r.http_version));
    SET_STRING_ELT(nms, 11, Rf_mkChar("http_minor"));
    SET_VECTOR_ELT(out, 12, timings_to_r(&r.timings));
    SET_STRING_ELT(nms, 12, Rf_mkChar("timings_ms"));
    SET_VECTOR_ELT(out, 13, trace_to_r(ctx->t));
    SET_STRING_ELT(nms, 13, Rf_mkChar("trace"));
    Rf_setAttrib(out, R_NamesSymbol, nms);

    UNPROTECT(3);
    return out;
}

/* --- §35.1 timings and §35.3 events, as R objects -------------------------
 *
 * -1 becomes NA rather than -1. A phase that did not happen is unknown, not
 * negative, and NA is the value every R idiom already handles correctly —
 * mean(), plotting, comparison. Handing back -1 would put a guard in every
 * caller and eventually produce a chart with a bar below the axis.
 */
static SEXP timings_to_r(const zu_timings *t) {
    static const char *nm[] = {
        "dns", "connect", "tls", "request_write", "ttfb", "response_read",
        "total", "body_bytes_wire", "body_bytes_decoded", NULL
    };
    const long v[7] = { t->dns, t->connect, t->tls, t->request_write,
                        t->ttfb, t->response_read, t->total };
    SEXP out, names;
    int i, n = 0;
    while (nm[n]) n++;

    out   = PROTECT(Rf_allocVector(REALSXP, n));
    names = PROTECT(Rf_allocVector(STRSXP, n));
    for (i = 0; i < 7; i++)
        REAL(out)[i] = (v[i] < 0) ? NA_REAL : (double)v[i];
    REAL(out)[7] = (double)t->body_bytes_wire;
    REAL(out)[8] = (double)t->body_bytes_decoded;
    for (i = 0; i < n; i++) SET_STRING_ELT(names, i, Rf_mkChar(nm[i]));
    Rf_setAttrib(out, R_NamesSymbol, names);
    UNPROTECT(2);
    return out;
}

/* A data-frame-shaped list: event, at_ms, bytes, detail. Columns rather than
 * a list of rows, because the first thing anyone does with a trace is look at
 * it as a table. */
static SEXP trace_to_r(const zu_trace *t) {
    SEXP out, names, ev, at, n_, detail;
    size_t i;
    if (!t) return R_NilValue;

    ev     = PROTECT(Rf_allocVector(STRSXP,  (R_xlen_t)t->n));
    at     = PROTECT(Rf_allocVector(REALSXP, (R_xlen_t)t->n));
    n_     = PROTECT(Rf_allocVector(REALSXP, (R_xlen_t)t->n));
    detail = PROTECT(Rf_allocVector(STRSXP,  (R_xlen_t)t->n));
    for (i = 0; i < t->n; i++) {
        SET_STRING_ELT(ev, (R_xlen_t)i, Rf_mkChar(zu_event_name(t->ev[i].ev)));
        REAL(at)[i] = (double)t->ev[i].at_ms;
        REAL(n_)[i] = (double)t->ev[i].n;
        SET_STRING_ELT(detail, (R_xlen_t)i, Rf_mkChar(t->ev[i].detail));
    }
    out   = PROTECT(Rf_allocVector(VECSXP, 5));
    names = PROTECT(Rf_allocVector(STRSXP, 5));
    SET_VECTOR_ELT(out, 0, ev);     SET_STRING_ELT(names, 0, Rf_mkChar("event"));
    SET_VECTOR_ELT(out, 1, at);     SET_STRING_ELT(names, 1, Rf_mkChar("at_ms"));
    SET_VECTOR_ELT(out, 2, n_);     SET_STRING_ELT(names, 2, Rf_mkChar("n"));
    SET_VECTOR_ELT(out, 3, detail); SET_STRING_ELT(names, 3, Rf_mkChar("detail"));
    /* Reported, not hidden: a truncated trace that looked complete would read
     * as a request that stopped early. */
    SET_VECTOR_ELT(out, 4, Rf_ScalarInteger(t->dropped));
    SET_STRING_ELT(names, 4, Rf_mkChar("dropped"));
    Rf_setAttrib(out, R_NamesSymbol, names);
    UNPROTECT(6);
    return out;
}

/* --- §39 build information -----------------------------------------------
 *
 * §14.5 is the reason this is not a nicety: "whatever the three platforms do,
 * zu_info() must report the effective revocation policy, because this is
 * exactly the kind of silent asymmetry that produces 'it works on my machine'
 * bug reports." The same goes for which store decided to trust a certificate
 * — §13.1 splits the TLS engine from the trust evaluator precisely because
 * they can differ, and "which store" is a question users genuinely ask.
 *
 * Reported from C rather than assembled in R, so it describes the build that
 * is actually loaded rather than what the R layer believes was configured.
 */
static SEXP C_zu_build_info(void) {
    static const char *nm[] = {
        "tls_backend", "trust", "tls_available", "revocation_default",
        "compression", "ipv6", "http", NULL
    };
    const char *backend = zu_tls_backend_name();
    const char *trust;
    SEXP out, names;
    int i, n = 0;

    while (nm[n]) n++;

    /* §13.1: the engine and the store are different questions, and on macOS
     * they are answered by different frameworks. */
    if (strcmp(backend, "securetransport") == 0)   trust = "macOS Keychain (SecTrust)";
    else if (strcmp(backend, "schannel") == 0)     trust = "Windows Certificate Store";
    else if (strcmp(backend, "openssl") == 0)      trust = "OpenSSL system defaults";
    else                                           trust = "none";

    out   = PROTECT(Rf_allocVector(VECSXP, n));
    names = PROTECT(Rf_allocVector(STRSXP, n));

    SET_VECTOR_ELT(out, 0, Rf_mkString(backend));
    SET_VECTOR_ELT(out, 1, Rf_mkString(trust));
    SET_VECTOR_ELT(out, 2, Rf_ScalarLogical(zu_tls_available()));
    /* §14.5 / D-31: off by default on every platform, measured in S0 (F-4). */
    SET_VECTOR_ELT(out, 3, Rf_ScalarLogical(FALSE));
    SET_VECTOR_ELT(out, 4, Rf_mkString("gzip, deflate"));
    /* §3.1: getaddrinfo is called with AF_UNSPEC, so both families are tried
     * in whatever order the resolver returns. Whether a route exists is a
     * property of the machine, not of this build — reporting "yes" here means
     * "not disabled", which is the honest claim. */
    SET_VECTOR_ELT(out, 5, Rf_ScalarLogical(TRUE));
    SET_VECTOR_ELT(out, 6, Rf_mkString("HTTP/1.1"));

    for (i = 0; i < n; i++) SET_STRING_ELT(names, i, Rf_mkChar(nm[i]));
    Rf_setAttrib(out, R_NamesSymbol, names);
    UNPROTECT(2);
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
    {"C_zu_perform",           (DL_FUNC) &C_zu_perform,          18},
    {"C_zu_pool_new",          (DL_FUNC) &C_zu_pool_new,          3},
    {"C_zu_pool_valid",        (DL_FUNC) &C_zu_pool_valid,        1},
    {"C_zu_pool_stats",        (DL_FUNC) &C_zu_pool_stats,        1},
    {"C_zu_pool_clear",        (DL_FUNC) &C_zu_pool_clear,        1},
    {"C_zu_tls_backend",       (DL_FUNC) &C_zu_tls_backend,       0},
    {"C_zu_build_info",        (DL_FUNC) &C_zu_build_info,        0},
    {NULL, NULL, 0}
};

void attribute_visible R_init_zuhttp(DllInfo *dll) {
    /* Interned once. Pointer identity against this symbol is what tells our
     * external pointers from another package's (§26.5). */
    zu_pool_tag = Rf_install("zu_pool");
    R_registerRoutines(dll, NULL, call_methods, NULL, NULL);
    R_useDynamicSymbols(dll, FALSE);
    R_forceSymbols(dll, TRUE);
}

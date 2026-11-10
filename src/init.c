/* zuhttp — R entry points.
 *
 * Design §11: this is the ONLY file permitted to include R headers. Every
 * other translation unit under src/ is plain C, which is what allows the core
 * to link into ctest/ and a fuzz harness with no R runtime present. If you
 * find yourself adding <R.h> to another file, the layering is wrong.
 *
 * S12 registers the first routines: the §34.1 condition hierarchy and the
 * §42 redaction policy. Both are deliberately C-side rather than
 * reimplemented in R, so there is one definition of each (see zuh_error.c and
 * zuh_redact.c for why).
 */
#include <R.h>
#include <Rinternals.h>
#include <R_ext/Rdynload.h>
#include <R_ext/Visibility.h>


#include "zuh_error.h"
#include "zuh_redact.h"
#include "zuh_buffer.h"
#include "zuh_alloc.h"
#include "zuh_engine.h"
#include "zuh_headers.h"
#include "zuh_tls.h"
#include "zuh_pool.h"
#include "zuh_sink.h"
#include "zuh_trace.h"
#include <setjmp.h>
#include <string.h>

/* Defined below; the pool constructor raises through it too. */
static void raise_zu_error(const zuh_error *e, const char *url);

/* Anything a caller could make arbitrarily large is bounded here rather than
 * in the R layer, so the bound cannot be bypassed by a different caller. */
#define ZUH_R_TEXT_MAX (1u << 20)

/* --- §27 the R callback sink ----------------------------------------------
 *
 * §27.3 is the whole difficulty. A user callback runs inside the C read loop
 * (and a §65.7 request body function inside nghttp2's data provider), and R
 * leaves a function non-locally with a longjmp: an error, an interrupt, an
 * exiting handler for a warning or message that the caller established
 * around the zuhttp call, a restart, return() from a closure. Any of them
 * would jump past the socket, the TLS context, the inflate stream and the
 * nghttp2 session, all C allocations with no R finalizer.
 *
 *   1. The call is made under R_UnwindProtect, whose cleanup longjmps back to
 *      the C frame that made it (guard_eval), so the jump stops there. Every
 *      kind of jump is caught, and none is caught early: a warning() that
 *      returns, or a calling handler, runs exactly as it would without us.
 *   2. The native loop then unwinds NORMALLY, so every C resource is
 *      released.
 *   3. Only then does the .Call resume the jump with R_ContinueUnwind(), so
 *      the user sees what R would have done with no zuhttp in between: their
 *      error, unwrapped, at their handler.
 *
 * An earlier version caught only "error" and "interrupt" with R_tryCatch and
 * re-signalled the condition; a warning under tryCatch(warning = ) longjmped
 * straight through nghttp2 (review #141). R documents the longjmp from the
 * cleanup, provided R_ContinueUnwind() follows.
 *
 * The continuation token is made before the engine runs, never inside it:
 * an allocation failure there would itself be a longjmp through C. Its
 * owner keeps it protected until R_ContinueUnwind(). */
/* On Windows, R jumps with GCC's __builtin_setjmp/__builtin_longjmp, and
 * the UCRT longjmp() unwinds with SEH through frames that R left that way,
 * which killed the R process on both Windows CI legs (#172). The builtins
 * restore registers and nothing else, as R's own jumps do, so they are what
 * this jump uses there. Elsewhere the C library's pair is the documented
 * one; the builtins' buffer is five words and their value is always 1. */
#if defined(_WIN32) && defined(__GNUC__)
typedef void *guard_jmpbuf[5];
#  define GUARD_SETJMP(b)  __builtin_setjmp(b)
#  define GUARD_LONGJMP(b) __builtin_longjmp(b, 1)
#else
typedef jmp_buf guard_jmpbuf;
#  define GUARD_SETJMP(b)  setjmp(b)
#  define GUARD_LONGJMP(b) longjmp(b, 1)
#endif

typedef struct {
    SEXP         token;   /* R_MakeUnwindCont(), protected by the owner */
    int          jumped;  /* a non-local exit was stopped; token carries it */
    int          resumed; /* the jump went on: the token is spent (#175) */
    guard_jmpbuf jb;
} r_guard;

static void guard_cleanup(void *data, Rboolean jump) {
    if (jump) GUARD_LONGJMP(((r_guard *)data)->jb);
}

/* fn(data); NULL with g->jumped set when it left non-locally. Once a jump
 * has been stopped, nothing more is evaluated: the token holds that jump. */
static SEXP guard_eval(r_guard *g, SEXP (*fn)(void *), void *data) {
    if (g->jumped) return NULL;
    if (GUARD_SETJMP(g->jb)) { g->jumped = 1; return NULL; }
    return R_UnwindProtect(fn, data, guard_cleanup, g, g->token);
}

static SEXP interrupt_body(void *ignored) {
    (void)ignored;
    R_CheckUserInterrupt();
    return R_NilValue;
}

typedef struct {
    SEXP    fn;
    r_guard g;
    int     stopped;   /* the callback asked to stop (§27.2 sentinel) */
} cb_ctx;

typedef struct { cb_ctx *c; const unsigned char *d; size_t n; } cb_call;

/* --- §65.7 a request body from an R function -----------------------------
 *
 * The engine calls next() while it sends, which over HTTP/2 is from inside
 * nghttp2's data provider, so f is called through guard_eval as the body
 * callback is. The engine owns the source and calls release() once. While
 * C_zu_perform is on the stack, it frees the context and resumes a stopped
 * jump; when a pulled body inherited the source (`detached`, full duplex over
 * HTTP/2), C_zu_stream_read resumes it and release() frees all of it.
 *
 * `keep` is list(f, token), preserved once: one R_PreserveObject() that
 * either happens or longjmps before any C state exists (review #142). */
typedef struct {
    SEXP       keep;        /* preserved list(fn, token) */
    r_guard    g;
    zuh_buffer piece;       /* the last piece, valid until the next call */
    int        released, detached;
} src_ctx;

static SEXP src_body(void *data) {
    SEXP call = PROTECT(Rf_lang1(VECTOR_ELT(((src_ctx *)data)->keep, 0)));
    SEXP res = Rf_eval(call, R_GlobalEnv);
    UNPROTECT(1);
    return res;
}

static zuh_code src_next(void *ctx, const void **data, size_t *len, zuh_deadline dl,
                         zuh_error *err) {
    src_ctx *c = (src_ctx *)ctx;
    for (;;) {
        SEXP res = guard_eval(&c->g, src_body, c);
        if (c->g.jumped) {
            zuh_error_set(err, ZUH_ERR_CANCELLED, ZUH_PHASE_WRITE,
                          "the request body function did not return");
            return ZUH_ERR_CANCELLED;
        }
        if (res == R_NilValue) { *len = 0; return ZUH_OK; }
        if (TYPEOF(res) != RAWSXP) {
            zuh_error_set(err, ZUH_ERR_PARSE, ZUH_PHASE_WRITE,
                          "the request body function must return a raw vector, or NULL at the end");
            return ZUH_ERR_PARSE;
        }
        if (XLENGTH(res) > 0) {
            c->piece.len = 0;
            if (!zuh_buf_append(&c->piece, RAW(res), (size_t)XLENGTH(res))) {
                zuh_error_set(err, ZUH_ERR_NOMEM, ZUH_PHASE_WRITE, "out of memory");
                return ZUH_ERR_NOMEM;
            }
            *data = c->piece.data;
            *len = c->piece.len;
            return ZUH_OK;
        }
        /* An empty raw vector is a piece of nothing, not the end: ask again,
         * in a loop rather than by recursion, which grew the C stack once per
         * empty piece (review #157). A function that only ever returns raw()
         * is still interruptible, and still bound by the timeout: an empty
         * piece writes nothing, so no write can notice the deadline (#217). */
        if (zuh_deadline_expired(dl)) {
            zuh_error_set(err, ZUH_ERR_TIMEOUT, ZUH_PHASE_WRITE,
                          "request timed out: the request body function returned "
                          "only empty pieces");
            return ZUH_ERR_TIMEOUT;
        }
        (void)guard_eval(&c->g, interrupt_body, NULL);
    }
}

static void src_release(void *ctx) {
    src_ctx *c = (src_ctx *)ctx;
    if (c->released) return;
    c->released = 1;
    zuh_buf_free(&c->piece);
    if (c->detached) {
        R_ReleaseObject(c->keep);
        zuh_free(c);
    }
    /* Not detached: C_zu_perform is still on the stack, holds `keep`
     * protected, and frees the context once it has read g.jumped. */
}

static SEXP cb_body(void *data) {
    cb_call *cc = (cb_call *)data;
    SEXP chunk = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t)cc->n));
    SEXP call;
    SEXP res;
    if (cc->n) memcpy(RAW(chunk), cc->d, cc->n);
    call = PROTECT(Rf_lang2(cc->c->fn, chunk));
    res  = Rf_eval(call, R_GlobalEnv);
    UNPROTECT(2);
    return res;
}

static zuh_code cb_write(zuh_sink *s, const unsigned char *d, size_t n,
                        zuh_error *err) {
    cb_ctx *c = (cb_ctx *)s->ctx;
    cb_call cc;
    SEXP res;

    if (c->g.jumped || c->stopped) return ZUH_ERR_CANCELLED;

    /* The chunk is allocated inside the protected call too: an allocation
     * failure is a longjmp like any other. */
    cc.c = c; cc.d = d; cc.n = n;
    res = guard_eval(&c->g, cb_body, &cc);
    if (c->g.jumped) {
        /* Not reported as a transport error: the caller's jump is resumed
         * once the loop has unwound (§27.3). */
        zuh_error_set(err, ZUH_ERR_CANCELLED, ZUH_PHASE_READ,
                     "the body callback did not return");
        return ZUH_ERR_CANCELLED;
    }
    /* §27.2: "the callback's return value controls flow: a sentinel return
     * stops the transfer cleanly", which then makes the connection
     * unpoolable (§26.3) — zuh_reuse_decide() maps ZUH_ERR_CANCELLED to
     * ZUH_NOREUSE_CANCELLED, so that happens without a special case. */
    if (res != R_NilValue && TYPEOF(res) == LGLSXP && Rf_length(res) == 1 &&
        LOGICAL(res)[0] == FALSE) {
        c->stopped = 1;
        s->stopped = 1;
        zuh_error_set(err, ZUH_ERR_CANCELLED, ZUH_PHASE_READ,
                     "the body callback stopped the transfer");
        return ZUH_ERR_CANCELLED;
    }
    return ZUH_OK;
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
 *     the PID guard in every finalizer; zuh_pool_free() runs it, which is why
 *     the finalizer body is just that call and not a hand-rolled teardown.
 */
static SEXP zuh_pool_tag = NULL;   /* install()ed once in R_init_zuhttp */

static void pool_finalizer(SEXP ptr) {
    zuh_pool *p = (zuh_pool *)R_ExternalPtrAddr(ptr);
    if (!p) return;
    /* Runs the §26.4 fork guard internally: a finalizer in a forked child
     * must not gracefully close sockets the parent still owns. */
    zuh_pool_free(p);
    R_ClearExternalPtr(ptr);
}

/* The pool behind `ptr`, or NULL if there is none, it is not ours, or it did
 * not survive serialization. NULL is not an error here — it is the signal the
 * R layer turns into "create one now" (§26.5). */
static zuh_pool *pool_ptr_get(SEXP ptr) {
    if (TYPEOF(ptr) != EXTPTRSXP) return NULL;
    if (R_ExternalPtrTag(ptr) != zuh_pool_tag) return NULL;
    return (zuh_pool *)R_ExternalPtrAddr(ptr);
}

static SEXP C_zu_pool_new(SEXP max_idle, SEXP max_per_host, SEXP idle_timeout_ms,
                          SEXP keepalive_time_ms, SEXP keepalive_timeout_ms) {
    zuh_pool_config cfg;
    zuh_pool *p;
    SEXP ptr;

    zuh_pool_config_init(&cfg);
    if (Rf_asInteger(max_idle) > 0)     cfg.max_idle        = (size_t)Rf_asInteger(max_idle);
    if (Rf_asInteger(max_per_host) > 0) cfg.max_per_host    = (size_t)Rf_asInteger(max_per_host);
    if (Rf_asInteger(idle_timeout_ms) > 0)
        cfg.idle_timeout_ms = (long)Rf_asInteger(idle_timeout_ms);
    /* §65.6: 0, the R layer's NULL, leaves keepalive off. */
    if (Rf_asInteger(keepalive_time_ms) > 0)
        cfg.keepalive_time_ms = (long)Rf_asInteger(keepalive_time_ms);
    if (Rf_asInteger(keepalive_timeout_ms) > 0)
        cfg.keepalive_timeout_ms = (long)Rf_asInteger(keepalive_timeout_ms);

    p = zuh_pool_new(&cfg);
    if (!p) {
        /* zu_memory_error, as every other allocation failure is (§34.1). A
         * bare Rf_error() here was the one unclassed out-of-memory error the
         * allocation-failure sweep found (#282). */
        zuh_error e;
        zuh_error_clear(&e);
        zuh_error_set(&e, ZUH_ERR_NOMEM, ZUH_PHASE_NONE, "could not allocate a connection pool");
        raise_zu_error(&e, NULL);
    }

    ptr = PROTECT(R_MakeExternalPtr(p, zuh_pool_tag, R_NilValue));
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
/* The configuration in C, for the tests: a setting R validated but
 * C_zu_pool_new() dropped or garbled would otherwise pass every test, as the
 * uninitialised keepalive fields of W21 did until valgrind (review #152). */
static SEXP C_zu_pool_config(SEXP ptr) {
    static const char *nm[] = {
        "max_idle", "max_per_host", "idle_timeout_ms", "keepalive_time_ms",
        "keepalive_timeout_ms", NULL
    };
    zuh_pool *p = pool_ptr_get(ptr);
    zuh_pool_config c;
    SEXP out, names;
    int i, n = 0;
    while (nm[n]) n++;
    if (!p) return R_NilValue;
    zuh_pool_config_get(p, &c);
    out = PROTECT(Rf_allocVector(REALSXP, n));
    REAL(out)[0] = (double)c.max_idle;
    REAL(out)[1] = (double)c.max_per_host;
    REAL(out)[2] = (double)c.idle_timeout_ms;
    REAL(out)[3] = (double)c.keepalive_time_ms;
    REAL(out)[4] = (double)c.keepalive_timeout_ms;
    names = PROTECT(Rf_allocVector(STRSXP, n));
    for (i = 0; i < n; i++) SET_STRING_ELT(names, i, Rf_mkChar(nm[i]));
    Rf_setAttrib(out, R_NamesSymbol, names);
    UNPROTECT(2);
    return out;
}

static SEXP C_zu_pool_stats(SEXP ptr) {
    static const char *nm[] = {
        "idle", "hits", "misses", "discarded_stale", "discarded_expired",
        "discarded_capacity", "discarded_unusable", "discarded_fork",
        "forks_detected", NULL
    };
    zuh_pool *p = pool_ptr_get(ptr);
    zuh_pool_stats st;
    SEXP out, names;
    int i, n = 0;

    while (nm[n]) n++;
    if (!p) return R_NilValue;
    zuh_pool_stats_get(p, &st);

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
    zuh_pool *p = pool_ptr_get(ptr);
    if (p) zuh_pool_clear(p);
    return R_NilValue;
}

/* --- §34.1 conditions ----------------------------------------------------- */

/* The class chain for one code, most specific first, with "error" and
 * "condition" appended — those two are R's names, so R is where they belong. */
static SEXP C_zu_condition_classes(SEXP code_sexp) {
    const char *chain[ZUH_CLASS_CHAIN_MAX];
    int n, i;
    SEXP out;

    if (!Rf_isInteger(code_sexp) || Rf_length(code_sexp) != 1)
        Rf_error("code must be a single integer");

    n = zuh_code_class_chain((zuh_code)INTEGER(code_sexp)[0], chain, ZUH_CLASS_CHAIN_MAX);
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
 * stable zuh_code. Lets the R layer build its constants from the C enum rather
 * than restating it. */
static SEXP C_zu_error_codes(void) {
    int i, n = (int)ZUH_CODE_PUBLIC_COUNT;   /* §34.1 classes only */
    SEXP out = PROTECT(Rf_allocVector(INTSXP, n));
    SEXP nms = PROTECT(Rf_allocVector(STRSXP, n));
    for (i = 0; i < n; i++) {
        INTEGER(out)[i] = i;
        SET_STRING_ELT(nms, i, Rf_mkChar(zuh_code_class((zuh_code)i)));
    }
    Rf_setAttrib(out, R_NamesSymbol, nms);
    UNPROTECT(2);
    return out;
}

static SEXP C_zu_code_retryable(SEXP code_sexp) {
    if (!Rf_isInteger(code_sexp) || Rf_length(code_sexp) != 1)
        Rf_error("code must be a single integer");
    return Rf_ScalarLogical(zuh_code_retryable((zuh_code)INTEGER(code_sexp)[0]));
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

static void policy_from(SEXP extra_headers, SEXP extra_params, zuh_redact_policy *p) {
    int nh = 0, np = 0;
    zuh_redact_policy_init(p);
    p->extra_headers = str_list(extra_headers, &nh);
    p->extra_params  = str_list(extra_params,  &np);
}

/* One scalar string in, one scalar string out, through a zuh_buffer. */
static SEXP redact_one(SEXP text, SEXP extra_headers, SEXP extra_params,
                       int (*fn)(const zuh_redact_policy *, const char *, size_t,
                                 zuh_buffer *)) {
    zuh_redact_policy p;
    zuh_buffer b;
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
    /* A text the bound refuses, or one whose redaction outgrows the output
     * bound, is shown as the marker and never raised over: this runs inside
     * condition construction, printing, hooks and cassettes, where an error
     * would replace the diagnostic the caller was about to see (review
     * #180), as zuh_trace_add_url() already does. */
    if (n > ZUH_R_TEXT_MAX) return Rf_mkString(ZUH_REDACTED);

    policy_from(extra_headers, extra_params, &p);
    if (!zuh_buf_init(&b, n + 32, ZUH_R_TEXT_MAX * 2)) Rf_error("out of memory");
    if (!fn(&p, s, n, &b)) { zuh_buf_free(&b); return Rf_mkString(ZUH_REDACTED); }

    out = PROTECT(Rf_allocVector(STRSXP, 1));
    SET_STRING_ELT(out, 0, Rf_mkCharLenCE((const char *)b.data, (int)b.len, CE_UTF8));
    zuh_buf_free(&b);
    UNPROTECT(1);
    return out;
}

static SEXP C_zu_redact_url(SEXP url, SEXP extra_params) {
    return redact_one(url, R_NilValue, extra_params, zuh_redact_url);
}

static SEXP C_zu_redact_form(SEXP body, SEXP extra_params) {
    return redact_one(body, R_NilValue, extra_params, zuh_redact_form_body);
}

/* Vectorised: which of these header names carry a secret value? */
static SEXP C_zu_is_secret_header(SEXP names, SEXP extra_headers) {
    zuh_redact_policy p;
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
            LOGICAL(out)[i] = zuh_redact_is_secret_header(&p, s, strlen(s));
        }
    }
    UNPROTECT(1);
    return out;
}

static SEXP C_zu_is_secret_param(SEXP names, SEXP extra_params) {
    zuh_redact_policy p;
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
            LOGICAL(out)[i] = zuh_redact_is_secret_param(&p, s, strlen(s));
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
 * zuh_net.c gives up, and the engine unwinds through its OWN error paths,
 * closing the socket and freeing every buffer on the way out.
 *
 * That is §25.2's discipline (b) — no native allocation lives only in a C
 * local across a checkpoint — enforced by never letting a longjmp cross one. */
/*
 * R_tryCatch, not R_ToplevelExec (2026-09-26). The checkpoint can raise more
 * than a user interrupt: setTimeLimit() and R.utils::withTimeout() raise
 * "reached elapsed time limit" from inside R_CheckUserInterrupt(). Under
 * R_ToplevelExec that error was printed to the console and then discarded,
 * and the request reported "interrupted by the user" — so a withTimeout()
 * around a zuhttp call never saw the error it was waiting for. Catching the
 * condition keeps it, and C_zu_perform re-raises it unchanged once the engine
 * has unwound; only a real interrupt becomes zu_interrupted_error. */
typedef struct { SEXP caught; } tick_ctx;
static SEXP g_tick_classes = NULL;   /* c("interrupt", "error"), preserved */

/* The tick of the request running now. Not the stream's tick_ctx: a pooled
 * connection keeps the zuh_net_opts of the request that OPENED it, so a
 * context stored there points into a .Call frame that has already returned
 * the next time the connection is used — a dangling stack pointer read on
 * every poll tick of a reused connection (found 2026-09-26). C_zu_perform
 * sets this on entry and restores the previous value before it returns or
 * raises, which also keeps a nested request from a callback (§27.4) right. */
static tick_ctx *g_tick_current = NULL;

static SEXP tick_body(void *ignored) {
    (void)ignored;
    R_CheckUserInterrupt();
    return R_NilValue;
}

static SEXP tick_handler(SEXP cond, void *data) {
    tick_ctx *t = (tick_ctx *)data;
    if (!t->caught) { R_PreserveObject(cond); t->caught = cond; }
    return R_NilValue;
}

static void tick_release(tick_ctx *t);

static int r_interrupt_tick(void *ctx) {
    tick_ctx local = { NULL };
    tick_ctx *t = g_tick_current ? g_tick_current : &local;
    int hit;
    (void)ctx;   /* deliberately unused: see g_tick_current */
#if defined(_WIN32)
    /* §25.4: in Rgui and RStudio the interrupt is delivered through the event
     * loop, so it is never observed unless the loop is pumped. */
    R_ProcessEvents();
#endif
    if (t->caught) return 1;
    R_tryCatch(tick_body, NULL, g_tick_classes, tick_handler, t, NULL, NULL);
    hit = t->caught != NULL;
    if (t == &local) tick_release(t);   /* nobody to hand it to */
    return hit;
}

/* Drop a condition the tick kept but will not re-raise. */
static void tick_release(tick_ctx *t) {
    if (t->caught) { R_ReleaseObject(t->caught); t->caught = NULL; }
}

/* The one place a stopped jump goes on (review #176). Every C resource the
 * call held is released first, then the token is marked spent, because a
 * continuation can be resumed once: its target context is gone the moment
 * it has been. A pulled body keeps its source, and with it the guard, until
 * it is freed, so a second zu_resp_read() after the body function raised
 * used to resume the same token again (review #175); it now sees `resumed`
 * and reports the failed body instead. Does not return. */
static void guard_resume(r_guard *g, tick_ctx *tick, zuh_sink *sink, zuh_result *r) {
    if (tick) tick_release(tick);
    if (sink) { zuh_sink_abort(sink); zuh_sink_free(sink); }
    if (r) zuh_result_free(r);
    g->resumed = 1;
    R_ContinueUnwind(g->token);
}

/* A string the engine built from UTF-8 input, marked as such at the R
 * boundary, as headers_to_r() marks header values. */
static SEXP utf8_string(const char *s) {
    SEXP x = PROTECT(Rf_allocVector(STRSXP, 1));
    SET_STRING_ELT(x, 0, Rf_mkCharCE(s, CE_UTF8));
    UNPROTECT(1);
    return x;
}

/* --- §63.2 the vertical slice --------------------------------------------- */

/* build_response needs the trace as well as the result, and R_UnwindProtect
 * passes one pointer. Bundling them beats a file-scope pointer, which would
 * be wrong the moment a callback issued a nested request (§27.4 permits that
 * on a different client). */
typedef struct { zuh_result *r; zuh_trace *t; SEXP pool; } resp_ctx;

/* --- §65.4 a body the caller pulls ---------------------------------------
 *
 * The open body owns a connection, which belongs to a pool (§26). The pool's
 * external pointer is kept in this pointer's protected slot, so the pool
 * cannot be collected, and its finalizer cannot free the connection under
 * us, while a body still holds one. The finalizer aborts an unfinished body:
 * over HTTP/2 that writes one RST_STREAM frame, bounded by a second. */
static SEXP zuh_stream_tag = NULL;

static void stream_finalizer(SEXP ptr) {
    zuh_open_body *b = (zuh_open_body *)R_ExternalPtrAddr(ptr);
    /* During a session the protected slot keeps the pool alive while this
     * runs. At exit both finalizers are onexit, and this one dereferences
     * the pool: it relies on R running the newer weak reference first, which
     * a body's always is, since a body is made after the pool it came from.
     * True of R's finalizer list today; if R ever ran them oldest first, the
     * pool would have to drain its open bodies itself (review #169). */
    if (!b) return;
    R_ClearExternalPtr(ptr);
    zuh_open_body_free(b);
}

static zuh_open_body *stream_ptr_get(SEXP ptr) {
    if (TYPEOF(ptr) != EXTPTRSXP || R_ExternalPtrTag(ptr) != zuh_stream_tag) return NULL;
    return (zuh_open_body *)R_ExternalPtrAddr(ptr);
}

static SEXP build_response(void *data);
static SEXP timings_to_r(const zuh_timings *t);
static SEXP trace_to_r(const zuh_trace *t);

/* Runs whether build_response returned or longjmped (§25.2 mechanism (a)).
 * `jump` is TRUE only on the unwind path; the work is identical either way,
 * so it is deliberately not branched on. */
static void free_result_on_unwind(void *data, Rboolean jump) {
    (void)jump;
    zuh_result_free(((resp_ctx *)data)->r);
}

/* Raise the §34.1 condition for a zuh_error by calling back into R. Building
 * the condition in R rather than in C keeps the class hierarchy in one place
 * (zu_condition()) and keeps this file free of condition construction. */
static void raise_zu_error(const zuh_error *e, const char *url) {
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

    SETCAR(p, Rf_ScalarInteger((int)zuh_code_public(e->code)));         p = CDR(p);
    SETCAR(p, utf8_string(e->message[0] ? e->message : "request failed")); p = CDR(p);
    SETCAR(p, url ? utf8_string(url) : R_NilValue);                     p = CDR(p);
    SETCAR(p, Rf_mkString(zuh_phase_name(e->phase)));                    p = CDR(p);
    SETCAR(p, e->backend[0] ? Rf_mkString(e->backend) : R_NilValue);    p = CDR(p);
    SETCAR(p, Rf_ScalarInteger(e->backend_code));

    Rf_eval(call, ns);           /* zu_stop_from_c() does not return */
    UNPROTECT(5);
}

static SEXP headers_to_r(const zuh_headers *h) {
    size_t n = zuh_headers_total(h), i;
    SEXP out = PROTECT(Rf_allocVector(STRSXP, (R_xlen_t)n));
    SEXP nms = PROTECT(Rf_allocVector(STRSXP, (R_xlen_t)n));
    for (i = 0; i < n; i++) {
        const char *name = NULL, *value = NULL;
        zuh_headers_at(h, i, &name, &value);
        SET_STRING_ELT(nms, (R_xlen_t)i, Rf_mkChar(name ? name : ""));
        /* §18.3: a value may carry obs-text (RFC 9110 §5.5), which is not
         * necessarily UTF-8. Marking such bytes UTF-8 made nchar(), grepl()
         * and print() fail on a Latin-1 filename. Only valid UTF-8 is marked
         * so; anything else is Latin-1, RFC 7230's nominal charset for
         * obs-text and the one encoding in which every byte is a character. */
        if (!value) value = "";
        SET_STRING_ELT(out, (R_xlen_t)i,
                       Rf_mkCharCE(value, zuh_utf8_valid(value, strlen(value))
                                              ? CE_UTF8 : CE_LATIN1));
    }
    Rf_setAttrib(out, R_NamesSymbol, nms);
    UNPROTECT(2);
    return out;
}

/* §14. Built here rather than in R so there is one definition of what a
 * TLS configuration is; the R layer validates paths, where the error can
 * name which of ca_file and ca_extra was wrong. Returns 0 when `tls` is not a
 * configuration (NULL: system defaults). Strings are borrowed from `tls` and
 * the pin array is R_alloc'd, so both live until the .Call returns. */
static int tls_from_r(SEXP tls, zuh_tls_config *cfg) {
    SEXP names;
    R_xlen_t i, n;
    if (tls == R_NilValue || !Rf_isVectorList(tls)) return 0;
    /* A list's names are reachable from `tls`, which .Call protects, so this
     * is belt and braces -- but rchk cannot see that, and its gate is worth
     * more than one PROTECT (W1). */
    names = PROTECT(Rf_getAttrib(tls, R_NamesSymbol));
    n = Rf_xlength(tls);
    zuh_tls_config_init(cfg);
    for (i = 0; i < n; i++) {
        const char *nm = (names == R_NilValue) ? ""
                         : Rf_translateCharUTF8(STRING_ELT(names, i));
        SEXP v = VECTOR_ELT(tls, i);
        if (v == R_NilValue) continue;
        if (strcmp(nm, "ca_file") == 0 && Rf_isString(v) && Rf_length(v) == 1) {
            cfg->ca_file = Rf_translateCharUTF8(STRING_ELT(v, 0));
            cfg->source  = ZUH_TRUST_FILE;   /* §14.2: REPLACES */
        } else if (strcmp(nm, "ca_extra") == 0 && Rf_isString(v) && Rf_length(v) == 1) {
            /* §14.2: ADDS. Deliberately does NOT touch `source`, which is
             * the whole difference between the two arguments. */
            cfg->ca_extra_file = Rf_translateCharUTF8(STRING_ELT(v, 0));
        } else if (strcmp(nm, "pins") == 0 && Rf_isString(v) && Rf_length(v) > 0) {
            R_xlen_t j, np = Rf_xlength(v);
            const char **pins = (const char **)R_alloc((size_t)np, sizeof(char *));
            for (j = 0; j < np; j++)
                pins[j] = Rf_translateCharUTF8(STRING_ELT(v, j));
            cfg->pins   = pins;
            cfg->n_pins = (size_t)np;
        } else if (strcmp(nm, "revocation") == 0) {
            cfg->revocation = (Rf_asLogical(v) == TRUE);
        } else if (strcmp(nm, "min_version") == 0) {
            int mv = Rf_asInteger(v);
            if (mv == 12 || mv == 13) cfg->min_version = mv;
        }
    }
    UNPROTECT(1);
    return 1;
}

/* D-56: refuse a TLS configuration the linked backend cannot honour, from R,
 * before DNS or TCP. The engine makes the same check again inside
 * zuh_tls_connect(), so a caller that bypasses the R layer is still refused;
 * this copy exists so the refusal costs no network round trip. */
static SEXP C_zu_tls_check(SEXP tls) {
    zuh_tls_config cfg;
    zuh_error e;
    zuh_error_clear(&e);
    if (!tls_from_r(tls, &cfg)) return R_NilValue;
    if (zuh_tls_config_check(&cfg, zuh_tls_backend_caps(), zuh_tls_backend_name(),
                            &e) != ZUH_OK)
        raise_zu_error(&e, NULL);
    return R_NilValue;
}

/* One entry point for every method. The R layer owns argument shaping; this
 * function's job is to translate and to own nothing across a longjmp. */
static SEXP C_zu_perform(SEXP method, SEXP url, SEXP header_names,
                         SEXP header_values, SEXP body, SEXP timeout_ms,
                         SEXP max_redirects, SEXP verify, SEXP max_body,
                         SEXP user_agent, SEXP decode, SEXP pool,
                         SEXP path, SEXP callback, SEXP proxy, SEXP tls,
                         SEXP trace, SEXP redact, SEXP http2, SEXP stream,
                         SEXP body_stream, SEXP body_timeout_ms) {
    zuh_get_opts o;
    tick_ctx tick = { NULL };
    zuh_req_spec spec;
    cb_ctx cb;
    zuh_sink cb_sink;
    zuh_tls_config tlscfg;
    zuh_trace tracebuf;
    zuh_redact_policy redact_policy;
    zuh_result r;
    zuh_error e;
    zuh_code rc;
    const char *u;
    int nh = 0, i;
    /* list(body_stream, token) for §65.7 and the callback's token. Made
     * here, PROTECTed, before any C state exists; see r_guard. */
    SEXP src_keep = R_NilValue, cb_token = R_NilValue;
    /* Both are PROTECTed below on every path, so every return after that,
     * including the "not reached" ones after a raise, which rchk cannot tell
     * apart, unprotects two. */

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

    if (Rf_isFunction(body_stream)) {
        src_keep = PROTECT(Rf_allocVector(VECSXP, 2));
        SET_VECTOR_ELT(src_keep, 0, body_stream);
        SET_VECTOR_ELT(src_keep, 1, R_MakeUnwindCont());
    } else {
        PROTECT(src_keep);
    }
    if (Rf_isFunction(callback)) cb_token = R_MakeUnwindCont();
    PROTECT(cb_token);
    if (body != R_NilValue) {
        if (TYPEOF(body) != RAWSXP)
            Rf_error("body must be a raw vector; the R layer serialises everything else");
        spec.body     = RAW(body);
        spec.body_len = (size_t)Rf_xlength(body);
    }

    zuh_get_opts_init(&o);
    o.timeout_ms    = (long)Rf_asInteger(timeout_ms);
    o.max_redirects = Rf_asInteger(max_redirects);
    o.verify        = Rf_asLogical(verify) == TRUE;
    {
        /* §40. A double above UINT64_MAX (Inf, 1e30) is undefined behaviour
         * to cast (C11 6.3.1.4): one compiler saturates, another gives 0,
         * which the engine reads as "the 16 MiB default". Inf is a natural
         * spelling of "no limit", as it is for `timeout`, so it is clamped
         * here rather than refused. 2^64 is exactly representable; anything
         * at or above it is "as large as a uint64_t goes". The R layer has
         * already refused NA and anything below 1. */
        double mb = Rf_asReal(max_body);
        o.max_body = mb >= 18446744073709551616.0 ? UINT64_MAX : (uint64_t)mb;
    }
    o.no_decode     = Rf_asLogical(decode) != TRUE;
    /* §65.4. The R layer has refused it together with path or callback. */
    o.stream_body   = Rf_asLogical(stream) == TRUE;
    /* §65.4: the request's own `timeout`, for each pulled read; `timeout_ms`
     * is this attempt's share of the total budget (#181). */
    o.body_timeout_ms = (long)Rf_asInteger(body_timeout_ms);
    /* §65.1. The R layer has refused anything but these three words. */
    if (Rf_isString(http2) && Rf_length(http2) == 1 && STRING_ELT(http2, 0) != NA_STRING) {
        const char *m = CHAR(STRING_ELT(http2, 0));
        o.http2 = strcmp(m, "required") == 0 ? ZUH_H2_REQUIRED
                : strcmp(m, "off") == 0      ? ZUH_H2_OFF : ZUH_H2_AUTO;
    }
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
    if (tls_from_r(tls, &tlscfg)) {
        o.tls = &tlscfg;
        /* One place names a replacement CA (§26.1's key reads it from here). */
        if (tlscfg.ca_file) o.ca_file = tlscfg.ca_file;
    }

    /* §42. The engine redacts the URLs it traces and its error messages,
     * and strips secret headers at a cross-origin redirect (§19.2), so the
     * caller's extra names have to reach it: `redact` is list(params,
     * headers). Set unconditionally rather than only when tracing: a policy
     * that depends on another option is one an added egress can silently
     * miss. The R_alloc storage behind the lists lives until this .Call
     * returns, which outlasts the engine call. */
    policy_from(Rf_isNewList(redact) && XLENGTH(redact) == 2 ? VECTOR_ELT(redact, 1)
                                                            : R_NilValue,
                Rf_isNewList(redact) && XLENGTH(redact) == 2 ? VECTOR_ELT(redact, 0)
                                                            : redact,
                &redact_policy);
    o.redact = &redact_policy;

    /* §35: opt-in. Without this the trace pointer stays NULL and every
     * zuh_trace_add() in the connect, handshake and read paths is one branch. */
    if (Rf_asLogical(trace) == TRUE) {
        zuh_trace_init(&tracebuf);
        o.trace = &tracebuf;
    }

    /* §25.1: a checkpoint at most one tick apart, and never inside a blocking
     * call. 100 ms is the design's ceiling. */
    o.tick     = r_interrupt_tick;
    o.tick_ctx = NULL;       /* never per-request state in a pooled object */

    /* §65.7. After everything that can longjmp (review #142) and before the
     * file sink, whose exclusive creation on disk must not be followed by an
     * allocation that can longjmp past it: R_PreserveObject() is one.
     * Outside R's heap, because a pulled body that inherits it outlives
     * this .Call. */
    if (src_keep != R_NilValue) {
        src_ctx *sc;
        R_PreserveObject(src_keep);
        sc = (src_ctx *)zuh_calloc(1, sizeof *sc);
        if (!sc || !zuh_buf_init(&sc->piece, 0, (size_t)-1)) {
            zuh_free(sc);
            R_ReleaseObject(src_keep);
            Rf_error("out of memory");
        }
        sc->keep = src_keep;
        sc->g.token = VECTOR_ELT(src_keep, 1);
        spec.source.next = src_next;
        spec.source.release = src_release;
        spec.source.ctx = sc;
    }

    memset(&cb, 0, sizeof cb);
    if (Rf_isFunction(callback)) {
        memset(&cb_sink, 0, sizeof cb_sink);
        cb.fn         = callback;
        cb.g.token    = cb_token;
        cb_sink.write = cb_write;
        cb_sink.ctx   = &cb;
        o.sink        = &cb_sink;
    } else if (Rf_isString(path) && Rf_length(path) == 1 &&
               STRING_ELT(path, 0) != NA_STRING) {
        const char *dest = Rf_translateCharUTF8(STRING_ELT(path, 0));
        o.sink = zuh_sink_file(dest, &e);
        if (!o.sink) {
            if (spec.source.ctx) {   /* nothing has run it: free it here */
                src_ctx *sc = (src_ctx *)spec.source.ctx;
                R_ReleaseObject(sc->keep);
                zuh_buf_free(&sc->piece);
                zuh_free(sc);
            }
            raise_zu_error(&e, u); UNPROTECT(2); return R_NilValue;
        }
    }

    zuh_error_clear(&e);
    {
        tick_ctx *prev = g_tick_current;
        g_tick_current = &tick;
        rc = zuh_engine_perform(&r, u, &spec, &o, &e);
        g_tick_current = prev;
    }

    /* §65.7: the engine has released the body source, unless the pulled
     * body inherited it. Either way it is no longer this frame's to free;
     * a condition the body function raised is, and goes first. */
    if (spec.source.ctx) {
        src_ctx *sc = (src_ctx *)spec.source.ctx;
        if (!sc->released) {
            sc->detached = 1;           /* the pulled body frees it */
        } else {
            r_guard g = sc->g;          /* the token is still PROTECTed by this frame */
            R_ReleaseObject(sc->keep);
            zuh_free(sc);
            spec.source.ctx = NULL;
            if (g.jumped) {
                guard_resume(&g, &tick, o.sink && o.sink != &cb_sink ? o.sink : NULL, &r);
                UNPROTECT(2); return R_NilValue;   /* not reached */
            }
        }
    }

    /* §27.3: the loop has unwound and every C resource it held is released,
     * so this is the first point at which the jump can go on. It is the
     * USER's jump, resumed as it was: wrapping it would turn "object 'x' not
     * found" inside their callback into a mysterious transport failure. */
    if (cb.g.jumped) {
        guard_resume(&cb.g, &tick, NULL, &r);
        UNPROTECT(2); return R_NilValue;   /* not reached */
    }
    if (o.sink && o.sink != &cb_sink) {
        /* Commit or discard, then release. A failure to rename is a failure
         * of the request: the caller asked for a file at that path and there
         * is not one, so reporting success would be a lie. */
        if (rc == ZUH_OK) rc = zuh_sink_finish(o.sink, &e);
        else             zuh_sink_abort(o.sink);
        if (rc != ZUH_OK) zuh_sink_abort(o.sink);
        r.body.len = 0;              /* the bytes went to the file, not here */
        zuh_sink_free(o.sink);
        o.sink = NULL;
    }
    if (rc != ZUH_OK) {
        /* Our tick returns 1 only for a pending user interrupt, so a
         * cancellation reaching here is always that (§34.1 separates
         * zu_interrupted_error from zu_cancelled_error because a person
         * pressing Ctrl-C and a programmatic stop want different handling). */
        /* Not an interrupt: an error R raised at the checkpoint, such as a
         * time limit. Re-raise it as it was; the sink above is already
         * discarded and the engine holds nothing. */
        if (rc == ZUH_ERR_CANCELLED && tick.caught &&
            !Rf_inherits(tick.caught, "interrupt")) {
            SEXP cond = PROTECT(tick.caught);
            SEXP call;
            R_ReleaseObject(cond);
            tick.caught = NULL;
            call = PROTECT(Rf_lang2(Rf_install("stop"), cond));
            Rf_eval(call, R_GlobalEnv);
            UNPROTECT(2);
            UNPROTECT(2); return R_NilValue;   /* not reached */
        }
        tick_release(&tick);
        if (rc == ZUH_ERR_CANCELLED) {
            zuh_error err2 = e;
            err2.code = ZUH_ERR_INTERRUPTED;
            snprintf(err2.message, sizeof err2.message,
                     "request interrupted by the user");
            raise_zu_error(&err2, u);
            UNPROTECT(2); return R_NilValue;   /* not reached */
        }
        /* No C resources are live here: zuh_engine_get frees everything it
         * owns before returning non-OK, which is what makes it safe to raise
         * an R condition (and longjmp) from this point.
         *
         * The return code is the authority. A path that returned an error
         * without filling `e` once reached R as "unknown zuhttp error code:
         * 0" — a plain simpleError no handler for zu_error would catch. */
        if (e.code == ZUH_OK) {
            e.code = rc;
            if (!e.message[0])
                snprintf(e.message, sizeof e.message, "request failed (%s)",
                         zuh_code_class(rc));
        }
        raise_zu_error(&e, u);
        UNPROTECT(2); return R_NilValue;   /* not reached */
    }

    /* The continuation token must be NULL, not R_NilValue. R checks
     * `cont == NULL` and allocates its own token in that case; R_NilValue is a
     * perfectly valid SEXP, so it passes that check and is then used as a
     * continuation it is not, which fails with "bad value" on every call. */
    {
        resp_ctx ctx;
        ctx.r = &r;
        ctx.t = o.trace;
        ctx.pool = pool;
        SEXP out = R_UnwindProtect(build_response, &ctx, free_result_on_unwind, &ctx, NULL);
        UNPROTECT(2);   /* src_keep, cb_token */
        return out;
    }
}

/* Everything below runs with `r` still owning C memory, and every R allocation
 * here can longjmp on failure. R_UnwindProtect guarantees free_result_on_unwind
 * runs either way — §25.2's mechanism (a), used to release promptly rather
 * than at the next GC. */
static SEXP build_response(void *data) {
    resp_ctx  *ctx = (resp_ctx *)data;
    zuh_result *rp = ctx->r;
    zuh_result r = *rp;
    SEXP out, nms, body;

    body = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t)r.body.len));
    if (r.body.len) memcpy(RAW(body), r.body.data, r.body.len);

    /* §35.2's connection metadata rides on the response rather than being a
     * second call, because it describes the connection THIS response came
     * over — asking again later would answer about a different one. */
    out = PROTECT(Rf_allocVector(VECSXP, 18));
    nms = PROTECT(Rf_allocVector(STRSXP, 18));
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
    SET_VECTOR_ELT(out, 14, Rf_ScalarInteger(r.http_major));
    SET_STRING_ELT(nms, 14, Rf_mkChar("http_major"));
    SET_VECTOR_ELT(out, 15, headers_to_r(&r.trailers));
    SET_STRING_ELT(nms, 15, Rf_mkChar("trailers"));
    SET_VECTOR_ELT(out, 17, r.final_method ? Rf_mkString(r.final_method) : R_NilValue);
    SET_STRING_ELT(nms, 17, Rf_mkChar("method"));
    SET_STRING_ELT(nms, 16, Rf_mkChar("stream"));
    if (rp->open) {
        /* Ownership moves to the pointer before anything else can longjmp:
         * from here the finalizer frees the body, and the unwind handler,
         * which frees what is left in `rp`, must not. */
        SEXP xp = R_MakeExternalPtr(rp->open, zuh_stream_tag, ctx->pool);
        SET_VECTOR_ELT(out, 16, xp);
        R_RegisterCFinalizerEx(xp, stream_finalizer, TRUE);
        rp->open = NULL;
    }
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
static SEXP timings_to_r(const zuh_timings *t) {
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
static SEXP trace_to_r(const zuh_trace *t) {
    SEXP out, names, ev, at, n_, detail;
    size_t i;
    if (!t) return R_NilValue;

    ev     = PROTECT(Rf_allocVector(STRSXP,  (R_xlen_t)t->n));
    at     = PROTECT(Rf_allocVector(REALSXP, (R_xlen_t)t->n));
    n_     = PROTECT(Rf_allocVector(REALSXP, (R_xlen_t)t->n));
    detail = PROTECT(Rf_allocVector(STRSXP,  (R_xlen_t)t->n));
    for (i = 0; i < t->n; i++) {
        SET_STRING_ELT(ev, (R_xlen_t)i, Rf_mkChar(zuh_event_name(t->ev[i].ev)));
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
        "tls_capabilities", "compression", "ipv6", "http", NULL
    };
    /* D-56: the zu_tls() settings this backend honours. The rest are refused
     * before any connection, and a user deciding whether a setting will work
     * should be able to ask rather than find out from an error. */
    static const struct { unsigned bit; const char *name; } caps_tab[] = {
        { ZUH_TLS_CAP_PINS,       "pins" },
        { ZUH_TLS_CAP_TLS13,      "tls13" },
        { ZUH_TLS_CAP_CA_FILE,    "ca_file" },
        { ZUH_TLS_CAP_CA_EXTRA,   "ca_extra" },
        { ZUH_TLS_CAP_REVOCATION, "revocation" }
    };
    unsigned caps = zuh_tls_available() ? zuh_tls_backend_caps() : 0u;
    SEXP capv;
    int nc = 0, k;
    const char *backend = zuh_tls_backend_name();
    const char *trust;
    SEXP out, names;
    int i, n = 0;

    while (nm[n]) n++;

    /* §13.1: the engine and the store are different questions, and on macOS
     * they are answered by different frameworks. */
    if (strcmp(backend, "network-framework") == 0) trust = "macOS Keychain (SecTrust)";
    else if (strcmp(backend, "schannel") == 0)     trust = "Windows Certificate Store";
    else if (strcmp(backend, "openssl") == 0)      trust = "OpenSSL system defaults";
    else                                           trust = "none";

    out   = PROTECT(Rf_allocVector(VECSXP, n));
    names = PROTECT(Rf_allocVector(STRSXP, n));

    SET_VECTOR_ELT(out, 0, Rf_mkString(backend));
    SET_VECTOR_ELT(out, 1, Rf_mkString(trust));
    SET_VECTOR_ELT(out, 2, Rf_ScalarLogical(zuh_tls_available()));
    /* §14.5 / D-31: off by default on every platform, measured in S0 (F-4). */
    SET_VECTOR_ELT(out, 3, Rf_ScalarLogical(FALSE));
    for (k = 0; k < (int)(sizeof caps_tab / sizeof caps_tab[0]); k++)
        if (caps & caps_tab[k].bit) nc++;
    capv = Rf_allocVector(STRSXP, nc);
    SET_VECTOR_ELT(out, 4, capv);           /* protected by `out` from here */
    for (k = 0, nc = 0; k < (int)(sizeof caps_tab / sizeof caps_tab[0]); k++)
        if (caps & caps_tab[k].bit)
            SET_STRING_ELT(capv, nc++, Rf_mkChar(caps_tab[k].name));
    SET_VECTOR_ELT(out, 5, Rf_mkString("gzip, deflate"));
    /* §3.1: getaddrinfo is called with AF_UNSPEC, so both families are tried
     * in whatever order the resolver returns. Whether a route exists is a
     * property of the machine, not of this build — reporting "yes" here means
     * "not disabled", which is the honest claim. */
    SET_VECTOR_ELT(out, 6, Rf_ScalarLogical(TRUE));
    /* §65.1: the protocols this build speaks. HTTP/2 is compiled into
     * every build (nghttp2 is vendored); over TLS it also needs the
     * backend's ALPN, which tls_capabilities reports. */
    {
        SEXP hv = Rf_allocVector(STRSXP, 2);
        SET_VECTOR_ELT(out, 7, hv);
        SET_STRING_ELT(hv, 0, Rf_mkChar("HTTP/1.1"));
        SET_STRING_ELT(hv, 1, Rf_mkChar("HTTP/2"));
    }

    for (i = 0; i < n; i++) SET_STRING_ELT(names, i, Rf_mkChar(nm[i]));
    Rf_setAttrib(out, R_NamesSymbol, names);
    UNPROTECT(2);
    return out;
}

/* §65.4: up to n decoded bytes, a raw vector of length 0 at the end. Every
 * wait is a §25.1 wait: the stream's tick reads g_tick_current, set here as
 * C_zu_perform sets it, and an interrupt ends the body as an abort would. */
static SEXP C_zu_stream_read(SEXP ptr, SEXP n, SEXP url, SEXP timeout_ms) {
    zuh_open_body *b = stream_ptr_get(ptr);
    tick_ctx tick = { NULL };
    const void *got = NULL;
    size_t got_len = 0;
    zuh_error e;
    zuh_code rc;
    double want = Rf_asReal(n);
    const char *u = (Rf_isString(url) && Rf_length(url) == 1)
                        ? Rf_translateCharUTF8(STRING_ELT(url, 0)) : NULL;
    SEXP out;
    if (!b) {
        /* §34.1, as every other read failure: after saveRDS()/readRDS() the
         * pointer comes back NULL, and the connection is gone. */
        zuh_error_clear(&e);
        zuh_error_set(&e, ZUH_ERR_IO, ZUH_PHASE_READ,
                      "this response's body is no longer readable: its connection "
                      "did not survive serialization, or the response was edited");
        raise_zu_error(&e, u);
    }
    if (zuh_open_body_busy(b)) {
        /* §65.7: the request body function is running inside nghttp2,
         * which is not re-entrant (review #155). */
        zuh_error_clear(&e);
        zuh_error_set(&e, ZUH_ERR_IO, ZUH_PHASE_READ,
                      "a response cannot be read from inside its own request body function");
        raise_zu_error(&e, u);
    }
    if (!(want >= 1)) want = 1;
    if (want > 64.0 * 1024 * 1024) want = 64.0 * 1024 * 1024;
    zuh_error_clear(&e);
    {
        tick_ctx *prev = g_tick_current;
        g_tick_current = &tick;
        /* #173: this call's bound, when the caller gave one; 0 otherwise. */
        rc = zuh_open_body_peek(b, (size_t)want, &got, &got_len,
                                (long)Rf_asInteger(timeout_ms), &e);
        g_tick_current = prev;
    }
    if (rc != ZUH_OK) {
        src_ctx *sc = (src_ctx *)zuh_open_body_source_ctx(b);
        /* §65.7: the request body function, still running under a full
         * duplex stream, did not return: its jump is the one to resume. The
         * token stays in sc->keep, preserved, until the body is freed, and
         * is resumed once: a later read of the failed body reports the
         * failure below (review #175). */
        if (sc && sc->g.jumped && !sc->g.resumed) {
            guard_resume(&sc->g, &tick, NULL, NULL);
            return R_NilValue;             /* not reached */
        }
        if (rc == ZUH_ERR_CANCELLED && tick.caught &&
            !Rf_inherits(tick.caught, "interrupt")) {
            SEXP cond = PROTECT(tick.caught);
            SEXP call;
            R_ReleaseObject(cond);
            tick.caught = NULL;
            call = PROTECT(Rf_lang2(Rf_install("stop"), cond));
            Rf_eval(call, R_GlobalEnv);
            UNPROTECT(2);
            return R_NilValue;
        }
        if (rc == ZUH_ERR_CANCELLED && tick.caught) {
            tick_release(&tick);
            e.code = ZUH_ERR_INTERRUPTED;
            snprintf(e.message, sizeof e.message, "request interrupted by the user");
        }
        tick_release(&tick);
        if (e.code == ZUH_OK) {
            e.code = rc;
            snprintf(e.message, sizeof e.message, "reading the response body failed (%s)",
                     zuh_code_class(rc));
        }
        raise_zu_error(&e, u);
        return R_NilValue;
    }
    tick_release(&tick);
    /* The copy into R comes last and is the only allocation that can
     * longjmp. The bytes are still the body's, which `ptr` keeps alive and
     * its finalizer frees, so a jump here owns nothing and loses nothing:
     * they are consumed only once copied (#214). */
    out = Rf_allocVector(RAWSXP, (R_xlen_t)got_len);
    if (got_len) memcpy(RAW(out), got, got_len);
    zuh_open_body_consume(b, got_len);
    return out;
}

static SEXP C_zu_stream_abort(SEXP ptr) {
    zuh_open_body *b = stream_ptr_get(ptr);
    if (zuh_open_body_busy(b)) {
        zuh_error e;
        zuh_error_clear(&e);
        zuh_error_set(&e, ZUH_ERR_IO, ZUH_PHASE_READ,
                      "a response cannot be aborted from inside its own request body function");
        raise_zu_error(&e, NULL);
    }
    if (b) zuh_open_body_abort(b);
    return R_NilValue;
}

/* D-98: NULL until the body has been read to a clean end, since trailers
 * come after it; still NULL after an abort or a failure, whose trailers are
 * unknown. An empty vector means the stream ended with none. */
static SEXP C_zu_stream_trailers(SEXP ptr) {
    zuh_open_body *b = stream_ptr_get(ptr);
    if (!b || !zuh_open_body_ended_clean(b)) return R_NilValue;
    return headers_to_r(zuh_open_body_trailers(b));
}

static SEXP C_zu_tls_backend(void) {
    return Rf_mkString(zuh_tls_backend_name());
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
    {"C_zu_perform",           (DL_FUNC) &C_zu_perform,          22},
    {"C_zu_stream_read",       (DL_FUNC) &C_zu_stream_read,       4},
    {"C_zu_stream_abort",      (DL_FUNC) &C_zu_stream_abort,      1},
    {"C_zu_stream_trailers",   (DL_FUNC) &C_zu_stream_trailers,   1},
    {"C_zu_pool_new",          (DL_FUNC) &C_zu_pool_new,          5},
    {"C_zu_pool_valid",        (DL_FUNC) &C_zu_pool_valid,        1},
    {"C_zu_pool_stats",        (DL_FUNC) &C_zu_pool_stats,        1},
    {"C_zu_pool_config",       (DL_FUNC) &C_zu_pool_config,       1},
    {"C_zu_pool_clear",        (DL_FUNC) &C_zu_pool_clear,        1},
    {"C_zu_tls_backend",       (DL_FUNC) &C_zu_tls_backend,       0},
    {"C_zu_tls_check",         (DL_FUNC) &C_zu_tls_check,         1},
    {"C_zu_build_info",        (DL_FUNC) &C_zu_build_info,        0},
    {NULL, NULL, 0}
};

void attribute_visible R_init_zuhttp(DllInfo *dll) {
    /* Interned once. Pointer identity against this symbol is what tells our
     * external pointers from another package's (§26.5). */
    zuh_pool_tag = Rf_install("zu_pool");
    zuh_stream_tag = Rf_install("zu_stream");
    g_tick_classes = Rf_allocVector(STRSXP, 2);
    R_PreserveObject(g_tick_classes);
    SET_STRING_ELT(g_tick_classes, 0, Rf_mkChar("interrupt"));
    SET_STRING_ELT(g_tick_classes, 1, Rf_mkChar("error"));
    R_registerRoutines(dll, NULL, call_methods, NULL, NULL);
    R_useDynamicSymbols(dll, FALSE);
    R_forceSymbols(dll, TRUE);
}

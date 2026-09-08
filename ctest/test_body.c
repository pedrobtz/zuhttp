/* Response body streaming and sinks — design §27, §21, §19.5.
 *
 * All of it on the mock stream, which is the point of S17 having split
 * zu_body.c out of the engine: the guarantee under test is "memory does not
 * grow with the body", and proving that needs a 100 MB response, which is
 * exactly the thing you cannot ask a real server for on every CI run.
 */
#include "zu_test.h"
#include "zu_body.h"
#include "zu_sink.h"
#include "zu_mock_stream.h"
#include "zu_tls.h"
#include "zu_trace.h"
#include "zu_alloc.h"
#include <string.h>
#include <stdio.h>

#if defined(ZU_POSIX)
#  include <sys/resource.h>
#  include <unistd.h>
#endif

void suite_body(void);

static int streq(const char *a, const char *b) { return a && b && strcmp(a, b) == 0; }

static zu_deadline forever(void) { return zu_deadline_in(60000); }

/* Drive one body through a pipe into `sink` and return the status. */
static zu_code run_body(const zu_mock_step *steps, size_t nsteps,
                        zu_frame_kind kind, uint64_t length,
                        zu_sink *sink, zu_headers *h, int no_decode,
                        uint64_t max_body, zu_error *err) {
    zu_stream *s = zu_mock_stream_new(steps, nsteps, 0, 0);
    zu_body_pipe p;
    zu_framing fr;
    zu_code rc;

    if (!s) return ZU_ERR_NOMEM;
    fr.kind = kind; fr.length = length; fr.poolable = 1;

    rc = zu_body_pipe_init(&p, sink, h, no_decode, max_body, err);
    if (rc == ZU_OK)
        rc = zu_body_read(s, &fr, &p, NULL, 0, max_body, forever(), err);
    zu_body_pipe_free(&p);
    zu_stream_free(s);
    return rc;
}

void suite_body(void) {
    zu_error e;
    zu_headers h;

    /* --- the sinks themselves ---------------------------------------- */

    ZU_CASE("§27: a memory sink accumulates exactly what it is given");
    {
        zu_buffer b;
        zu_sink sink;
        ZU_CHECK(zu_buf_init(&b, 8, 1 << 20));
        zu_sink_memory_init(&sink, &b);
        ZU_CHECK_EQ_INT(zu_sink_write(&sink, "abc", 3, &e), ZU_OK);
        ZU_CHECK_EQ_INT(zu_sink_write(&sink, "de", 2, &e), ZU_OK);
        ZU_CHECK_EQ_INT((int)b.len, 5);
        ZU_CHECK(memcmp(b.data, "abcde", 5) == 0);
        ZU_CHECK_EQ_INT((int)sink.written, 5);
        /* A zero-length write is not an error and must not be counted. */
        ZU_CHECK_EQ_INT(zu_sink_write(&sink, "", 0, &e), ZU_OK);
        ZU_CHECK_EQ_INT((int)sink.written, 5);
        zu_buf_free(&b);
    }

    ZU_CASE("§19.5: a discard sink counts without keeping");
    {
        zu_sink *d = zu_sink_discard();
        ZU_CHECK(d != NULL);
        ZU_CHECK_EQ_INT(zu_sink_write(d, "12345", 5, &e), ZU_OK);
        ZU_CHECK_EQ_INT((int)d->written, 5);
        zu_sink_free(d);
    }

    /* --- §27.1 atomic file writes ------------------------------------- */

    ZU_CASE("§27.1: a finished download appears at the target path");
    {
        const char *path = "zu_test_dl_ok.bin";
        zu_sink *f;
        FILE *fp;
        char buf[16];
        size_t n;

        remove(path);
        f = zu_sink_file(path, &e);
        ZU_CHECK(f != NULL);
        /* Nothing at the destination until finish(): that IS the guarantee. */
        ZU_CHECK(fopen(path, "rb") == NULL);
        ZU_CHECK_EQ_INT(zu_sink_write(f, "hello", 5, &e), ZU_OK);
        ZU_CHECK(fopen(path, "rb") == NULL);
        ZU_CHECK_EQ_INT(zu_sink_finish(f, &e), ZU_OK);
        zu_sink_free(f);

        fp = fopen(path, "rb");
        ZU_CHECK(fp != NULL);
        if (fp) {
            n = fread(buf, 1, sizeof buf, fp);
            fclose(fp);
            ZU_CHECK_EQ_INT((int)n, 5);
            ZU_CHECK(memcmp(buf, "hello", 5) == 0);
        }
        remove(path);
    }

    ZU_CASE("§27.1: an aborted download leaves NOTHING at the target path");
    {
        const char *path = "zu_test_dl_abort.bin";
        zu_sink *f;
        const char *tmp;
        char tmpcopy[256];

        remove(path);
        f = zu_sink_file(path, &e);
        ZU_CHECK(f != NULL);
        tmp = zu_sink_file_tmp_path(f);
        ZU_CHECK(tmp != NULL);
        if (tmp) { strncpy(tmpcopy, tmp, sizeof tmpcopy - 1); tmpcopy[sizeof tmpcopy - 1] = 0; }

        ZU_CHECK_EQ_INT(zu_sink_write(f, "partial", 7, &e), ZU_OK);
        zu_sink_abort(f);
        zu_sink_free(f);

        /* Neither the destination nor the temporary file survives. The
         * second half matters as much as the first: a leftover .zudl beside
         * every failed download is its own bug report. */
        ZU_CHECK(fopen(path, "rb") == NULL);
        ZU_CHECK(fopen(tmpcopy, "rb") == NULL);
    }

    ZU_CASE("§27.1: an abandoned download cleans up even without abort()");
    {
        const char *path = "zu_test_dl_drop.bin";
        zu_sink *f;
        remove(path);
        f = zu_sink_file(path, &e);
        ZU_CHECK(f != NULL);
        ZU_CHECK_EQ_INT(zu_sink_write(f, "partial", 7, &e), ZU_OK);
        zu_sink_free(f);                 /* destroy without finish or abort */
        ZU_CHECK(fopen(path, "rb") == NULL);
    }

    ZU_CASE("§27.1: finishing replaces an existing file");
    {
        const char *path = "zu_test_dl_replace.bin";
        zu_sink *f;
        FILE *fp = fopen(path, "wb");
        char buf[16];
        size_t n;
        if (fp) { fwrite("old", 1, 3, fp); fclose(fp); }

        f = zu_sink_file(path, &e);
        ZU_CHECK(f != NULL);
        ZU_CHECK_EQ_INT(zu_sink_write(f, "new!", 4, &e), ZU_OK);
        ZU_CHECK_EQ_INT(zu_sink_finish(f, &e), ZU_OK);
        zu_sink_free(f);

        fp = fopen(path, "rb");
        ZU_CHECK(fp != NULL);
        if (fp) { n = fread(buf, 1, sizeof buf, fp); fclose(fp);
                  ZU_CHECK_EQ_INT((int)n, 4);
                  ZU_CHECK(memcmp(buf, "new!", 4) == 0); }
        remove(path);
    }

    /* --- framing through the pipe ------------------------------------- */

    ZU_CASE("a Content-Length body stops at the length, whatever else arrived");
    {
        static const zu_mock_step steps[] = {
            { ZU_MOCK_DATA, "HELLOandthenTHENEXTRESPONSE", 27, ZU_OK }
        };
        zu_buffer b; zu_sink sink;
        ZU_CHECK(zu_buf_init(&b, 8, 1 << 20));
        zu_sink_memory_init(&sink, &b);
        zu_headers_init(&h);
        ZU_CHECK_EQ_INT(run_body(steps, 1, ZU_FRAME_LENGTH, 5, &sink, &h, 1,
                                 1u << 20, &e), ZU_OK);
        ZU_CHECK_EQ_INT((int)b.len, 5);
        ZU_CHECK(memcmp(b.data, "HELLO", 5) == 0);
        zu_headers_free(&h);
        zu_buf_free(&b);
    }

    /* No ZU_MOCK_WOULDBLOCK step here, deliberately. The stream contract is
     * that a read blocks until data, EOF or the deadline: zu_net.c loops
     * internally on EWOULDBLOCK and never surfaces it, so a body reader that
     * handled it would be handling a case that cannot occur. Scripting one
     * would test the mock rather than the code. */
    ZU_CASE("a body split across many reads arrives whole");
    {
        static const zu_mock_step steps[] = {
            { ZU_MOCK_DATA, "ab", 2, ZU_OK },
            { ZU_MOCK_DATA, "cd", 2, ZU_OK },
            { ZU_MOCK_DATA, "e",  1, ZU_OK }
        };
        zu_buffer b; zu_sink sink;
        ZU_CHECK(zu_buf_init(&b, 8, 1 << 20));
        zu_sink_memory_init(&sink, &b);
        zu_headers_init(&h);
        ZU_CHECK_EQ_INT(run_body(steps, 3, ZU_FRAME_LENGTH, 5, &sink, &h, 1,
                                 1u << 20, &e), ZU_OK);
        ZU_CHECK_EQ_INT((int)b.len, 5);
        ZU_CHECK(memcmp(b.data, "abcde", 5) == 0);
        zu_headers_free(&h);
        zu_buf_free(&b);
    }

    ZU_CASE("§27.1: the body limit applies to a FILE sink, not only to memory");
    {
        static const zu_mock_step steps[] = {
            { ZU_MOCK_DATA, "0123456789", 10, ZU_OK },
            { ZU_MOCK_DATA, "0123456789", 10, ZU_OK },
            { ZU_MOCK_DATA, "0123456789", 10, ZU_OK }
        };
        const char *path = "zu_test_dl_limit.bin";
        zu_sink *f;
        remove(path);
        f = zu_sink_file(path, &e);
        ZU_CHECK(f != NULL);
        zu_headers_init(&h);
        /* An unbounded download to disk is still a denial of service, just
         * against a different resource. */
        ZU_CHECK_EQ_INT(run_body(steps, 3, ZU_FRAME_UNTIL_CLOSE, 0, f, &h, 1,
                                 12, &e), ZU_ERR_BODY_LIMIT);
        zu_sink_abort(f);
        zu_sink_free(f);
        ZU_CHECK(fopen(path, "rb") == NULL);
        zu_headers_free(&h);
    }

    /* --- §40: the cap is a BOUND, not a thing noticed afterwards ------- */

    ZU_CASE("§40: the sink is never handed a byte past max_body");
    {
        /* Found by fuzz_body on its first seed, and reproducible from R: a
         * max_body of 1024 handed 1593 bytes to a user's callback. The old
         * check ran after a chunk had already been delivered, so it reported
         * the overrun correctly and far too late. A byte a caller has already
         * received cannot be un-received. */
        static const zu_mock_step steps[] = {
            { ZU_MOCK_DATA, "0123456789", 10, ZU_OK },
            { ZU_MOCK_DATA, "0123456789", 10, ZU_OK },
            { ZU_MOCK_DATA, "0123456789", 10, ZU_OK }
        };
        zu_sink *d;
        int cap;
        for (cap = 1; cap <= 30; cap++) {
            d = zu_sink_discard();
            ZU_CHECK(d != NULL);
            zu_headers_init(&h);
            (void)run_body(steps, 3, ZU_FRAME_UNTIL_CLOSE, 0, d, &h, 1,
                           (uint64_t)cap, &e);
            /* Exactly the promise §40 makes, at every cap around the read
             * boundaries — not just at a convenient one. */
            ZU_CHECK(d->written <= (uint64_t)cap);
            zu_headers_free(&h);
            zu_sink_free(d);
        }
    }

    ZU_CASE("§40: a body exactly at the cap is delivered, not refused");
    {
        static const zu_mock_step steps[] = {
            { ZU_MOCK_DATA, "0123456789", 10, ZU_OK }
        };
        zu_buffer b; zu_sink sink;
        ZU_CHECK(zu_buf_init(&b, 8, 1 << 20));
        zu_sink_memory_init(&sink, &b);
        zu_headers_init(&h);
        /* Off-by-one in the other direction: refusing a body that fits would
         * make max_body mean "one less than it says". */
        ZU_CHECK_EQ_INT(run_body(steps, 1, ZU_FRAME_LENGTH, 10, &sink, &h, 1,
                                 10, &e), ZU_OK);
        ZU_CHECK_EQ_INT((int)b.len, 10);
        zu_headers_free(&h);
        zu_buf_free(&b);
    }

    /* --- §27: memory does not grow with the body ---------------------- */

#if defined(ZU_POSIX)
    ZU_CASE("§27: a 100 MB body streams in constant memory (S17 criterion)");
    {
        /* 1600 steps over one 64 KiB buffer: the mock hands out the same page
         * repeatedly, so the TEST does not need 100 MB either. */
        enum { CHUNK = 64u * 1024u, STEPS = 1600 };
        const uint64_t total = (uint64_t)CHUNK * STEPS;   /* 100 MiB */
        char *page = (char *)zu_alloc(CHUNK);
        zu_mock_step *steps = (zu_mock_step *)zu_alloc(sizeof(zu_mock_step) * STEPS);
        zu_sink *d = zu_sink_discard();
        struct rusage before, after;
        long grew_kb;
        int i;

        ZU_CHECK(page && steps && d);
        if (page && steps && d) {
            memset(page, 'x', CHUNK);
            for (i = 0; i < STEPS; i++) {
                steps[i].kind = ZU_MOCK_DATA;
                steps[i].data = page;
                steps[i].len  = CHUNK;
                steps[i].code = ZU_OK;
            }
            zu_headers_init(&h);
            getrusage(RUSAGE_SELF, &before);
            ZU_CHECK_EQ_INT(run_body(steps, STEPS, ZU_FRAME_LENGTH, total, d,
                                     &h, 1, total + 1, &e), ZU_OK);
            getrusage(RUSAGE_SELF, &after);
            zu_headers_free(&h);

            /* Every byte arrived... */
            ZU_CHECK(d->written == total);

            /* ...and peak RSS did not follow it. ru_maxrss is bytes on macOS
             * and kilobytes on Linux; normalising to KiB keeps one threshold.
             * It is a PEAK, so this measures growth over whatever the suite
             * had already touched — which is the honest reading of "under
             * 16 MB over baseline". */
#if defined(__APPLE__)
            grew_kb = (long)((after.ru_maxrss - before.ru_maxrss) / 1024);
#else
            grew_kb = (long)(after.ru_maxrss - before.ru_maxrss);
#endif
            if (grew_kb < 0) grew_kb = 0;
            printf("    (100 MiB body; peak RSS grew %ld KiB)\n", grew_kb);
            ZU_CHECK(grew_kb < 16 * 1024);
        }
        zu_sink_free(d);
        zu_free(steps);
        zu_free(page);
    }

    ZU_CASE("§27: 100 MB to a FILE sink is also constant-memory");
    {
        enum { CHUNK = 64u * 1024u, STEPS = 1600 };
        const uint64_t total = (uint64_t)CHUNK * STEPS;
        const char *path = "zu_test_dl_big.bin";
        char *page = (char *)zu_alloc(CHUNK);
        zu_mock_step *steps = (zu_mock_step *)zu_alloc(sizeof(zu_mock_step) * STEPS);
        zu_sink *f;
        struct rusage before, after;
        long grew_kb;
        int i;

        remove(path);
        f = zu_sink_file(path, &e);
        ZU_CHECK(page && steps && f);
        if (page && steps && f) {
            memset(page, 'y', CHUNK);
            for (i = 0; i < STEPS; i++) {
                steps[i].kind = ZU_MOCK_DATA; steps[i].data = page;
                steps[i].len = CHUNK; steps[i].code = ZU_OK;
            }
            zu_headers_init(&h);
            getrusage(RUSAGE_SELF, &before);
            ZU_CHECK_EQ_INT(run_body(steps, STEPS, ZU_FRAME_LENGTH, total, f,
                                     &h, 1, total + 1, &e), ZU_OK);
            ZU_CHECK_EQ_INT(zu_sink_finish(f, &e), ZU_OK);
            getrusage(RUSAGE_SELF, &after);
            zu_headers_free(&h);
#if defined(__APPLE__)
            grew_kb = (long)((after.ru_maxrss - before.ru_maxrss) / 1024);
#else
            grew_kb = (long)(after.ru_maxrss - before.ru_maxrss);
#endif
            if (grew_kb < 0) grew_kb = 0;
            printf("    (100 MiB to disk; peak RSS grew %ld KiB)\n", grew_kb);
            ZU_CHECK(grew_kb < 16 * 1024);
        }
        zu_sink_free(f);
        remove(path);
        zu_free(steps);
        zu_free(page);
    }

    /* The control. Without it the two assertions above are unfalsifiable:
     * "RSS did not grow" is also what you measure when the measurement does
     * not work, when the mock never delivered the body, or when ru_maxrss is
     * not wired up on this platform. Sending the SAME 100 MiB somewhere that
     * genuinely keeps it must move the number. */
    ZU_CASE("§27: the RSS measurement detects accumulation (control)");
    {
        enum { CHUNK = 64u * 1024u, STEPS = 1600 };
        const uint64_t total = (uint64_t)CHUNK * STEPS;
        char *page = (char *)zu_alloc(CHUNK);
        zu_mock_step *steps = (zu_mock_step *)zu_alloc(sizeof(zu_mock_step) * STEPS);
        zu_buffer keep;
        zu_sink sink;
        struct rusage before, after;
        long grew_kb;
        int i;

        ZU_CHECK(page && steps);
        ZU_CHECK(zu_buf_init(&keep, CHUNK, (size_t)total + CHUNK));
        if (page && steps) {
            memset(page, 'z', CHUNK);
            for (i = 0; i < STEPS; i++) {
                steps[i].kind = ZU_MOCK_DATA; steps[i].data = page;
                steps[i].len = CHUNK; steps[i].code = ZU_OK;
            }
            zu_sink_memory_init(&sink, &keep);
            zu_headers_init(&h);
            getrusage(RUSAGE_SELF, &before);
            ZU_CHECK_EQ_INT(run_body(steps, STEPS, ZU_FRAME_LENGTH, total,
                                     &sink, &h, 1, total + 1, &e), ZU_OK);
            getrusage(RUSAGE_SELF, &after);
            zu_headers_free(&h);
#if defined(__APPLE__)
            grew_kb = (long)((after.ru_maxrss - before.ru_maxrss) / 1024);
#else
            grew_kb = (long)(after.ru_maxrss - before.ru_maxrss);
#endif
            if (grew_kb < 0) grew_kb = 0;
            printf("    (100 MiB kept in memory; peak RSS grew %ld KiB)\n", grew_kb);
            ZU_CHECK(keep.len == total);
            /* Well above the 16 MiB the streaming cases must stay under. */
            ZU_CHECK(grew_kb > 32 * 1024);
        }
        zu_buf_free(&keep);
        zu_free(steps);
        zu_free(page);
    }
#endif

    /* --- §35.2 cipher-suite names -------------------------------------- */

    ZU_CASE("§35.2: suite codes map to names, unknown ones do not");
    {
        /* The three the numeric backends see most, one per family. */
        ZU_CHECK(streq(zu_tls_cipher_name(0x1303), "TLS_CHACHA20_POLY1305_SHA256"));
        ZU_CHECK(streq(zu_tls_cipher_name(0xCCA9), "ECDHE-ECDSA-CHACHA20-POLY1305"));
        ZU_CHECK(streq(zu_tls_cipher_name(0xC02B), "ECDHE-ECDSA-AES128-GCM-SHA256"));
        ZU_CHECK(streq(zu_tls_cipher_name(0x009C), "AES128-GCM-SHA256"));
        /* An unknown code must be NULL rather than a wrong name: the caller
         * falls back to the hex, and a plausible-looking wrong answer about
         * which cipher secured a connection is worse than no answer. */
        ZU_CHECK(zu_tls_cipher_name(0x0000) == NULL);
        ZU_CHECK(zu_tls_cipher_name(0xFFFF) == NULL);
        ZU_CHECK(zu_tls_cipher_name(0x1399) == NULL);
    }

    /* --- §35 the trace buffer ------------------------------------------ */

    ZU_CASE("§35.3: every event has a name, and out-of-range does not crash");
    {
        int i;
        for (i = 0; i < ZU_EV_COUNT; i++)
            ZU_CHECK(zu_event_name((zu_event)i)[0] != '\0');
        ZU_CHECK(streq(zu_event_name(ZU_EV_DNS_START), "dns.start"));
        ZU_CHECK(streq(zu_event_name(ZU_EV_REQUEST_DONE), "request.done"));
        ZU_CHECK(streq(zu_event_name((zu_event)-1), "?"));
        ZU_CHECK(streq(zu_event_name((zu_event)999), "?"));
    }

    ZU_CASE("§35.1: a phase that did not happen is -1, not 0");
    {
        zu_timings t;
        zu_timings_init(&t);
        /* Zero would claim the phase was instantaneous. A pooled connection
         * has no dns time and an http:// request has no tls time, and both
         * need to be distinguishable from "too fast to measure". */
        ZU_CHECK_EQ_INT((int)t.dns, -1);
        ZU_CHECK_EQ_INT((int)t.connect, -1);
        ZU_CHECK_EQ_INT((int)t.tls, -1);
        ZU_CHECK_EQ_INT((int)t.total, -1);
        ZU_CHECK(t.body_bytes_wire == 0);
    }

    ZU_CASE("§35: a NULL trace is a no-op, which is what makes the seam free");
    {
        /* Every zu_trace_add() in the connect and handshake paths passes a
         * possibly-NULL pointer. If this crashed, tracing could not be
         * optional. */
        zu_trace_add(NULL, ZU_EV_DNS_START, "x", 1);
        ZU_CHECK_EQ_INT((int)zu_trace_elapsed(NULL), -1);
    }

    ZU_CASE("§35: the trace is bounded and reports what it dropped");
    {
        zu_trace *t = (zu_trace *)zu_alloc(sizeof *t);
        int i;
        ZU_CHECK(t != NULL);
        if (t) {
            zu_trace_init(t);
            for (i = 0; i < ZU_TRACE_MAX + 25; i++)
                zu_trace_add(t, ZU_EV_BODY_CHUNK, "chunk", (uint64_t)i);
            /* A body.chunk per read means a large download would otherwise
             * grow this without bound. Silently stopping would read as a
             * request that silently stopped, so the overflow is counted. */
            ZU_CHECK_EQ_INT((int)t->n, ZU_TRACE_MAX);
            ZU_CHECK_EQ_INT(t->dropped, 25);
            ZU_CHECK(streq(t->ev[0].detail, "chunk"));
        }
        zu_free(t);
    }

    ZU_CASE("§35: a NULL detail is stored as empty, not as a stray pointer");
    {
        zu_trace *t = (zu_trace *)zu_alloc(sizeof *t);
        ZU_CHECK(t != NULL);
        if (t) {
            zu_trace_init(t);
            zu_trace_add(t, ZU_EV_REQUEST_DONE, NULL, 200);
            ZU_CHECK_EQ_INT((int)t->n, 1);
            ZU_CHECK(t->ev[0].detail[0] == '\0');
            ZU_CHECK(t->ev[0].n == 200);
        }
        zu_free(t);
    }

    ZU_CASE("no leaks across the suite");
    {
        zu_alloc_stats end;
        zu_alloc_stats_get(&end);
        ZU_CHECK_EQ_INT(end.live_blocks, 0);
    }
}

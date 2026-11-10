/* Response body streaming and sinks — design §27, §21, §19.5.
 *
 * All of it on the mock stream, which is the point of S17 having split
 * zuh_body.c out of the engine: the guarantee under test is "memory does not
 * grow with the body", and proving that needs a 100 MB response, which is
 * exactly the thing you cannot ask a real server for on every CI run.
 */
/* symlink() and getpid() are POSIX; -std=c99 hides them without this, as it
 * does in src/ (tools/check-feature-macros). Before every system header. */
#if !defined(_WIN32)
#  if defined(__APPLE__)
#    define _DARWIN_C_SOURCE
#  else
#    define _POSIX_C_SOURCE 200112L
#  endif
#endif
#include "zuh_test.h"
#include "zuh_body.h"
#include "zuh_sink.h"
#include "zuh_mock_stream.h"
#include "zuh_tls.h"
#include "zuh_trace.h"
#include "zuh_alloc.h"
#include "zuh_fork.h"
#include <string.h>
#include <stdio.h>
#include <zlib.h>

#if defined(ZUH_POSIX)
#  include <sys/resource.h>
#  include <unistd.h>
#endif

void suite_body(void);

static int streq(const char *a, const char *b) { return a && b && strcmp(a, b) == 0; }

static zuh_deadline forever(void) { return zuh_deadline_in(60000); }

/* Drive one body through a pipe into `sink` and return the status. */
static zuh_code run_body(const zuh_mock_step *steps, size_t nsteps,
                        zuh_frame_kind kind, uint64_t length,
                        zuh_sink *sink, zuh_headers *h, int no_decode,
                        uint64_t max_body, zuh_error *err) {
    zuh_stream *s = zuh_mock_stream_new(steps, nsteps, 0, 0);
    zuh_body_pipe p;
    zuh_framing fr;
    zuh_code rc;

    if (!s) return ZUH_ERR_NOMEM;
    fr.kind = kind; fr.length = length; fr.poolable = 1;

    rc = zuh_body_pipe_init(&p, sink, h, no_decode, max_body, err);
    if (rc == ZUH_OK)
        rc = zuh_body_read(s, &fr, &p, NULL, 0, forever(), err);
    zuh_body_pipe_free(&p);
    zuh_stream_free(s);
    return rc;
}

/* run_body() with every read cut to at most `max_read` bytes (0: none). */
static zuh_code run_body_split(const zuh_mock_step *steps, size_t nsteps,
                               zuh_frame_kind kind, uint64_t length, size_t max_read,
                               zuh_sink *sink, zuh_headers *h, uint64_t max_body,
                               zuh_error *err) {
    zuh_stream *s = zuh_mock_stream_new(steps, nsteps, max_read, 0);
    zuh_body_pipe p;
    zuh_framing fr;
    zuh_code rc;
    if (!s) return ZUH_ERR_NOMEM;
    fr.kind = kind; fr.length = length; fr.poolable = 1;
    rc = zuh_body_pipe_init(&p, sink, h, 0, max_body, err);
    if (rc == ZUH_OK) rc = zuh_body_read(s, &fr, &p, NULL, 0, forever(), err);
    zuh_body_pipe_free(&p);
    zuh_stream_free(s);
    return rc;
}

/* gzip of `n` bytes of `src`, appended to `out`. */
static int gzip_bytes(zuh_buffer *out, const void *src, size_t n) {
    unsigned char tmp[8192];
    z_stream s;
    int rc;
    memset(&s, 0, sizeof s);
    if (deflateInit2(&s, 9, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) return 0;
    s.next_in = (Bytef *)(uintptr_t)src; s.avail_in = (uInt)n;
    do {
        s.next_out = tmp; s.avail_out = sizeof tmp;
        rc = deflate(&s, Z_FINISH);
        if (rc == Z_STREAM_ERROR || !zuh_buf_append(out, tmp, sizeof tmp - s.avail_out)) {
            deflateEnd(&s);
            return 0;
        }
    } while (rc != Z_STREAM_END);
    deflateEnd(&s);
    return 1;
}

/* gzip of `n` zero bytes, streamed through deflate so the input is never held:
 * 100 MB of zeros is about 100 KB, a ratio near deflate's ceiling of ~1030:1. */
static int gzip_zeros(zuh_buffer *out, uint64_t n) {
    static unsigned char zeros[65536];
    unsigned char chunk[65536];
    z_stream s;
    int flush, rc;
    memset(&s, 0, sizeof s);
    if (deflateInit2(&s, 9, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) return 0;
    do {
        uInt take = n > sizeof zeros ? (uInt)sizeof zeros : (uInt)n;
        n -= take;
        flush = n ? Z_NO_FLUSH : Z_FINISH;
        s.next_in = zeros; s.avail_in = take;
        do {
            s.next_out = chunk; s.avail_out = sizeof chunk;
            rc = deflate(&s, flush);
            if (rc == Z_STREAM_ERROR
                || !zuh_buf_append(out, chunk, sizeof chunk - s.avail_out)) {
                deflateEnd(&s);
                return 0;
            }
        } while (s.avail_out == 0);
    } while (flush != Z_FINISH);
    deflateEnd(&s);
    return rc == Z_STREAM_END;
}

void suite_body(void) {
    zuh_error e;
    zuh_headers h;
    size_t pl;

    /* --- the sinks themselves ---------------------------------------- */

    ZUH_CASE("§27: a memory sink accumulates exactly what it is given");
    {
        zuh_buffer b;
        zuh_sink sink;
        ZUH_CHECK(zuh_buf_init(&b, 8, 1 << 20));
        zuh_sink_memory_init(&sink, &b);
        ZUH_CHECK_EQ_INT(zuh_sink_write(&sink, "abc", 3, &e), ZUH_OK);
        ZUH_CHECK_EQ_INT(zuh_sink_write(&sink, "de", 2, &e), ZUH_OK);
        ZUH_CHECK_EQ_INT((int)b.len, 5);
        ZUH_CHECK(memcmp(b.data, "abcde", 5) == 0);
        ZUH_CHECK_EQ_INT((int)sink.written, 5);
        /* A zero-length write is not an error and must not be counted. */
        ZUH_CHECK_EQ_INT(zuh_sink_write(&sink, "", 0, &e), ZUH_OK);
        ZUH_CHECK_EQ_INT((int)sink.written, 5);
        zuh_buf_free(&b);
    }

    ZUH_CASE("§19.5: a discard sink counts without keeping");
    {
        zuh_sink *d = zuh_sink_discard();
        ZUH_CHECK(d != NULL);
        ZUH_CHECK_EQ_INT(zuh_sink_write(d, "12345", 5, &e), ZUH_OK);
        ZUH_CHECK_EQ_INT((int)d->written, 5);
        zuh_sink_free(d);
    }

    /* --- §27.1 atomic file writes ------------------------------------- */

    ZUH_CASE("§27.1: a finished download appears at the target path");
    {
        const char *path = "zu_test_dl_ok.bin";
        zuh_sink *f;
        FILE *fp;
        char buf[16];
        size_t n;

        remove(path);
        f = zuh_sink_file(path, &e);
        ZUH_CHECK(f != NULL);
        /* Nothing at the destination until finish(): that IS the guarantee. */
        ZUH_CHECK(fopen(path, "rb") == NULL);
        ZUH_CHECK_EQ_INT(zuh_sink_write(f, "hello", 5, &e), ZUH_OK);
        ZUH_CHECK(fopen(path, "rb") == NULL);
        ZUH_CHECK_EQ_INT(zuh_sink_finish(f, &e), ZUH_OK);
        zuh_sink_free(f);

        fp = fopen(path, "rb");
        ZUH_CHECK(fp != NULL);
        if (fp) {
            n = fread(buf, 1, sizeof buf, fp);
            fclose(fp);
            ZUH_CHECK_EQ_INT((int)n, 5);
            ZUH_CHECK(memcmp(buf, "hello", 5) == 0);
        }
        remove(path);
    }

    ZUH_CASE("§27.1: an aborted download leaves NOTHING at the target path");
    {
        const char *path = "zu_test_dl_abort.bin";
        zuh_sink *f;
        const char *tmp;
        char tmpcopy[256];

        remove(path);
        f = zuh_sink_file(path, &e);
        ZUH_CHECK(f != NULL);
        tmp = zuh_sink_file_tmp_path(f);
        ZUH_CHECK(tmp != NULL);
        if (tmp) { strncpy(tmpcopy, tmp, sizeof tmpcopy - 1); tmpcopy[sizeof tmpcopy - 1] = 0; }

        ZUH_CHECK_EQ_INT(zuh_sink_write(f, "partial", 7, &e), ZUH_OK);
        zuh_sink_abort(f);
        zuh_sink_free(f);

        /* Neither the destination nor the temporary file survives. The
         * second half matters as much as the first: a leftover .zudl beside
         * every failed download is its own bug report. */
        ZUH_CHECK(fopen(path, "rb") == NULL);
        ZUH_CHECK(fopen(tmpcopy, "rb") == NULL);
    }

    ZUH_CASE("§27.1: an abandoned download cleans up even without abort()");
    {
        const char *path = "zu_test_dl_drop.bin";
        zuh_sink *f;
        remove(path);
        f = zuh_sink_file(path, &e);
        ZUH_CHECK(f != NULL);
        ZUH_CHECK_EQ_INT(zuh_sink_write(f, "partial", 7, &e), ZUH_OK);
        zuh_sink_free(f);                 /* destroy without finish or abort */
        ZUH_CHECK(fopen(path, "rb") == NULL);
    }

    ZUH_CASE("§27.1: finishing replaces an existing file");
    {
        const char *path = "zu_test_dl_replace.bin";
        zuh_sink *f;
        FILE *fp = fopen(path, "wb");
        char buf[16];
        size_t n;
        if (fp) { fwrite("old", 1, 3, fp); fclose(fp); }

        f = zuh_sink_file(path, &e);
        ZUH_CHECK(f != NULL);
        ZUH_CHECK_EQ_INT(zuh_sink_write(f, "new!", 4, &e), ZUH_OK);
        ZUH_CHECK_EQ_INT(zuh_sink_finish(f, &e), ZUH_OK);
        zuh_sink_free(f);

        fp = fopen(path, "rb");
        ZUH_CHECK(fp != NULL);
        if (fp) { n = fread(buf, 1, sizeof buf, fp); fclose(fp);
                  ZUH_CHECK_EQ_INT((int)n, 4);
                  ZUH_CHECK(memcmp(buf, "new!", 4) == 0); }
        remove(path);
    }

    ZUH_CASE("§27.1: the temporary file is created, never opened: nothing at its name is written through");
    {
        /* The temporary name was predictable (<path>.zudl<pid>) and opened
         * with fopen("wb"), which truncates a file already there and follows
         * a symlink planted there — writing the download into whatever the
         * link named. Creation is now exclusive, and a taken name moves the
         * sink on to another. */
        const char *path = "zu_test_dl_excl.bin";
        char base[256];
        zuh_sink *f1, *f2;
        FILE *fp;
        char buf[16];
        size_t n;
        snprintf(base, sizeof base, "%s.zudl%ld", path, (long)zuh_pid_current());
        fp = fopen(base, "wb");
        if (fp) { fwrite("KEEP", 1, 4, fp); fclose(fp); }
        f1 = zuh_sink_file(path, &e);
        f2 = zuh_sink_file(path, &e);
        ZUH_CHECK(f1 != NULL && f2 != NULL);
        if (f1 && f2) {
            ZUH_CHECK(strcmp(zuh_sink_file_tmp_path(f1), base) != 0);
            ZUH_CHECK(strcmp(zuh_sink_file_tmp_path(f1), zuh_sink_file_tmp_path(f2)) != 0);
            ZUH_CHECK_EQ_INT(zuh_sink_write(f1, "new!", 4, &e), ZUH_OK);
            ZUH_CHECK_EQ_INT(zuh_sink_finish(f1, &e), ZUH_OK);
        }
        zuh_sink_free(f1); zuh_sink_free(f2);
        fp = fopen(base, "rb");                       /* the squatter survives */
        ZUH_CHECK(fp != NULL);
        if (fp) { n = fread(buf, 1, sizeof buf, fp); fclose(fp);
                  ZUH_CHECK(n == 4 && memcmp(buf, "KEEP", 4) == 0); }
        remove(base); remove(path);
#if defined(ZUH_POSIX)
        {
            const char *victim = "zu_test_dl_victim.txt";
            fp = fopen(victim, "wb");
            if (fp) { fwrite("KEEP ME", 1, 7, fp); fclose(fp); }
            ZUH_CHECK_EQ_INT(symlink(victim, base), 0);
            f1 = zuh_sink_file(path, &e);
            ZUH_CHECK(f1 != NULL);
            if (f1) {
                ZUH_CHECK_EQ_INT(zuh_sink_write(f1, "OK", 2, &e), ZUH_OK);
                ZUH_CHECK_EQ_INT(zuh_sink_finish(f1, &e), ZUH_OK);
            }
            zuh_sink_free(f1);
            fp = fopen(victim, "rb");
            ZUH_CHECK(fp != NULL);
            if (fp) { n = fread(buf, 1, sizeof buf, fp); fclose(fp);
                      ZUH_CHECK(n == 7 && memcmp(buf, "KEEP ME", 7) == 0); }
            {
                char lbuf[64];
                ZUH_CHECK(readlink(path, lbuf, sizeof lbuf) < 0);   /* a file, not a link */
            }
            remove(base); remove(victim); remove(path);
        }
#endif
    }

    ZUH_CASE("§27.1: a commit that fails keeps the previous download (D-53)");
    {
        /* The destination was removed before the rename, on every platform,
         * so a rename that then failed destroyed the last good file. */
        const char *path = "zu_test_dl_keep.bin";
        zuh_sink *f;
        FILE *fp = fopen(path, "wb");
        char buf[16];
        size_t n;
        if (fp) { fwrite("old", 1, 3, fp); fclose(fp); }
        f = zuh_sink_file(path, &e);
        ZUH_CHECK(f != NULL);
        if (f) {
            /* The fault: point the sink at a temporary name that does not
             * exist, so the rename itself fails. Deleting the real temporary
             * file would be the obvious injection, but Windows refuses to
             * delete a file that is still open, and the commit then simply
             * succeeds. The real file is removed afterwards. */
            char real_tmp[512];
            char *t = (char *)(uintptr_t)zuh_sink_file_tmp_path(f);
            snprintf(real_tmp, sizeof real_tmp, "%s", t);
            t[strlen(t) - 1] = (char)(t[strlen(t) - 1] ^ 1);
            ZUH_CHECK_EQ_INT(zuh_sink_write(f, "new!", 4, &e), ZUH_OK);
            ZUH_CHECK_EQ_INT(zuh_sink_finish(f, &e), ZUH_ERR_IO);
            zuh_sink_free(f);
            remove(real_tmp);
        }
        fp = fopen(path, "rb");
        ZUH_CHECK(fp != NULL);
        if (fp) { n = fread(buf, 1, sizeof buf, fp); fclose(fp);
                  ZUH_CHECK(n == 3 && memcmp(buf, "old", 3) == 0); }
        remove(path);
    }

    ZUH_CASE("D-69: a bomb fails on the ratio, with the absolute cap out of the way");
    {
        /* 100 MB of zeros as ~100 KB of gzip. max_body is raised to 1 GiB so the
         * only limit that can fire is the ratio (§21.4): it must, and early --
         * after kilobytes of output, not the 100 MB the absolute cap allows. */
        zuh_buffer src, b; zuh_sink sink; zuh_mock_step step;
        const uint64_t big = (uint64_t)1 << 30;
        ZUH_CHECK(zuh_buf_init(&src, 1 << 16, (size_t)-1));
        ZUH_CHECK(gzip_zeros(&src, (uint64_t)100 * 1024 * 1024));
        ZUH_CHECK(zuh_buf_init(&b, 1 << 16, (size_t)-1));
        zuh_sink_memory_init(&sink, &b);
        zuh_headers_init(&h);
        ZUH_CHECK(zuh_headers_add_str(&h, "Content-Encoding", "gzip") == ZUH_OK);
        step.kind = ZUH_MOCK_DATA; step.data = src.data; step.len = src.len; step.code = ZUH_OK;
        ZUH_CHECK_EQ_INT(run_body(&step, 1, ZUH_FRAME_LENGTH, src.len, &sink, &h, 0,
                                 big, &e), ZUH_ERR_BODY_LIMIT);
        ZUH_CHECK(strstr(e.message, "ratio") != NULL);
        ZUH_CHECK(b.len < 1024 * 1024);
        zuh_headers_free(&h);
        zuh_buf_free(&b);
        zuh_buf_free(&src);
    }

    ZUH_CASE("#212: max_body caps decoded bytes under chunked framing too");
    {
        /* gzip of 5 zeros is ~23 bytes. With max_body = 5 the decoded body
         * fits exactly, and must arrive under either framing: the chunk
         * decoder used to be given max_body as its own cap, which it applied
         * to the de-chunked but still COMPRESSED payload, so the chunked
         * response failed where the Content-Length one succeeded. */
        zuh_buffer src, wire, b; zuh_sink sink; zuh_mock_step step;
        char hdr[32];
        int k;
        ZUH_CHECK(zuh_buf_init(&src, 64, (size_t)-1));
        ZUH_CHECK(gzip_zeros(&src, 5));
        ZUH_CHECK(src.len > 5);
        ZUH_CHECK(zuh_buf_init(&wire, 128, (size_t)-1));
        snprintf(hdr, sizeof hdr, "%lx\r\n", (unsigned long)src.len);
        ZUH_CHECK(zuh_buf_append(&wire, hdr, strlen(hdr)));
        ZUH_CHECK(zuh_buf_append(&wire, src.data, src.len));
        ZUH_CHECK(zuh_buf_append(&wire, "\r\n0\r\n\r\n", 7));
        for (k = 0; k < 2; k++) {
            const zuh_buffer *body = k ? &wire : &src;
            ZUH_CHECK(zuh_buf_init(&b, 16, (size_t)-1));
            zuh_sink_memory_init(&sink, &b);
            zuh_headers_init(&h);
            ZUH_CHECK(zuh_headers_add_str(&h, "Content-Encoding", "gzip") == ZUH_OK);
            step.kind = ZUH_MOCK_DATA; step.data = body->data; step.len = body->len;
            step.code = ZUH_OK;
            zuh_error_clear(&e);
            ZUH_CHECK_EQ_INT(run_body(&step, 1, k ? ZUH_FRAME_CHUNKED : ZUH_FRAME_LENGTH,
                                     body->len, &sink, &h, 0, 5, &e), ZUH_OK);
            ZUH_CHECK_EQ_INT((int)b.len, 5);
            zuh_headers_free(&h);
            zuh_buf_free(&b);
        }
        /* The cap still binds the decoded bytes: one byte less fails. */
        ZUH_CHECK(zuh_buf_init(&b, 16, (size_t)-1));
        zuh_sink_memory_init(&sink, &b);
        zuh_headers_init(&h);
        ZUH_CHECK(zuh_headers_add_str(&h, "Content-Encoding", "gzip") == ZUH_OK);
        step.kind = ZUH_MOCK_DATA; step.data = wire.data; step.len = wire.len; step.code = ZUH_OK;
        ZUH_CHECK_EQ_INT(run_body(&step, 1, ZUH_FRAME_CHUNKED, wire.len, &sink, &h, 0, 4, &e),
                         ZUH_ERR_BODY_LIMIT);
        ZUH_CHECK(b.len <= 4);
        zuh_headers_free(&h);
        zuh_buf_free(&b);
        zuh_buf_free(&wire);
        zuh_buf_free(&src);
    }

    /* --- framing through the pipe ------------------------------------- */

    ZUH_CASE("a Content-Length body stops at the length, whatever else arrived");
    {
        static const zuh_mock_step steps[] = {
            { ZUH_MOCK_DATA, "HELLOandthenTHENEXTRESPONSE", 27, ZUH_OK }
        };
        zuh_buffer b; zuh_sink sink;
        ZUH_CHECK(zuh_buf_init(&b, 8, 1 << 20));
        zuh_sink_memory_init(&sink, &b);
        zuh_headers_init(&h);
        ZUH_CHECK_EQ_INT(run_body(steps, 1, ZUH_FRAME_LENGTH, 5, &sink, &h, 1,
                                 1u << 20, &e), ZUH_OK);
        ZUH_CHECK_EQ_INT((int)b.len, 5);
        ZUH_CHECK(memcmp(b.data, "HELLO", 5) == 0);
        zuh_headers_free(&h);
        zuh_buf_free(&b);
    }

    /* No ZUH_MOCK_WOULDBLOCK step here, deliberately. The stream contract is
     * that a read blocks until data, EOF or the deadline: zuh_net.c loops
     * internally on EWOULDBLOCK and never surfaces it, so a body reader that
     * handled it would be handling a case that cannot occur. Scripting one
     * would test the mock rather than the code. */
    ZUH_CASE("a body split across many reads arrives whole");
    {
        static const zuh_mock_step steps[] = {
            { ZUH_MOCK_DATA, "ab", 2, ZUH_OK },
            { ZUH_MOCK_DATA, "cd", 2, ZUH_OK },
            { ZUH_MOCK_DATA, "e",  1, ZUH_OK }
        };
        zuh_buffer b; zuh_sink sink;
        ZUH_CHECK(zuh_buf_init(&b, 8, 1 << 20));
        zuh_sink_memory_init(&sink, &b);
        zuh_headers_init(&h);
        ZUH_CHECK_EQ_INT(run_body(steps, 3, ZUH_FRAME_LENGTH, 5, &sink, &h, 1,
                                 1u << 20, &e), ZUH_OK);
        ZUH_CHECK_EQ_INT((int)b.len, 5);
        ZUH_CHECK(memcmp(b.data, "abcde", 5) == 0);
        zuh_headers_free(&h);
        zuh_buf_free(&b);
    }

    ZUH_CASE("§27.1: the body limit applies to a FILE sink, not only to memory");
    {
        static const zuh_mock_step steps[] = {
            { ZUH_MOCK_DATA, "0123456789", 10, ZUH_OK },
            { ZUH_MOCK_DATA, "0123456789", 10, ZUH_OK },
            { ZUH_MOCK_DATA, "0123456789", 10, ZUH_OK }
        };
        const char *path = "zu_test_dl_limit.bin";
        zuh_sink *f;
        remove(path);
        f = zuh_sink_file(path, &e);
        ZUH_CHECK(f != NULL);
        zuh_headers_init(&h);
        /* An unbounded download to disk is still a denial of service, just
         * against a different resource. */
        ZUH_CHECK_EQ_INT(run_body(steps, 3, ZUH_FRAME_UNTIL_CLOSE, 0, f, &h, 1,
                                 12, &e), ZUH_ERR_BODY_LIMIT);
        zuh_sink_abort(f);
        zuh_sink_free(f);
        ZUH_CHECK(fopen(path, "rb") == NULL);
        zuh_headers_free(&h);
    }

    ZUH_CASE("#210: malformed chunk framing raises, and the sink was handed no framing bytes");
    {
        /* What the caller got before the error is the test. A decoder error
         * left `len` at its input value, the wire length, and the reader fed
         * that much to the sink before looking at the result: a callback saw
         * the raw `X\r\nATTACK...` bytes, then the request raised. In one
         * read the decoded prefix is discarded too, since after an error no
         * output bytes of that call are valid; split across two reads, the
         * valid chunk was delivered by a call that succeeded and stays. */
        static const char bad[] = "X\r\nATTACK\r\n0\r\n\r\n";
        static const char lead[] = "3\r\nabc\r\nX\r\nATTACK\r\n0\r\n\r\n";
        static const zuh_mock_step one[]  = { { ZUH_MOCK_DATA, bad, sizeof bad - 1, ZUH_OK } };
        static const zuh_mock_step both[] = { { ZUH_MOCK_DATA, lead, sizeof lead - 1, ZUH_OK } };
        static const zuh_mock_step split[] = {
            { ZUH_MOCK_DATA, "3\r\nabc\r\n", 8, ZUH_OK },
            { ZUH_MOCK_DATA, bad, sizeof bad - 1, ZUH_OK } };
        const zuh_mock_step *sc[3] = { one, both, split };
        const size_t ns[3] = { 1, 1, 2 };
        const size_t want[3] = { 0, 0, 3 };
        int k;
        for (k = 0; k < 3; k++) {
            zuh_buffer b; zuh_sink sink;
            ZUH_CHECK(zuh_buf_init(&b, 8, 1 << 20));
            zuh_sink_memory_init(&sink, &b);
            zuh_headers_init(&h);
            zuh_error_clear(&e);
            ZUH_CHECK_EQ_INT(run_body(sc[k], ns[k], ZUH_FRAME_CHUNKED, 0, &sink, &h, 1,
                                     1u << 20, &e), ZUH_ERR_PARSE);
            ZUH_CHECK_EQ_INT((int)b.len, (int)want[k]);
            if (want[k]) ZUH_CHECK(memcmp(b.data, "abc", 3) == 0);
            zuh_headers_free(&h);
            zuh_buf_free(&b);
        }
    }

    ZUH_CASE("#211: repeated Content-Encoding fields are a stacked encoding, refused");
    {
        /* Two fields mean the body was encoded twice (RFC 9110 §8.4). The
         * pipe used to read the first field only, inflate once and then
         * remove both headers, handing back still-compressed bytes with the
         * evidence gone. One field still decodes; two are refused before any
         * byte is read, and the headers are left as the server sent them. */
        zuh_body_pipe p;
        zuh_headers_init(&h);
        ZUH_CHECK(zuh_headers_add_str(&h, "Content-Encoding", "gzip") == ZUH_OK);
        zuh_error_clear(&e);
        ZUH_CHECK_EQ_INT(zuh_body_pipe_init(&p, NULL, &h, 0, 0, &e), ZUH_OK);
        zuh_body_pipe_free(&p);
        zuh_headers_free(&h);

        zuh_headers_init(&h);
        ZUH_CHECK(zuh_headers_add_str(&h, "Content-Encoding", "gzip") == ZUH_OK);
        ZUH_CHECK(zuh_headers_add_str(&h, "content-encoding", "gzip") == ZUH_OK);
        zuh_error_clear(&e);
        ZUH_CHECK_EQ_INT(zuh_body_pipe_init(&p, NULL, &h, 0, 0, &e), ZUH_ERR_BODY_DECODE);
        ZUH_CHECK_EQ_INT((int)zuh_headers_count(&h, "Content-Encoding"), 2);
        zuh_body_pipe_free(&p);
        /* decode = FALSE asks for the wire bytes, which need no decoding. */
        zuh_error_clear(&e);
        ZUH_CHECK_EQ_INT(zuh_body_pipe_init(&p, NULL, &h, 1, 0, &e), ZUH_OK);
        zuh_body_pipe_free(&p);
        zuh_headers_free(&h);
    }

    /* --- §40: the cap is a BOUND, not a thing noticed afterwards ------- */

    ZUH_CASE("§40: the sink is never handed a byte past max_body");
    {
        /* Found by fuzz_body on its first seed, and reproducible from R: a
         * max_body of 1024 handed 1593 bytes to a user's callback. The old
         * check ran after a chunk had already been delivered, so it reported
         * the overrun correctly and far too late. A byte a caller has already
         * received cannot be un-received. */
        static const zuh_mock_step steps[] = {
            { ZUH_MOCK_DATA, "0123456789", 10, ZUH_OK },
            { ZUH_MOCK_DATA, "0123456789", 10, ZUH_OK },
            { ZUH_MOCK_DATA, "0123456789", 10, ZUH_OK }
        };
        zuh_sink *d;
        int cap;
        for (cap = 1; cap <= 30; cap++) {
            zuh_code rc;
            d = zuh_sink_discard();
            ZUH_CHECK(d != NULL);
            zuh_headers_init(&h);
            rc = run_body(steps, 3, ZUH_FRAME_UNTIL_CLOSE, 0, d, &h, 1,
                          (uint64_t)cap, &e);
            /* Exactly the promise §40 makes, at every cap around the read
             * boundaries — not just at a convenient one. And the refusal
             * itself, with what was delivered before it, so a reader that
             * delivers nothing cannot pass (#196). */
            ZUH_CHECK(d->written <= (uint64_t)cap);
            ZUH_CHECK_EQ_INT(rc, cap < 30 ? ZUH_ERR_BODY_LIMIT : ZUH_OK);
            if (cap >= 10) ZUH_CHECK(d->written >= 10);
            zuh_headers_free(&h);
            zuh_sink_free(d);
        }
    }

    ZUH_CASE("§40: a body exactly at the cap is delivered, not refused");
    {
        static const zuh_mock_step steps[] = {
            { ZUH_MOCK_DATA, "0123456789", 10, ZUH_OK }
        };
        zuh_buffer b; zuh_sink sink;
        ZUH_CHECK(zuh_buf_init(&b, 8, 1 << 20));
        zuh_sink_memory_init(&sink, &b);
        zuh_headers_init(&h);
        /* Off-by-one in the other direction: refusing a body that fits would
         * make max_body mean "one less than it says". */
        ZUH_CHECK_EQ_INT(run_body(steps, 1, ZUH_FRAME_LENGTH, 10, &sink, &h, 1,
                                 10, &e), ZUH_OK);
        ZUH_CHECK_EQ_INT((int)b.len, 10);
        zuh_headers_free(&h);
        zuh_buf_free(&b);
    }

    /* --- §27: memory does not grow with the body ---------------------- */

#if defined(ZUH_POSIX)
    ZUH_CASE("§27: a 100 MB body streams in constant memory (S17 criterion)");
    {
        /* 1600 steps over one 64 KiB buffer: the mock hands out the same page
         * repeatedly, so the TEST does not need 100 MB either. */
        enum { CHUNK = 64u * 1024u, STEPS = 1600 };
        const uint64_t total = (uint64_t)CHUNK * STEPS;   /* 100 MiB */
        char *page = (char *)zuh_alloc(CHUNK);
        zuh_mock_step *steps = (zuh_mock_step *)zuh_alloc(sizeof(zuh_mock_step) * STEPS);
        zuh_sink *d = zuh_sink_discard();
        struct rusage before, after;
        long grew_kb;
        int i;

        ZUH_CHECK(page && steps && d);
        if (page && steps && d) {
            memset(page, 'x', CHUNK);
            for (i = 0; i < STEPS; i++) {
                steps[i].kind = ZUH_MOCK_DATA;
                steps[i].data = page;
                steps[i].len  = CHUNK;
                steps[i].code = ZUH_OK;
            }
            zuh_headers_init(&h);
            getrusage(RUSAGE_SELF, &before);
            ZUH_CHECK_EQ_INT(run_body(steps, STEPS, ZUH_FRAME_LENGTH, total, d,
                                     &h, 1, total + 1, &e), ZUH_OK);
            getrusage(RUSAGE_SELF, &after);
            zuh_headers_free(&h);

            /* Every byte arrived... */
            ZUH_CHECK(d->written == total);

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
            ZUH_CHECK(grew_kb < 16 * 1024);
        }
        zuh_sink_free(d);
        zuh_free(steps);
        zuh_free(page);
    }

    ZUH_CASE("§27: 100 MB to a FILE sink is also constant-memory");
    {
        enum { CHUNK = 64u * 1024u, STEPS = 1600 };
        const uint64_t total = (uint64_t)CHUNK * STEPS;
        const char *path = "zu_test_dl_big.bin";
        char *page = (char *)zuh_alloc(CHUNK);
        zuh_mock_step *steps = (zuh_mock_step *)zuh_alloc(sizeof(zuh_mock_step) * STEPS);
        zuh_sink *f;
        struct rusage before, after;
        long grew_kb;
        int i;

        remove(path);
        f = zuh_sink_file(path, &e);
        ZUH_CHECK(page && steps && f);
        if (page && steps && f) {
            memset(page, 'y', CHUNK);
            for (i = 0; i < STEPS; i++) {
                steps[i].kind = ZUH_MOCK_DATA; steps[i].data = page;
                steps[i].len = CHUNK; steps[i].code = ZUH_OK;
            }
            zuh_headers_init(&h);
            getrusage(RUSAGE_SELF, &before);
            ZUH_CHECK_EQ_INT(run_body(steps, STEPS, ZUH_FRAME_LENGTH, total, f,
                                     &h, 1, total + 1, &e), ZUH_OK);
            ZUH_CHECK_EQ_INT(zuh_sink_finish(f, &e), ZUH_OK);
            getrusage(RUSAGE_SELF, &after);
            zuh_headers_free(&h);
#if defined(__APPLE__)
            grew_kb = (long)((after.ru_maxrss - before.ru_maxrss) / 1024);
#else
            grew_kb = (long)(after.ru_maxrss - before.ru_maxrss);
#endif
            if (grew_kb < 0) grew_kb = 0;
            printf("    (100 MiB to disk; peak RSS grew %ld KiB)\n", grew_kb);
            ZUH_CHECK(grew_kb < 16 * 1024);
        }
        zuh_sink_free(f);
        remove(path);
        zuh_free(steps);
        zuh_free(page);
    }

    /* The control. Without it the two assertions above are unfalsifiable:
     * "RSS did not grow" is also what you measure when the measurement does
     * not work, when the mock never delivered the body, or when ru_maxrss is
     * not wired up on this platform. Sending the SAME 100 MiB somewhere that
     * genuinely keeps it must move the number. */
    ZUH_CASE("§27: the RSS measurement detects accumulation (control)");
    {
        enum { CHUNK = 64u * 1024u, STEPS = 1600 };
        const uint64_t total = (uint64_t)CHUNK * STEPS;
        char *page = (char *)zuh_alloc(CHUNK);
        zuh_mock_step *steps = (zuh_mock_step *)zuh_alloc(sizeof(zuh_mock_step) * STEPS);
        zuh_buffer keep;
        zuh_sink sink;
        struct rusage before, after;
        long grew_kb;
        int i;

        ZUH_CHECK(page && steps);
        ZUH_CHECK(zuh_buf_init(&keep, CHUNK, (size_t)total + CHUNK));
        if (page && steps) {
            memset(page, 'z', CHUNK);
            for (i = 0; i < STEPS; i++) {
                steps[i].kind = ZUH_MOCK_DATA; steps[i].data = page;
                steps[i].len = CHUNK; steps[i].code = ZUH_OK;
            }
            zuh_sink_memory_init(&sink, &keep);
            zuh_headers_init(&h);
            getrusage(RUSAGE_SELF, &before);
            ZUH_CHECK_EQ_INT(run_body(steps, STEPS, ZUH_FRAME_LENGTH, total,
                                     &sink, &h, 1, total + 1, &e), ZUH_OK);
            getrusage(RUSAGE_SELF, &after);
            zuh_headers_free(&h);
#if defined(__APPLE__)
            grew_kb = (long)((after.ru_maxrss - before.ru_maxrss) / 1024);
#else
            grew_kb = (long)(after.ru_maxrss - before.ru_maxrss);
#endif
            if (grew_kb < 0) grew_kb = 0;
            printf("    (100 MiB kept in memory; peak RSS grew %ld KiB)\n", grew_kb);
            ZUH_CHECK(keep.len == total);
            /* Well above the 16 MiB the streaming cases must stay under. */
            ZUH_CHECK(grew_kb > 32 * 1024);
        }
        zuh_buf_free(&keep);
        zuh_free(steps);
        zuh_free(page);
    }
#endif

    /* --- §35.2 cipher-suite names -------------------------------------- */

    ZUH_CASE("§35.2: suite codes map to names, unknown ones do not");
    {
        /* The three the numeric backends see most, one per family. */
        ZUH_CHECK(streq(zuh_tls_cipher_name(0x1303), "TLS_CHACHA20_POLY1305_SHA256"));
        ZUH_CHECK(streq(zuh_tls_cipher_name(0xCCA9), "ECDHE-ECDSA-CHACHA20-POLY1305"));
        ZUH_CHECK(streq(zuh_tls_cipher_name(0xC02B), "ECDHE-ECDSA-AES128-GCM-SHA256"));
        ZUH_CHECK(streq(zuh_tls_cipher_name(0x009C), "AES128-GCM-SHA256"));
        /* An unknown code must be NULL rather than a wrong name: the caller
         * falls back to the hex, and a plausible-looking wrong answer about
         * which cipher secured a connection is worse than no answer. */
        ZUH_CHECK(zuh_tls_cipher_name(0x0000) == NULL);
        ZUH_CHECK(zuh_tls_cipher_name(0xFFFF) == NULL);
        ZUH_CHECK(zuh_tls_cipher_name(0x1399) == NULL);
    }

    /* --- §35 the trace buffer ------------------------------------------ */

    ZUH_CASE("§35.3: every event has a name, and out-of-range does not crash");
    {
        int i;
        for (i = 0; i < ZUH_EV_COUNT; i++)
            ZUH_CHECK(zuh_event_name((zuh_event)i)[0] != '\0');
        ZUH_CHECK(streq(zuh_event_name(ZUH_EV_DNS_START), "dns.start"));
        ZUH_CHECK(streq(zuh_event_name(ZUH_EV_REQUEST_DONE), "request.done"));
        ZUH_CHECK(streq(zuh_event_name((zuh_event)-1), "?"));
        ZUH_CHECK(streq(zuh_event_name((zuh_event)999), "?"));
    }

    ZUH_CASE("§35.1: a phase that did not happen is -1, not 0");
    {
        zuh_timings t;
        zuh_timings_init(&t);
        /* Zero would claim the phase was instantaneous. A pooled connection
         * has no dns time and an http:// request has no tls time, and both
         * need to be distinguishable from "too fast to measure". */
        ZUH_CHECK_EQ_INT((int)t.dns, -1);
        ZUH_CHECK_EQ_INT((int)t.connect, -1);
        ZUH_CHECK_EQ_INT((int)t.tls, -1);
        ZUH_CHECK_EQ_INT((int)t.total, -1);
        ZUH_CHECK(t.body_bytes_wire == 0);
    }

    ZUH_CASE("§35: a NULL trace is a no-op, which is what makes the seam free");
    {
        /* Every zuh_trace_add() in the connect and handshake paths passes a
         * possibly-NULL pointer. If this crashed, tracing could not be
         * optional. */
        zuh_trace_add(NULL, ZUH_EV_DNS_START, "x", 1);
        ZUH_CHECK_EQ_INT((int)zuh_trace_elapsed(NULL), -1);
    }

    ZUH_CASE("§35: the trace is bounded and reports what it dropped");
    {
        zuh_trace *t = (zuh_trace *)zuh_alloc(sizeof *t);
        int i;
        ZUH_CHECK(t != NULL);
        if (t) {
            zuh_trace_init(t);
            for (i = 0; i < ZUH_TRACE_MAX + 25; i++)
                zuh_trace_add(t, ZUH_EV_BODY_CHUNK, "chunk", (uint64_t)i);
            /* A body.chunk per read means a large download would otherwise
             * grow this without bound. Silently stopping would read as a
             * request that silently stopped, so the overflow is counted. */
            ZUH_CHECK_EQ_INT((int)t->n, ZUH_TRACE_MAX);
            ZUH_CHECK_EQ_INT(t->dropped, 25);
            ZUH_CHECK(streq(t->ev[0].detail, "chunk"));
        }
        zuh_free(t);
    }

    ZUH_CASE("§35: a NULL detail is stored as empty, not as a stray pointer");
    {
        zuh_trace *t = (zuh_trace *)zuh_alloc(sizeof *t);
        ZUH_CHECK(t != NULL);
        if (t) {
            zuh_trace_init(t);
            zuh_trace_add(t, ZUH_EV_REQUEST_DONE, NULL, 200);
            ZUH_CHECK_EQ_INT((int)t->n, 1);
            ZUH_CHECK(t->ev[0].detail[0] == '\0');
            ZUH_CHECK(t->ev[0].n == 200);
        }
        zuh_free(t);
    }

    /* #252: max_body is decoded bytes on every framing and encoding, so one
     * payload is accepted or refused alike under each, at the cap's edges
     * and at reads that split the framing and the gzip stream. #212 billed
     * compressed bytes under chunked framing; reverting it fails here. */
    ZUH_CASE("limits: max_body straddled under Content-Length, chunked and close, identity and gzip (#252)");
    for (pl = 0; pl < 2; pl++) {
        /* A compressible payload, and one gzip makes larger than itself: on
         * that one, billing compressed bytes refuses a body at the cap. */
        enum { N = 3000 };
        static unsigned char payload[N];
        static const zuh_frame_kind kinds[] = { ZUH_FRAME_LENGTH, ZUH_FRAME_CHUNKED, ZUH_FRAME_UNTIL_CLOSE };
        static const size_t splits[] = { 0, 1, 7 };
        zuh_buffer gz, wire, got;
        size_t i, enc, fk, sp, c;
        uint32_t x = 2463534242u;
        for (i = 0; i < N; i++) {
            x ^= x << 13; x ^= x >> 17; x ^= x << 5;
            payload[i] = pl ? (unsigned char)(x >> 24) : (unsigned char)(97u + i % 10u + (i / 100u) % 7u);
        }
        ZUH_CHECK(zuh_buf_init(&gz, 256, (size_t)-1));
        ZUH_CHECK(gzip_bytes(&gz, payload, N));
        ZUH_CHECK(gz.len > 32 && (pl ? gz.len > N : gz.len < N));
        for (enc = 0; enc < 2; enc++) {
            const unsigned char *body = enc ? gz.data : payload;
            size_t blen = enc ? gz.len : (size_t)N;
            for (fk = 0; fk < 3; fk++) {
                ZUH_CHECK(zuh_buf_init(&wire, 256, (size_t)-1));
                if (kinds[fk] == ZUH_FRAME_CHUNKED) {
                    /* Three chunks, so chunk boundaries fall inside the stream. */
                    size_t off = 0, part = blen / 3 + 1;
                    while (off < blen) {
                        char line[32];
                        size_t l = blen - off < part ? blen - off : part;
                        snprintf(line, sizeof line, "%lx\r\n", (unsigned long)l);
                        zuh_buf_append(&wire, line, strlen(line));
                        zuh_buf_append(&wire, body + off, l);
                        zuh_buf_append(&wire, "\r\n", 2);
                        off += l;
                    }
                    zuh_buf_append(&wire, "0\r\n\r\n", 5);
                } else {
                    zuh_buf_append(&wire, body, blen);
                }
                for (sp = 0; sp < sizeof splits / sizeof splits[0]; sp++) {
                    for (c = N - 1; c <= N + 1; c++) {
                        zuh_sink sink;
                        zuh_mock_step step;
                        zuh_code rc;
                        ZUH_CHECK(zuh_buf_init(&got, 256, (size_t)-1));
                        zuh_sink_memory_init(&sink, &got);
                        zuh_headers_init(&h);
                        if (enc) zuh_headers_add_str(&h, "Content-Encoding", "gzip");
                        step.kind = ZUH_MOCK_DATA; step.data = wire.data; step.len = wire.len;
                        step.code = ZUH_OK;
                        zuh_error_clear(&e);
                        rc = run_body_split(&step, 1, kinds[fk], blen, splits[sp], &sink, &h,
                                            (uint64_t)c, &e);
                        if (rc != (c < N ? ZUH_ERR_BODY_LIMIT : ZUH_OK))
                            printf("    %s, framing %lu, reads of %lu, cap %lu: code %d\n",
                                   enc ? "gzip" : "identity", (unsigned long)fk,
                                   (unsigned long)splits[sp], (unsigned long)c, (int)rc);
                        ZUH_CHECK_EQ_INT(rc, c < N ? ZUH_ERR_BODY_LIMIT : ZUH_OK);
                        /* What the sink got: never past the cap, always the
                         * payload's own first bytes, all of it on success. */
                        ZUH_CHECK(got.len <= c);
                        ZUH_CHECK(got.len == 0 || memcmp(got.data, payload, got.len) == 0);
                        if (rc == ZUH_OK) ZUH_CHECK_EQ_INT(got.len, N);
                        else ZUH_CHECK_EQ_INT(e.code, ZUH_ERR_BODY_LIMIT);
                        zuh_headers_free(&h);
                        zuh_buf_free(&got);
                    }
                }
                zuh_buf_free(&wire);
            }
        }
        zuh_buf_free(&gz);
    }

    /* #256: picohttpparser refuses a chunked body whose framing is at least
     * 100 KiB and more than three quarters of what it has read, so a
     * server cannot make the client parse framing forever. Its limit is
     * this package's limit, and a re-vendor that moved it would show here.
     * One-byte chunks are 5 bytes of framing to 1 of data. Read a byte at a
     * time, every call but the one that completes the last-chunk line is
     * incomplete, so the count is exact: 20479 chunks are 102395 framing
     * bytes, and a last-chunk line of "000" brings that to 102399 and one
     * of "0000" to 102400, the refusal.
     * One-shot reads leave the final read uncounted, so they are straddled
     * by a margin: 20000 chunks pass, 24000 do not. Two-byte chunks are 28%
     * data, and pass at any length. */
    ZUH_CASE("limits: picohttpparser's chunk-overhead refusal, byte-wise and one-shot (#256)");
    {
        static const struct { size_t chunks, dlen, max_read; const char *last; zuh_code want; } cases[] = {
            { 20479, 1, 1, "000",  ZUH_OK }, { 20479, 1, 1, "0000", ZUH_ERR_PARSE },
            { 20480, 1, 1, "0",    ZUH_ERR_PARSE },
            { 20000, 1, 0, "0",    ZUH_OK }, { 24000, 1, 0, "0",    ZUH_ERR_PARSE },
            { 30000, 2, 1, "0",    ZUH_OK }, { 30000, 2, 0, "0",    ZUH_OK } };
        size_t j, i;
        for (j = 0; j < sizeof cases / sizeof cases[0]; j++) {
            zuh_buffer wire, got;
            zuh_sink sink;
            zuh_mock_step step;
            zuh_code rc;
            ZUH_CHECK(zuh_buf_init(&wire, 1u << 18, (size_t)-1));
            for (i = 0; i < cases[j].chunks; i++)
                zuh_buf_append_str(&wire, cases[j].dlen == 1 ? "1\r\nX\r\n" : "2\r\nXX\r\n");
            zuh_buf_append_str(&wire, cases[j].last);
            zuh_buf_append_str(&wire, "\r\n\r\n");
            ZUH_CHECK(zuh_buf_init(&got, 1u << 16, (size_t)-1));
            zuh_sink_memory_init(&sink, &got);
            zuh_headers_init(&h);
            step.kind = ZUH_MOCK_DATA; step.data = wire.data; step.len = wire.len; step.code = ZUH_OK;
            zuh_error_clear(&e);
            rc = run_body_split(&step, 1, ZUH_FRAME_CHUNKED, 0, cases[j].max_read, &sink, &h, 0, &e);
            ZUH_CHECK_EQ_INT(rc, cases[j].want);
            /* Only chunk data ever reached the sink, never framing. */
            for (i = 0; i < got.len && got.data[i] == 'X'; i++) { }
            ZUH_CHECK_EQ_INT(i, got.len);
            if (rc == ZUH_OK) ZUH_CHECK_EQ_INT(got.len, cases[j].chunks * cases[j].dlen);
            else {
                ZUH_CHECK_EQ_INT(e.code, ZUH_ERR_PARSE);
                ZUH_CHECK(strstr(e.message, "chunked") != NULL);
                ZUH_CHECK(got.len <= cases[j].chunks * cases[j].dlen);
            }
            zuh_headers_free(&h);
            zuh_buf_free(&got);
            zuh_buf_free(&wire);
        }
    }

    /* #271: what a body read leaves over, and what it says when the
     * connection ends early, per framing. */
    ZUH_CASE("#271: a connection ending early names its framing");
    {
        static const char part[] = "5\r\nhel";
        zuh_mock_step st[1];
        zuh_buffer out; zuh_sink sink; zuh_code rc;
        st[0].kind = ZUH_MOCK_DATA; st[0].data = part; st[0].len = sizeof part - 1; st[0].code = ZUH_OK;
        zuh_headers_init(&h);
        zuh_buf_init(&out, 0, (size_t)-1); zuh_sink_memory_init(&sink, &out); zuh_error_clear(&e);
        rc = run_body(st, 1, ZUH_FRAME_CHUNKED, 0, &sink, &h, 0, 1u << 20, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_ERR_PARSE);
        ZUH_CHECK(strstr(e.message, "chunked") != NULL);
        zuh_buf_free(&out);
        zuh_buf_init(&out, 0, (size_t)-1); zuh_sink_memory_init(&sink, &out); zuh_error_clear(&e);
        rc = run_body(st, 1, ZUH_FRAME_LENGTH, 100, &sink, &h, 0, 1u << 20, &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_ERR_PARSE);
        ZUH_CHECK(strstr(e.message, "of 100") != NULL);
        zuh_buf_free(&out);
        zuh_headers_free(&h);
    }

    /* Content-Length met mid-read, after an earlier read: the body is the
     * declared bytes and the rest is surplus, counted exactly. */
    ZUH_CASE("#271: Content-Length reached in a second read takes exactly what is left");
    {
        zuh_mock_step st[2];
        zuh_stream *s;
        zuh_body_pipe p; zuh_framing fr; zuh_buffer out; zuh_sink sink; zuh_code rc;
        
        st[0].kind = ZUH_MOCK_DATA; st[0].data = "abcdef"; st[0].len = 6; st[0].code = ZUH_OK;
        st[1].kind = ZUH_MOCK_DATA; st[1].data = "ghijXXXX"; st[1].len = 8; st[1].code = ZUH_OK;
        s = zuh_mock_stream_new(st, 2, 0, 0);
        zuh_headers_init(&h);
        zuh_buf_init(&out, 0, (size_t)-1); zuh_sink_memory_init(&sink, &out); zuh_error_clear(&e);
        fr.kind = ZUH_FRAME_LENGTH; fr.length = 10; fr.poolable = 1;
        rc = zuh_body_pipe_init(&p, &sink, &h, 0, 1u << 20, &e);
        if (rc == ZUH_OK) rc = zuh_body_read(s, &fr, &p, NULL, 0, forever(), &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        ZUH_CHECK(out.len == 10 && memcmp(out.data, "abcdefghij", 10) == 0);
        ZUH_CHECK_EQ_INT(p.surplus, 4);
        zuh_body_pipe_free(&p); zuh_stream_free(s);
        zuh_buf_free(&out); zuh_headers_free(&h);
    }

    /* The bytes that came with the headers can be more than one read's
     * worth. Past the last chunk, every one of them is surplus: what this
     * read decoded past the end, and what the seed still holds. */
    ZUH_CASE("#271: surplus after a chunked body counts the unread seed too");
    {
        static char seed[20000 + 32];
        static const char body[] = "3\r\nabc\r\n0\r\n\r\n";
        size_t blen = sizeof body - 1, extra = 20000;
        zuh_mock_step st[1];
        zuh_stream *s;
        zuh_body_pipe p; zuh_framing fr; zuh_buffer out; zuh_sink sink; zuh_code rc;
        
        memcpy(seed, body, blen);
        memset(seed + blen, 'Z', extra);
        st[0].kind = ZUH_MOCK_EOF; st[0].data = NULL; st[0].len = 0; st[0].code = ZUH_OK;
        s = zuh_mock_stream_new(st, 1, 0, 0);
        zuh_headers_init(&h);
        zuh_buf_init(&out, 0, (size_t)-1); zuh_sink_memory_init(&sink, &out); zuh_error_clear(&e);
        fr.kind = ZUH_FRAME_CHUNKED; fr.length = 0; fr.poolable = 1;
        rc = zuh_body_pipe_init(&p, &sink, &h, 0, 1u << 20, &e);
        if (rc == ZUH_OK) rc = zuh_body_read(s, &fr, &p, seed, blen + extra, forever(), &e);
        ZUH_CHECK_EQ_INT(rc, ZUH_OK);
        ZUH_CHECK(out.len == 3 && memcmp(out.data, "abc", 3) == 0);
        ZUH_CHECK_EQ_INT(p.surplus, extra);
        zuh_body_pipe_free(&p); zuh_stream_free(s);
        zuh_buf_free(&out); zuh_headers_free(&h);
    }

    ZUH_CASE("no leaks across the suite");
    {
        zuh_alloc_stats end;
        zuh_alloc_stats_get(&end);
        ZUH_CHECK_EQ_INT(end.live_blocks, 0);
    }
}

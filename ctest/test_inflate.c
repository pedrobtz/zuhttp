#include "zuh_test.h"
#include "zuh_inflate.h"
#include "zuh_body.h"
#include "zuh_alloc.h"
#include "zuh_buffer.h"
#include <string.h>
#include <zlib.h>

void suite_inflate(void);

/* Compress with a chosen wrapping so both §21.3 cases can be tested.
 * windowBits: 15+16 gzip, 15 zlib-wrapped deflate, -15 raw deflate. */
static size_t compress_with(int windowBits, const void *src, size_t n,
                            unsigned char *dst, size_t dcap, int level) {
    z_stream s;
    memset(&s, 0, sizeof s);
    if (deflateInit2(&s, level, Z_DEFLATED, windowBits, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        return 0;
    s.next_in = (Bytef *)(uintptr_t)src;
    s.avail_in = (uInt)n;
    s.next_out = dst;
    s.avail_out = (uInt)dcap;
    if (deflate(&s, Z_FINISH) != Z_STREAM_END) { deflateEnd(&s); return 0; }
    deflateEnd(&s);
    return dcap - s.avail_out;
}

/* A highly compressible payload of `n` zero bytes, gzipped into a zuh_buffer.
 * The compression ratio is what makes it a bomb: 4 MB of zeros is ~4 KB. */
static int make_gzip_of_zeros(zuh_buffer *out, size_t n) {
    unsigned char *zeros;
    unsigned char *comp;
    size_t clen;
    int ok = 0;
    if (!zuh_buf_init(out, 256, 64 * 1024 * 1024)) return 0;
    zeros = (unsigned char *)zuh_alloc(n);
    comp  = (unsigned char *)zuh_alloc(n / 2 + 1024);
    if (zeros && comp) {
        memset(zeros, 0, n);
        clen = compress_with(15 + 16, zeros, n, comp, n / 2 + 1024, 9);
        if (clen) ok = zuh_buf_append(out, comp, clen);
    }
    zuh_free(zeros);
    zuh_free(comp);
    if (!ok) zuh_buf_free(out);
    return ok;
}

/* #255/#327: inflate `n` zeros, gzipped, fed whole (step 0) or `step`
 * bytes at a time, at the shipped ratio. 1 when it decodes completely, 0
 * on the ratio error, -1 otherwise; checks the output bound on the way. */
static int ratio_verdict(const unsigned char *zeros, size_t n, unsigned char *comp,
                         size_t cap, size_t step, size_t *outp) {
    zuh_inflate z; zuh_buffer out; zuh_error e;
    zuh_code rc = ZUH_ERR_WOULDBLOCK;
    size_t off = 0, clen = compress_with(15 + 16, zeros, n, comp, cap, 9);
    int v;
    if (!clen) return -1;
    if (!step) step = clen;
    zuh_error_clear(&e);
    if (!zuh_buf_init(&out, 0, 0)) return -1;
    zuh_inflate_init(&z, ZUH_ENC_GZIP, 0, ZUH_MAX_DECOMPRESSION_RATIO);
    while (off < clen && (rc == ZUH_ERR_WOULDBLOCK || rc == ZUH_OK)) {
        size_t m = clen - off < step ? clen - off : step;
        rc = zuh_inflate_run(&z, comp + off, m, &out, &e);
        off += m;
        ZUH_CHECK(z.in_total < 32 || z.out_total <= z.in_total * 1000 + 1);
    }
    if (rc == ZUH_OK || rc == ZUH_ERR_WOULDBLOCK)
        rc = zuh_inflate_run(&z, NULL, 0, &out, &e);
    v = rc == ZUH_OK ? (out.len == n ? 1 : -1)
      : (rc == ZUH_ERR_BODY_LIMIT && strstr(e.message, "ratio")) ? 0 : -1;
    if (outp) *outp = out.len;
    zuh_inflate_free(&z); zuh_buf_free(&out);
    return v;
}

void suite_inflate(void) {
    ZUH_CASE("Content-Encoding mapping");
    ZUH_CHECK_EQ_INT(zuh_encoding_parse(NULL), ZUH_ENC_IDENTITY);
    ZUH_CHECK_EQ_INT(zuh_encoding_parse(""), ZUH_ENC_IDENTITY);
    ZUH_CHECK_EQ_INT(zuh_encoding_parse("identity"), ZUH_ENC_IDENTITY);
    ZUH_CHECK_EQ_INT(zuh_encoding_parse("gzip"), ZUH_ENC_GZIP);
    ZUH_CHECK_EQ_INT(zuh_encoding_parse("  GZIP "), ZUH_ENC_GZIP);
    ZUH_CHECK_EQ_INT(zuh_encoding_parse("x-gzip"), ZUH_ENC_GZIP);
    ZUH_CHECK_EQ_INT(zuh_encoding_parse("deflate"), ZUH_ENC_DEFLATE);
    /* Unknown codings must not be silently treated as identity. */
    ZUH_CHECK_EQ_INT(zuh_encoding_parse("br"), ZUH_ENC_UNSUPPORTED);
    ZUH_CHECK_EQ_INT(zuh_encoding_parse("zstd"), ZUH_ENC_UNSUPPORTED);
    ZUH_CHECK_EQ_INT(zuh_encoding_parse("gzip, br"), ZUH_ENC_UNSUPPORTED);

    ZUH_CASE("gzip round-trips");
    {
        const char *plain = "hello world, hello world, hello world";
        unsigned char comp[512];
        size_t clen = compress_with(15 + 16, plain, strlen(plain), comp, sizeof comp, 6);
        zuh_inflate z; zuh_buffer out; zuh_error e; const char *s;
        ZUH_CHECK(clen > 0);
        zuh_error_clear(&e);
        zuh_buf_init(&out, 0, 0);
        ZUH_CHECK_EQ_INT(zuh_inflate_init(&z, ZUH_ENC_GZIP, 0, 0), ZUH_OK);
        ZUH_CHECK_EQ_INT(zuh_inflate_run(&z, comp, clen, &out, &e), ZUH_OK);
        ZUH_CHECK(zuh_buf_cstr(&out, &s));
        ZUH_CHECK(strcmp(s, plain) == 0);
        zuh_inflate_free(&z); zuh_buf_free(&out);
    }

    /* §21.3: both deflate wrappings must work, because servers send both. */
    ZUH_CASE("§21.3: zlib-wrapped deflate round-trips");
    {
        const char *plain = "the quick brown fox jumps over the lazy dog";
        unsigned char comp[512];
        size_t clen = compress_with(15, plain, strlen(plain), comp, sizeof comp, 6);
        zuh_inflate z; zuh_buffer out; zuh_error e; const char *s;
        ZUH_CHECK(clen > 0);
        zuh_error_clear(&e);
        zuh_buf_init(&out, 0, 0);
        ZUH_CHECK_EQ_INT(zuh_inflate_init(&z, ZUH_ENC_DEFLATE, 0, 0), ZUH_OK);
        ZUH_CHECK_EQ_INT(zuh_inflate_run(&z, comp, clen, &out, &e), ZUH_OK);
        ZUH_CHECK(zuh_buf_cstr(&out, &s));
        ZUH_CHECK(strcmp(s, plain) == 0);
        zuh_inflate_free(&z); zuh_buf_free(&out);
    }

    ZUH_CASE("§21.3: RAW deflate round-trips (the common non-conforming case)");
    {
        const char *plain = "the quick brown fox jumps over the lazy dog";
        unsigned char comp[512];
        size_t clen = compress_with(-15, plain, strlen(plain), comp, sizeof comp, 6);
        zuh_inflate z; zuh_buffer out; zuh_error e; const char *s;
        ZUH_CHECK(clen > 0);
        zuh_error_clear(&e);
        zuh_buf_init(&out, 0, 0);
        ZUH_CHECK_EQ_INT(zuh_inflate_init(&z, ZUH_ENC_DEFLATE, 0, 0), ZUH_OK);
        ZUH_CHECK_EQ_INT(zuh_inflate_run(&z, comp, clen, &out, &e), ZUH_OK);
        ZUH_CHECK(zuh_buf_cstr(&out, &s));
        ZUH_CHECK(strcmp(s, plain) == 0);
        zuh_inflate_free(&z); zuh_buf_free(&out);
    }

    ZUH_CASE("identity passes bytes through unchanged");
    {
        zuh_inflate z; zuh_buffer out; zuh_error e;
        zuh_error_clear(&e);
        zuh_buf_init(&out, 0, 0);
        ZUH_CHECK_EQ_INT(zuh_inflate_init(&z, ZUH_ENC_IDENTITY, 0, 0), ZUH_OK);
        ZUH_CHECK_EQ_INT(zuh_inflate_run(&z, "abc", 3, &out, &e), ZUH_OK);
        ZUH_CHECK_EQ_INT(out.len, 3);
        ZUH_CHECK_MEM(out.data, "abc", 3);
        zuh_inflate_free(&z); zuh_buf_free(&out);
    }

    ZUH_CASE("an unsupported coding fails at init rather than passing bytes on");
    {
        zuh_inflate z;
        ZUH_CHECK_EQ_INT(zuh_inflate_init(&z, ZUH_ENC_UNSUPPORTED, 0, 0), ZUH_ERR_BODY_DECODE);
    }

    ZUH_CASE("malformed compressed data is rejected");
    {
        zuh_inflate z; zuh_buffer out; zuh_error e;
        unsigned char junk[64];
        memset(junk, 0xAB, sizeof junk);
        zuh_error_clear(&e);
        zuh_buf_init(&out, 0, 0);
        zuh_inflate_init(&z, ZUH_ENC_GZIP, 0, 0);
        ZUH_CHECK_EQ_INT(zuh_inflate_run(&z, junk, sizeof junk, &out, &e), ZUH_ERR_BODY_DECODE);
        zuh_inflate_free(&z); zuh_buf_free(&out);
    }

    ZUH_CASE("input split at every boundary produces identical output");
    {
        const char *plain = "aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd";
        unsigned char comp[512];
        size_t clen = compress_with(15 + 16, plain, strlen(plain), comp, sizeof comp, 6);
        size_t split;
        for (split = 1; split < clen; split++) {
            zuh_inflate z; zuh_buffer out; zuh_error e; const char *s;
            zuh_code r1, r2;
            zuh_error_clear(&e);
            zuh_buf_init(&out, 0, 0);
            zuh_inflate_init(&z, ZUH_ENC_GZIP, 0, 0);
            r1 = zuh_inflate_run(&z, comp, split, &out, &e);
            r2 = zuh_inflate_run(&z, comp + split, clen - split, &out, &e);
            ZUH_CHECK(r1 == ZUH_ERR_WOULDBLOCK || r1 == ZUH_OK);
            ZUH_CHECK_EQ_INT(r2, ZUH_OK);
            ZUH_CHECK(zuh_buf_cstr(&out, &s));
            ZUH_CHECK(strcmp(s, plain) == 0);
            zuh_inflate_free(&z); zuh_buf_free(&out);
        }
    }

    /* #242: RFC 1952 §2.2 makes a gzip body of two members equivalent to one
     * member of their concatenation, which is what `gzip -dc` prints. The
     * oracle is the plaintext: three deflate()-made members, one of them
     * empty, must decode to the first and third joined, read whole, split
     * at every byte and fed a byte at a time. The caps count the body, not
     * a member: max_out at the joined length passes and one less fails. */
    ZUH_CASE("#242: a multi-member gzip body decodes as the concatenation of its members");
    {
        const char *a = "the first member, the first member, ";
        const char *b = "and the third, after an empty second";
        char joined[128];
        unsigned char comp[1024];
        size_t na = strlen(a), nb = strlen(b), nj, clen = 0, c, split, i;
        nj = na + nb;
        memcpy(joined, a, na);
        memcpy(joined + na, b, nb);
        c = compress_with(15 + 16, a, na, comp, sizeof comp, 6);
        ZUH_CHECK(c > 0); clen += c;
        c = compress_with(15 + 16, "", 0, comp + clen, sizeof comp - clen, 6);
        ZUH_CHECK(c > 0); clen += c;
        c = compress_with(15 + 16, b, nb, comp + clen, sizeof comp - clen, 6);
        ZUH_CHECK(c > 0); clen += c;

        for (split = 0; split <= clen; split++) {
            zuh_inflate z; zuh_buffer out; zuh_error e;
            zuh_code r1, r2;
            zuh_error_clear(&e);
            zuh_buf_init(&out, 0, 0);
            zuh_inflate_init(&z, ZUH_ENC_GZIP, 0, 0);
            r1 = zuh_inflate_run(&z, comp, split, &out, &e);
            r2 = zuh_inflate_run(&z, comp + split, clen - split, &out, &e);
            ZUH_CHECK(r1 == ZUH_ERR_WOULDBLOCK || r1 == ZUH_OK);
            ZUH_CHECK(r2 == ZUH_ERR_WOULDBLOCK || r2 == ZUH_OK);
            ZUH_CHECK_EQ_INT(zuh_inflate_run(&z, NULL, 0, &out, &e), ZUH_OK);
            ZUH_CHECK_EQ_INT(out.len, nj);
            ZUH_CHECK(out.len == nj && memcmp(out.data, joined, nj) == 0);
            zuh_inflate_free(&z); zuh_buf_free(&out);
        }
        {
            zuh_inflate z; zuh_buffer out; zuh_error e;
            int ok = 1;
            zuh_error_clear(&e);
            zuh_buf_init(&out, 0, 0);
            zuh_inflate_init(&z, ZUH_ENC_GZIP, 0, 0);
            for (i = 0; i < clen; i++) {
                zuh_code r = zuh_inflate_run(&z, comp + i, 1, &out, &e);
                if (r != ZUH_OK && r != ZUH_ERR_WOULDBLOCK) ok = 0;
            }
            ZUH_CHECK(ok);
            ZUH_CHECK_EQ_INT(zuh_inflate_run(&z, NULL, 0, &out, &e), ZUH_OK);
            ZUH_CHECK(out.len == nj && memcmp(out.data, joined, nj) == 0);
            zuh_inflate_free(&z); zuh_buf_free(&out);
        }
        {
            size_t cap;
            for (cap = nj - 1; cap <= nj + 1; cap++) {
                zuh_inflate z; zuh_buffer out; zuh_error e; zuh_code r;
                zuh_error_clear(&e);
                zuh_buf_init(&out, 0, 0);
                zuh_inflate_init(&z, ZUH_ENC_GZIP, (uint64_t)cap, 0);
                r = zuh_inflate_run(&z, comp, clen, &out, &e);
                if (cap < nj) {
                    ZUH_CHECK_EQ_INT(r, ZUH_ERR_BODY_LIMIT);
                    ZUH_CHECK(out.len <= cap);
                } else {
                    ZUH_CHECK(r == ZUH_OK || r == ZUH_ERR_WOULDBLOCK);
                    ZUH_CHECK_EQ_INT(zuh_inflate_run(&z, NULL, 0, &out, &e), ZUH_OK);
                    ZUH_CHECK_EQ_INT(out.len, nj);
                }
                zuh_inflate_free(&z); zuh_buf_free(&out);
            }
        }
    }

    ZUH_CASE("#242: a second gzip member cut short fails at the end of the body");
    {
        const char *a = "a complete first member";
        unsigned char comp[512];
        size_t na = strlen(a), c1, c2, cut;
        c1 = compress_with(15 + 16, a, na, comp, sizeof comp, 6);
        c2 = compress_with(15 + 16, a, na, comp + c1, sizeof comp - c1, 6);
        ZUH_CHECK(c1 > 0 && c2 > 0);
        for (cut = 1; cut < c2; cut++) {
            zuh_inflate z; zuh_buffer out; zuh_error e; zuh_code r;
            zuh_error_clear(&e);
            zuh_buf_init(&out, 0, 0);
            zuh_inflate_init(&z, ZUH_ENC_GZIP, 0, 0);
            r = zuh_inflate_run(&z, comp, c1 + cut, &out, &e);
            if (r == ZUH_OK || r == ZUH_ERR_WOULDBLOCK)
                r = zuh_inflate_run(&z, NULL, 0, &out, &e);
            ZUH_CHECK_EQ_INT(r, ZUH_ERR_BODY_DECODE);
            zuh_inflate_free(&z); zuh_buf_free(&out);
        }
    }

    /* §21.4 — the reason this module has limits at all. */
    ZUH_CASE("§21.4: a decompression bomb is stopped by the OUTPUT limit");
    {
        static unsigned char zeros[400000];
        unsigned char comp[4096];
        size_t clen = compress_with(15 + 16, zeros, sizeof zeros, comp, sizeof comp, 9);
        zuh_inflate z; zuh_buffer out; zuh_error e;
        ZUH_CHECK(clen > 0 && clen < 2048);      /* ~400 KB -> under 2 KB */
        zuh_error_clear(&e);
        zuh_buf_init(&out, 0, 0);
        zuh_inflate_init(&z, ZUH_ENC_GZIP, 65536, 0);   /* cap output at 64 KB */
        ZUH_CHECK_EQ_INT(zuh_inflate_run(&z, comp, clen, &out, &e), ZUH_ERR_BODY_LIMIT);
        ZUH_CHECK_EQ_INT(e.code, ZUH_ERR_BODY_LIMIT);
        /* the cap bounds the allocation: we did not inflate all 400 KB */
        ZUH_CHECK(out.len <= 65536 + 16384);
        zuh_inflate_free(&z); zuh_buf_free(&out);
    }

    ZUH_CASE("§21.4: a bomb is also stopped by the RATIO limit");
    {
        static unsigned char zeros[400000];
        unsigned char comp[4096];
        size_t clen = compress_with(15 + 16, zeros, sizeof zeros, comp, sizeof comp, 9);
        zuh_inflate z; zuh_buffer out; zuh_error e;
        zuh_error_clear(&e);
        zuh_buf_init(&out, 0, 0);
        zuh_inflate_init(&z, ZUH_ENC_GZIP, 0, 100);     /* at most 100:1 */
        ZUH_CHECK_EQ_INT(zuh_inflate_run(&z, comp, clen, &out, &e), ZUH_ERR_BODY_LIMIT);
        zuh_inflate_free(&z); zuh_buf_free(&out);
    }

    ZUH_CASE("a legitimate high-ratio body under the caps still succeeds");
    {
        static unsigned char zeros[4096];
        unsigned char comp[512];
        size_t clen = compress_with(15 + 16, zeros, sizeof zeros, comp, sizeof comp, 9);
        zuh_inflate z; zuh_buffer out; zuh_error e;
        zuh_error_clear(&e);
        zuh_buf_init(&out, 0, 0);
        zuh_inflate_init(&z, ZUH_ENC_GZIP, 1048576, 10000);
        ZUH_CHECK_EQ_INT(zuh_inflate_run(&z, comp, clen, &out, &e), ZUH_OK);
        ZUH_CHECK_EQ_INT(out.len, sizeof zeros);
        zuh_inflate_free(&z); zuh_buf_free(&out);
    }

    /* Found by the S18 fuzz target, not by review: the caps were checked
     * AFTER a 16 KB inflate chunk was appended, so a 1 MB limit delivered
     * 1 MB + 16 KB. A caller sizing memory from max_decompressed_bytes was
     * therefore given a figure that was not a bound (§21.4). */
    ZUH_CASE("a bomb is stopped AT the cap, not one chunk past it");
    {
        zuh_buffer src, out;
        zuh_inflate z;
        zuh_error e;
        const uint64_t cap = 64 * 1024;   /* smaller than one 16 KB chunk x 4 */
        ZUH_CHECK(make_gzip_of_zeros(&src, 4 * 1024 * 1024));
        ZUH_CHECK(zuh_buf_init(&out, 256, 16 * 1024 * 1024));
        ZUH_CHECK_EQ_INT(zuh_inflate_init(&z, ZUH_ENC_GZIP, cap, 0), ZUH_OK);
        ZUH_CHECK_EQ_INT(zuh_inflate_run(&z, src.data, src.len, &out, &e), ZUH_ERR_BODY_LIMIT);
        /* Exactly the cap. Not "close to", not "the cap plus a chunk". */
        ZUH_CHECK_EQ_INT((long long)z.out_total, (long long)cap);
        ZUH_CHECK_EQ_INT((long long)out.len, (long long)cap);
        zuh_buf_free(&out); zuh_buf_free(&src); zuh_inflate_free(&z);
    }

    ZUH_CASE("a body of exactly the cap is ACCEPTED, not rejected");
    {
        zuh_buffer src, out;
        zuh_inflate z;
        zuh_error e;
        const size_t n = 50000;
        ZUH_CHECK(make_gzip_of_zeros(&src, n));
        ZUH_CHECK(zuh_buf_init(&out, 256, 1024 * 1024));
        /* The off-by-one that the one-byte output headroom exists to avoid:
         * bounding the window at the cap would make this look like an
         * overflow, because zlib needs one more call to report Z_STREAM_END. */
        ZUH_CHECK_EQ_INT(zuh_inflate_init(&z, ZUH_ENC_GZIP, n, 0), ZUH_OK);
        ZUH_CHECK_EQ_INT(zuh_inflate_run(&z, src.data, src.len, &out, &e), ZUH_OK);
        ZUH_CHECK_EQ_INT((long long)out.len, (long long)n);
        zuh_buf_free(&out); zuh_buf_free(&src); zuh_inflate_free(&z);
    }

    ZUH_CASE("the ratio cap also bounds output exactly");
    {
        zuh_buffer src, out;
        zuh_inflate z;
        zuh_error e;
        ZUH_CHECK(make_gzip_of_zeros(&src, 4 * 1024 * 1024));
        ZUH_CHECK(zuh_buf_init(&out, 256, 16 * 1024 * 1024));
        ZUH_CHECK_EQ_INT(zuh_inflate_init(&z, ZUH_ENC_GZIP, 0, 10), ZUH_OK);
        ZUH_CHECK_EQ_INT(zuh_inflate_run(&z, src.data, src.len, &out, &e), ZUH_ERR_BODY_LIMIT);
        /* out_total may never exceed in_total * max_ratio. */
        ZUH_CHECK(z.out_total <= z.in_total * 10);
        ZUH_CHECK_EQ_INT((long long)out.len, (long long)z.out_total);
        zuh_buf_free(&out); zuh_buf_free(&src); zuh_inflate_free(&z);
    }

    /* #255, restated by #327: the ratio at its edge, at the shipped 1000:1.
     * The cap is out <= 1000 x compressed bytes inflate has consumed so
     * far, judged as it decodes. That is the only verdict that does not
     * depend on how the bytes arrive (#327), and it is not "1000 x the
     * whole stream": the last output appears before zlib reads the 8-byte
     * gzip trailer. So the edge is searched for, not computed: the largest
     * run of zeros n that passes. n - 1 and n pass and n + 1 is the bomb
     * error, fed whole and in 100-byte pieces alike, and no output byte
     * ever exceeds 1000 x consumed + 1 (the one byte of headroom). */
    ZUH_CASE("limits: a gzip stream of zeros at the ratio's edge, n - 1, n and n + 1, whole and split (#255, #327)");
    {
        size_t cap = 1u << 16, lo = 200000, hi = 1100000, n, d;
        unsigned char *zeros = (unsigned char *)zuh_calloc(1, hi + 2);
        unsigned char *comp = (unsigned char *)zuh_alloc(cap);
        /* 1: passed, 0: the ratio error, -1: anything else. */
        #define RATIO_VERDICT(len, step, outp) ratio_verdict(zeros, (len), comp, cap, (step), (outp))
        ZUH_CHECK(zeros && comp);
        if (zeros && comp) {
            ZUH_CHECK_EQ_INT(RATIO_VERDICT(lo, 0, NULL), 1);
            ZUH_CHECK_EQ_INT(RATIO_VERDICT(hi, 0, NULL), 0);
            while (hi - lo > 1) {            /* lo passes, hi fails */
                size_t mid = lo + (hi - lo) / 2;
                if (RATIO_VERDICT(mid, 0, NULL) == 1) lo = mid; else hi = mid;
            }
            n = lo;
            for (d = 0; d < 2; d++) {
                size_t step = d ? 100 : 0;
                ZUH_CHECK_EQ_INT(RATIO_VERDICT(n - 1, step, NULL), 1);
                ZUH_CHECK_EQ_INT(RATIO_VERDICT(n, step, NULL), 1);
                ZUH_CHECK_EQ_INT(RATIO_VERDICT(n + 1, step, NULL), 0);
            }
        }
        #undef RATIO_VERDICT
        zuh_free(zeros); zuh_free(comp);
    }

    /* #255: the ratio waits for 32 compressed bytes. No deflate stream runs
     * far past 1000:1 (its ceiling is about 1030:1), so the warm-up is
     * straddled against a ratio of 2, which zeros pass at once: the first
     * 31 bytes of the stream are let through whatever they inflate to, and
     * 32 or 33 are held to the ratio. */
    ZUH_CASE("limits: the ratio applies from the 32nd compressed byte, not the 31st (#255)");
    {
        static unsigned char zeros[1u << 20];
        unsigned char comp[4096];
        size_t clen = compress_with(15 + 16, zeros, sizeof zeros, comp, sizeof comp, 9);
        size_t k;
        ZUH_CHECK(clen > 40);
        for (k = 31; k <= 33; k++) {
            zuh_inflate z; zuh_buffer out; zuh_error e;
            zuh_code rc;
            zuh_error_clear(&e);
            ZUH_CHECK(zuh_buf_init(&out, 0, 0));
            zuh_inflate_init(&z, ZUH_ENC_GZIP, 0, 2);
            rc = zuh_inflate_run(&z, comp, k, &out, &e);
            if (k < 32) {
                /* Not yet judged, and over the ratio it would be judged by. */
                ZUH_CHECK_EQ_INT(rc, ZUH_ERR_WOULDBLOCK);
                ZUH_CHECK(out.len > 2 * 33);
            } else {
                ZUH_CHECK_EQ_INT(rc, ZUH_ERR_BODY_LIMIT);
                ZUH_CHECK(strstr(e.message, "ratio") != NULL);
                ZUH_CHECK(out.len <= 2 * k);
            }
            zuh_inflate_free(&z); zuh_buf_free(&out);
        }
    }

    /* #327: the ratio verdict may not depend on how the bytes arrive. It
     * counted input OFFERED to inflate rather than consumed, so a body fed
     * whole had its incompressible tail counted while its zeros still
     * decoded, and passed; fed in pieces it was judged on the prefix, and
     * failed. 4,000,000 zeros then 700 random bytes, about 843:1 overall,
     * whose zero run decodes past 1000:1 before the tail arrives: refused
     * whole and at every split. The 1 MB-zeros-at-999:1 control passes at
     * every split too. */
    ZUH_CASE("limits: the ratio verdict is the same whole and split at 1, 100, 500, 2000 and 4096 bytes (#327)");
    {
        size_t nz = 4000000, nr = 700, n = nz + nr, clen, cap = 1u << 16;
        unsigned char *src = (unsigned char *)zuh_calloc(1, n);
        unsigned char *comp = (unsigned char *)zuh_alloc(cap);
        static const size_t splits[] = { 0, 1, 100, 500, 2000, 4096 };
        unsigned seed = 327u;
        size_t i, k;
        ZUH_CHECK(src && comp);
        for (i = nz; src && i < n; i++) { seed = seed * 1103515245u + 12345u; src[i] = (unsigned char)(seed >> 16); }
        clen = (src && comp) ? compress_with(15 + 16, src, n, comp, cap, 9) : 0;
        ZUH_CHECK(clen > 0 && n / clen < 1000);    /* under the cap overall */
        for (k = 0; clen && k < sizeof splits / sizeof splits[0]; k++) {
            zuh_inflate z; zuh_buffer out; zuh_error e;
            zuh_code rc = ZUH_ERR_WOULDBLOCK;
            size_t off = 0, step = splits[k] ? splits[k] : clen;
            zuh_error_clear(&e);
            ZUH_CHECK(zuh_buf_init(&out, 0, 0));
            zuh_inflate_init(&z, ZUH_ENC_GZIP, 0, ZUH_MAX_DECOMPRESSION_RATIO);
            while (off < clen && (rc == ZUH_ERR_WOULDBLOCK || rc == ZUH_OK)) {
                size_t m = clen - off < step ? clen - off : step;
                rc = zuh_inflate_run(&z, comp + off, m, &out, &e);
                off += m;
            }
            ZUH_CHECK_EQ_INT(rc, ZUH_ERR_BODY_LIMIT);
            ZUH_CHECK(strstr(e.message, "ratio") != NULL);
            zuh_inflate_free(&z); zuh_buf_free(&out);
        }
        zuh_free(src); zuh_free(comp);
    }

    ZUH_CASE("no leaks across the suite");
    {
        zuh_alloc_stats st;
        zuh_alloc_stats_get(&st);
        ZUH_CHECK_EQ_INT(st.live_blocks, 0);
    }
}

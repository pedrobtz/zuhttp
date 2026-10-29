#include "zuh_test.h"
#include "zuh_inflate.h"
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

    ZUH_CASE("no leaks across the suite");
    {
        zuh_alloc_stats st;
        zuh_alloc_stats_get(&st);
        ZUH_CHECK_EQ_INT(st.live_blocks, 0);
    }
}

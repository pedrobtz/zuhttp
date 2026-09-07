#include "zu_test.h"
#include "zu_inflate.h"
#include "zu_alloc.h"
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

void suite_inflate(void) {
    ZU_CASE("Content-Encoding mapping");
    ZU_CHECK_EQ_INT(zu_encoding_parse(NULL), ZU_ENC_IDENTITY);
    ZU_CHECK_EQ_INT(zu_encoding_parse(""), ZU_ENC_IDENTITY);
    ZU_CHECK_EQ_INT(zu_encoding_parse("identity"), ZU_ENC_IDENTITY);
    ZU_CHECK_EQ_INT(zu_encoding_parse("gzip"), ZU_ENC_GZIP);
    ZU_CHECK_EQ_INT(zu_encoding_parse("  GZIP "), ZU_ENC_GZIP);
    ZU_CHECK_EQ_INT(zu_encoding_parse("x-gzip"), ZU_ENC_GZIP);
    ZU_CHECK_EQ_INT(zu_encoding_parse("deflate"), ZU_ENC_DEFLATE);
    /* Unknown codings must not be silently treated as identity. */
    ZU_CHECK_EQ_INT(zu_encoding_parse("br"), ZU_ENC_UNSUPPORTED);
    ZU_CHECK_EQ_INT(zu_encoding_parse("zstd"), ZU_ENC_UNSUPPORTED);
    ZU_CHECK_EQ_INT(zu_encoding_parse("gzip, br"), ZU_ENC_UNSUPPORTED);

    ZU_CASE("gzip round-trips");
    {
        const char *plain = "hello world, hello world, hello world";
        unsigned char comp[512];
        size_t clen = compress_with(15 + 16, plain, strlen(plain), comp, sizeof comp, 6);
        zu_inflate z; zu_buffer out; zu_error e; const char *s;
        ZU_CHECK(clen > 0);
        zu_error_clear(&e);
        zu_buf_init(&out, 0, 0);
        ZU_CHECK_EQ_INT(zu_inflate_init(&z, ZU_ENC_GZIP, 0, 0), ZU_OK);
        ZU_CHECK_EQ_INT(zu_inflate_run(&z, comp, clen, &out, &e), ZU_OK);
        ZU_CHECK(zu_buf_cstr(&out, &s));
        ZU_CHECK(strcmp(s, plain) == 0);
        zu_inflate_free(&z); zu_buf_free(&out);
    }

    /* §21.3: both deflate wrappings must work, because servers send both. */
    ZU_CASE("§21.3: zlib-wrapped deflate round-trips");
    {
        const char *plain = "the quick brown fox jumps over the lazy dog";
        unsigned char comp[512];
        size_t clen = compress_with(15, plain, strlen(plain), comp, sizeof comp, 6);
        zu_inflate z; zu_buffer out; zu_error e; const char *s;
        ZU_CHECK(clen > 0);
        zu_error_clear(&e);
        zu_buf_init(&out, 0, 0);
        ZU_CHECK_EQ_INT(zu_inflate_init(&z, ZU_ENC_DEFLATE, 0, 0), ZU_OK);
        ZU_CHECK_EQ_INT(zu_inflate_run(&z, comp, clen, &out, &e), ZU_OK);
        ZU_CHECK(zu_buf_cstr(&out, &s));
        ZU_CHECK(strcmp(s, plain) == 0);
        zu_inflate_free(&z); zu_buf_free(&out);
    }

    ZU_CASE("§21.3: RAW deflate round-trips (the common non-conforming case)");
    {
        const char *plain = "the quick brown fox jumps over the lazy dog";
        unsigned char comp[512];
        size_t clen = compress_with(-15, plain, strlen(plain), comp, sizeof comp, 6);
        zu_inflate z; zu_buffer out; zu_error e; const char *s;
        ZU_CHECK(clen > 0);
        zu_error_clear(&e);
        zu_buf_init(&out, 0, 0);
        ZU_CHECK_EQ_INT(zu_inflate_init(&z, ZU_ENC_DEFLATE, 0, 0), ZU_OK);
        ZU_CHECK_EQ_INT(zu_inflate_run(&z, comp, clen, &out, &e), ZU_OK);
        ZU_CHECK(zu_buf_cstr(&out, &s));
        ZU_CHECK(strcmp(s, plain) == 0);
        zu_inflate_free(&z); zu_buf_free(&out);
    }

    ZU_CASE("identity passes bytes through unchanged");
    {
        zu_inflate z; zu_buffer out; zu_error e;
        zu_error_clear(&e);
        zu_buf_init(&out, 0, 0);
        ZU_CHECK_EQ_INT(zu_inflate_init(&z, ZU_ENC_IDENTITY, 0, 0), ZU_OK);
        ZU_CHECK_EQ_INT(zu_inflate_run(&z, "abc", 3, &out, &e), ZU_OK);
        ZU_CHECK_EQ_INT(out.len, 3);
        ZU_CHECK_MEM(out.data, "abc", 3);
        zu_inflate_free(&z); zu_buf_free(&out);
    }

    ZU_CASE("an unsupported coding fails at init rather than passing bytes on");
    {
        zu_inflate z;
        ZU_CHECK_EQ_INT(zu_inflate_init(&z, ZU_ENC_UNSUPPORTED, 0, 0), ZU_ERR_BODY_DECODE);
    }

    ZU_CASE("malformed compressed data is rejected");
    {
        zu_inflate z; zu_buffer out; zu_error e;
        unsigned char junk[64];
        memset(junk, 0xAB, sizeof junk);
        zu_error_clear(&e);
        zu_buf_init(&out, 0, 0);
        zu_inflate_init(&z, ZU_ENC_GZIP, 0, 0);
        ZU_CHECK_EQ_INT(zu_inflate_run(&z, junk, sizeof junk, &out, &e), ZU_ERR_BODY_DECODE);
        zu_inflate_free(&z); zu_buf_free(&out);
    }

    ZU_CASE("input split at every boundary produces identical output");
    {
        const char *plain = "aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd";
        unsigned char comp[512];
        size_t clen = compress_with(15 + 16, plain, strlen(plain), comp, sizeof comp, 6);
        size_t split;
        for (split = 1; split < clen; split++) {
            zu_inflate z; zu_buffer out; zu_error e; const char *s;
            zu_code r1, r2;
            zu_error_clear(&e);
            zu_buf_init(&out, 0, 0);
            zu_inflate_init(&z, ZU_ENC_GZIP, 0, 0);
            r1 = zu_inflate_run(&z, comp, split, &out, &e);
            r2 = zu_inflate_run(&z, comp + split, clen - split, &out, &e);
            ZU_CHECK(r1 == ZU_ERR_WOULDBLOCK || r1 == ZU_OK);
            ZU_CHECK_EQ_INT(r2, ZU_OK);
            ZU_CHECK(zu_buf_cstr(&out, &s));
            ZU_CHECK(strcmp(s, plain) == 0);
            zu_inflate_free(&z); zu_buf_free(&out);
        }
    }

    /* §21.4 — the reason this module has limits at all. */
    ZU_CASE("§21.4: a decompression bomb is stopped by the OUTPUT limit");
    {
        static unsigned char zeros[400000];
        unsigned char comp[4096];
        size_t clen = compress_with(15 + 16, zeros, sizeof zeros, comp, sizeof comp, 9);
        zu_inflate z; zu_buffer out; zu_error e;
        ZU_CHECK(clen > 0 && clen < 2048);      /* ~400 KB -> under 2 KB */
        zu_error_clear(&e);
        zu_buf_init(&out, 0, 0);
        zu_inflate_init(&z, ZU_ENC_GZIP, 65536, 0);   /* cap output at 64 KB */
        ZU_CHECK_EQ_INT(zu_inflate_run(&z, comp, clen, &out, &e), ZU_ERR_BODY_LIMIT);
        ZU_CHECK_EQ_INT(e.code, ZU_ERR_BODY_LIMIT);
        /* the cap bounds the allocation: we did not inflate all 400 KB */
        ZU_CHECK(out.len <= 65536 + 16384);
        zu_inflate_free(&z); zu_buf_free(&out);
    }

    ZU_CASE("§21.4: a bomb is also stopped by the RATIO limit");
    {
        static unsigned char zeros[400000];
        unsigned char comp[4096];
        size_t clen = compress_with(15 + 16, zeros, sizeof zeros, comp, sizeof comp, 9);
        zu_inflate z; zu_buffer out; zu_error e;
        zu_error_clear(&e);
        zu_buf_init(&out, 0, 0);
        zu_inflate_init(&z, ZU_ENC_GZIP, 0, 100);     /* at most 100:1 */
        ZU_CHECK_EQ_INT(zu_inflate_run(&z, comp, clen, &out, &e), ZU_ERR_BODY_LIMIT);
        zu_inflate_free(&z); zu_buf_free(&out);
    }

    ZU_CASE("a legitimate high-ratio body under the caps still succeeds");
    {
        static unsigned char zeros[4096];
        unsigned char comp[512];
        size_t clen = compress_with(15 + 16, zeros, sizeof zeros, comp, sizeof comp, 9);
        zu_inflate z; zu_buffer out; zu_error e;
        zu_error_clear(&e);
        zu_buf_init(&out, 0, 0);
        zu_inflate_init(&z, ZU_ENC_GZIP, 1048576, 10000);
        ZU_CHECK_EQ_INT(zu_inflate_run(&z, comp, clen, &out, &e), ZU_OK);
        ZU_CHECK_EQ_INT(out.len, sizeof zeros);
        zu_inflate_free(&z); zu_buf_free(&out);
    }

    ZU_CASE("no leaks across the suite");
    {
        zu_alloc_stats st;
        zu_alloc_stats_get(&st);
        ZU_CHECK_EQ_INT(st.live_blocks, 0);
    }
}

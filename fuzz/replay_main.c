/* A non-libFuzzer driver (design §43, §50.3).
 *
 * libFuzzer needs clang. This driver needs nothing, so the SAME harnesses run
 * as a deterministic corpus-replay regression suite on every platform and
 * compiler in CI — including Rtools on Windows, where libFuzzer is absent.
 *
 * That matters more than it looks: a crash found by fuzzing on one platform
 * becomes a corpus file, and this driver is what stops it coming back
 * anywhere else.
 *
 *   ./replay_uri corpus/uri/SEEDS    exit 0 if every input survives
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size);

int main(int argc, char **argv) {
    int i, files = 0;
    for (i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        unsigned char *buf;
        long n;
        if (!f) { fprintf(stderr, "cannot open %s\n", argv[i]); return 2; }
        if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 2; }
        n = ftell(f);
        if (n < 0) { fclose(f); return 2; }
        if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return 2; }
        buf = (unsigned char *)malloc((size_t)n ? (size_t)n : 1);
        if (!buf) { fclose(f); return 2; }
        if (n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n) {
            free(buf); fclose(f); return 2;
        }
        fclose(f);
        (void)LLVMFuzzerTestOneInput(buf, (size_t)n);
        free(buf);
        files++;
    }
    printf("replayed %d input(s) with no crash\n", files);
    return 0;
}

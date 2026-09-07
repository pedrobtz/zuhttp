#include "zu_test.h"
#include "zu_alloc.h"

int zu_test_fails = 0;
int zu_test_checks = 0;
const char *zu_test_current = "(none)";

void suite_alloc(void);
void suite_buffer(void);
void suite_error(void);
void suite_time(void);
void suite_stream(void);
void suite_headers(void);
void suite_request(void);
void suite_framing(void);
void suite_response(void);
void suite_uri(void);
void suite_redirect(void);
void suite_inflate(void);
void suite_net(void);
void suite_pool(void);
void suite_proxy(void);

int main(void) {
    zu_alloc_stats st;

    printf("zuhttp C core tests (S2 foundations + S3 wire)\n\n");
    ZU_SUITE(suite_alloc);
    ZU_SUITE(suite_error);
    ZU_SUITE(suite_buffer);
    ZU_SUITE(suite_time);
    ZU_SUITE(suite_stream);
    ZU_SUITE(suite_headers);
    ZU_SUITE(suite_request);
    ZU_SUITE(suite_framing);
    ZU_SUITE(suite_response);
    ZU_SUITE(suite_uri);
    ZU_SUITE(suite_redirect);
    ZU_SUITE(suite_inflate);
    ZU_SUITE(suite_net);
    ZU_SUITE(suite_pool);
    ZU_SUITE(suite_proxy);

    zu_alloc_stats_get(&st);
    printf("\n%d checks, %d failures\n", zu_test_checks, zu_test_fails);
    printf("allocations: %lu made, %lu freed, %lu live, peak %lu bytes\n",
           (unsigned long)st.total_allocs, (unsigned long)st.total_frees,
           (unsigned long)st.live_blocks, (unsigned long)st.peak_bytes);

    if (st.live_blocks != 0) {
        printf("LEAK: %lu blocks still live\n", (unsigned long)st.live_blocks);
        return 1;
    }
    return zu_test_fails == 0 ? 0 : 1;
}

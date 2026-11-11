/* #311: Network.framework's receive buffer stays bounded under a slow reader.
 *
 *   nwrx PORT CA    reads a 16 MiB Content-Length body from server.py's
 *                   `bulk` mode in 16 KiB reads, pausing after each one, and
 *                   fails when the backend ever held more than NW_RX_LIMIT
 *
 * White-box: the backend source is included so the test can read rx_cap,
 * which nothing outside the backend sees. Each read() used to re-arm a 64 KiB
 * receive whatever was buffered, and rx_append() reset the buffer only once
 * it was drained, so a reader slower than the network held the whole body
 * (a reviewer measured 64 MiB for a 40 MiB body). The pause makes this reader
 * slower than loopback; without it the bound holds by accident. */
#include "../../src/zuh_tls_nw.c"
#include <stdio.h>
#include <time.h>

#define BODY (16u * 1024u * 1024u)
/* Two receives' worth: the backlog under one chunk, plus the chunk that
 * arrived on top of it. The point is "bounded", not this exact figure. */
#define NW_RX_LIMIT (2u * NW_RX_CHUNK)

int main(int argc, char **argv) {
    zuh_stream *s;
    zuh_error e;
    zuh_tls_config c;
    zuh_code rc;
    char buf[16384];
    size_t total = 0, peak = 0, head = 0;
    const char *req = "GET /bulk HTTP/1.1\r\nHost: localhost\r\n\r\n";
    if (argc != 3) { fprintf(stderr, "usage: nwrx PORT CA\n"); return 2; }
    zuh_error_clear(&e);
    zuh_tls_config_init(&c);
    c.source = ZUH_TRUST_FILE; c.ca_file = argv[2];
    rc = zuh_tls_dial(&s, "localhost", (uint16_t)atoi(argv[1]), NULL, &c,
                      zuh_deadline_in(10000), NULL, &e);
    if (rc != ZUH_OK) { printf("FAIL nwrx: dial: %s\n", e.message); return 1; }
    if (zuh_stream_write(s, req, strlen(req), zuh_deadline_in(10000), &e) < 0) {
        printf("FAIL nwrx: write: %s\n", e.message);
        zuh_stream_free(s);
        return 1;
    }
    while (total < BODY + head) {
        struct timespec ts = { 0, 200000 };      /* 0.2 ms per 16 KiB read */
        zuh_ssize n = zuh_stream_read(s, buf, sizeof buf, zuh_deadline_in(10000), &e);
        nw_shared *sh = ((nw_impl *)s->impl)->sh;
        if (n <= 0) break;
        if (total == 0) {   /* the response head: count the body after it */
            const char *end = memmem(buf, (size_t)n, "\r\n\r\n", 4);
            if (end) head = (size_t)(end + 4 - buf);
        }
        total += (size_t)n;
        pthread_mutex_lock(&sh->mu);
        if (sh->rx_cap > peak) peak = sh->rx_cap;
        pthread_mutex_unlock(&sh->mu);
        nanosleep(&ts, NULL);
    }
    zuh_stream_free(s);
    if (total < BODY + head) {
        printf("FAIL nwrx: read %zu of %u body bytes\n", total - head, BODY);
        return 1;
    }
    if (peak > NW_RX_LIMIT) {
        printf("FAIL nwrx: the receive buffer reached %zu KiB (limit %u KiB)\n",
               peak >> 10, NW_RX_LIMIT >> 10);
        return 1;
    }
    printf("nwrx: %u body bytes, receive buffer peaked at %zu KiB\n", BODY, peak >> 10);
    return 0;
}

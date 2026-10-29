#include "zuh_trace.h"
#include <string.h>
#include <stdio.h>

static const char *const k_names[ZUH_EV_COUNT] = {
    "request.start",
    "dns.start",
    "dns.done",
    "connect.start",
    "connect.done",
    "tls.start",
    "tls.done",
    "request.sent",
    "headers.received",
    "body.chunk",
    "redirect.followed",
    "connection.reused",
    "request.done"
};

const char *zuh_event_name(zuh_event e) {
    if ((int)e < 0 || (int)e >= ZUH_EV_COUNT) return "?";
    return k_names[e];
}

void zuh_timings_init(zuh_timings *t) {
    if (!t) return;
    memset(t, 0, sizeof *t);
    /* Not zero: a phase that did not happen is different from one that took
     * no measurable time, and the difference is the whole point of reporting
     * dns and connect separately for a pooled connection. */
    t->dns = t->connect = t->tls = -1;
    t->request_write = t->ttfb = t->response_read = t->total = -1;
}

void zuh_trace_init(zuh_trace *t) {
    if (!t) return;
    memset(t, 0, sizeof *t);
    t->t0 = zuh_now_ms();
}

long zuh_trace_elapsed(const zuh_trace *t) {
    if (!t) return -1;
    return (long)(zuh_now_ms() - t->t0);
}

/* Copy a detail into a fixed slot, truncating honestly.
 *
 * Two things a plain strncpy() gets wrong here. A silently shortened URL
 * reads as a complete one, so a truncated detail must say so. And cutting in
 * the middle of a multi-byte character leaves invalid UTF-8 in a field that
 * init.c hands straight to mkChar() — which is how this very field once
 * reached R as undecodable bytes, from a dangling pointer rather than a split
 * character. The log must not be able to manufacture that a second way, so
 * the cut backs off to a character boundary. */
static void copy_detail(char *dst, size_t cap, const char *src) {
    size_t n, keep;
    const size_t mark = sizeof ZUH_TRACE_TRUNC - 1;

    if (!dst || cap == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    n = strlen(src);
    if (n < cap) { memcpy(dst, src, n + 1); return; }
    if (cap <= mark + 1) { dst[0] = '\0'; return; }

    /* A UTF-8 continuation byte is 10xxxxxx. If the first byte we are about
     * to drop is one, the character it belongs to started earlier, so keeping
     * up to `keep` would split it. */
    keep = cap - 1 - mark;
    while (keep > 0 && ((unsigned char)src[keep] & 0xC0) == 0x80) keep--;
    memcpy(dst, src, keep);
    memcpy(dst + keep, ZUH_TRACE_TRUNC, mark + 1);
}

void zuh_trace_add(zuh_trace *t, zuh_event e, const char *detail, uint64_t n) {
    zuh_trace_entry *slot;
    if (!t) return;
    if (t->n >= ZUH_TRACE_MAX) {
        /* A body.chunk per 16 KB means a large download would otherwise fill
         * this forever. Counting the overflow keeps the log honest — a trace
         * that silently stopped would read as a request that silently
         * stopped. */
        t->dropped++;
        return;
    }
    slot = &t->ev[t->n++];
    slot->ev    = e;
    slot->at_ms = zuh_trace_elapsed(t);
    slot->n     = n;
    copy_detail(slot->detail, sizeof slot->detail, detail);
}

void zuh_trace_add_url(zuh_trace *t, zuh_event e, const zuh_redact_policy *p,
                      const char *url, uint64_t n) {
    zuh_redact_policy dflt;
    zuh_buffer b;
    const char *s = NULL;

    if (!t) return;                       /* §35.4: off is one branch */
    if (!url) { zuh_trace_add(t, e, NULL, n); return; }
    if (!p) { zuh_redact_policy_init(&dflt); p = &dflt; }

    /* On any failure the detail is the redaction marker and never the URL:
     * running out of memory is not a reason to print a credential. */
    if (!zuh_buf_init(&b, 256, 64 * 1024)) {
        zuh_trace_add(t, e, ZUH_REDACTED, n);
        return;
    }
    if (zuh_redact_url(p, url, strlen(url), &b) && zuh_buf_cstr(&b, &s))
        zuh_trace_add(t, e, s, n);
    else
        zuh_trace_add(t, e, ZUH_REDACTED, n);
    zuh_buf_free(&b);
}

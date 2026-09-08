#include "zu_trace.h"
#include <string.h>
#include <stdio.h>

static const char *const k_names[ZU_EV_COUNT] = {
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

const char *zu_event_name(zu_event e) {
    if ((int)e < 0 || (int)e >= ZU_EV_COUNT) return "?";
    return k_names[e];
}

void zu_timings_init(zu_timings *t) {
    if (!t) return;
    memset(t, 0, sizeof *t);
    /* Not zero: a phase that did not happen is different from one that took
     * no measurable time, and the difference is the whole point of reporting
     * dns and connect separately for a pooled connection. */
    t->dns = t->connect = t->tls = -1;
    t->request_write = t->ttfb = t->response_read = t->total = -1;
}

void zu_trace_init(zu_trace *t) {
    if (!t) return;
    memset(t, 0, sizeof *t);
    t->t0 = zu_now_ms();
}

long zu_trace_elapsed(const zu_trace *t) {
    if (!t) return -1;
    return (long)(zu_now_ms() - t->t0);
}

void zu_trace_add(zu_trace *t, zu_event e, const char *detail, uint64_t n) {
    zu_trace_entry *slot;
    if (!t) return;
    if (t->n >= ZU_TRACE_MAX) {
        /* A body.chunk per 16 KB means a large download would otherwise fill
         * this forever. Counting the overflow keeps the log honest — a trace
         * that silently stopped would read as a request that silently
         * stopped. */
        t->dropped++;
        return;
    }
    slot = &t->ev[t->n++];
    slot->ev    = e;
    slot->at_ms = zu_trace_elapsed(t);
    slot->n     = n;
    if (detail) {
        snprintf(slot->detail, sizeof slot->detail, "%s", detail);
    } else {
        slot->detail[0] = '\0';
    }
}

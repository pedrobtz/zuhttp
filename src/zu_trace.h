/* zuhttp — the §35 event log and phase timings.
 *
 * §35.1 lists nine timings and §35.3 lists ten lifecycle events. Both were
 * specified and neither existed: zu_resp_timings() returned `total` alone,
 * and the only hooks were the four HTTP-level ones. The phases a user most
 * wants to see — DNS, connect, TLS handshake — were exactly the invisible
 * ones.
 *
 * COLLECTED, NOT CALLED BACK. The obvious design fires an R callback per
 * event, and it is wrong here: these events happen deep inside the connect
 * and handshake paths, where an R error would longjmp past a half-built
 * socket and a live TLS context. §27.3 describes that hazard for body
 * callbacks and mitigates it with R_tryCatch; doing the same at six more
 * call sites would multiply the risk for no gain, because a trace does not
 * need to be live to be useful — you read it after the request either way.
 *
 * So the engine appends to a fixed-capacity log with no allocation, and R
 * renders it afterwards. The cost when tracing is off is one NULL check.
 */
#ifndef ZUHTTP_TRACE_H
#define ZUHTTP_TRACE_H

#include "zu_platform.h"
#include "zu_time.h"

/* §35.3's event list. request.start and request.done bracket the whole
 * operation including retries and redirects; the rest are per hop. */
typedef enum {
    ZU_EV_REQUEST_START = 0,
    ZU_EV_DNS_START,
    ZU_EV_DNS_DONE,
    ZU_EV_CONNECT_START,
    ZU_EV_CONNECT_DONE,
    ZU_EV_TLS_START,
    ZU_EV_TLS_DONE,
    ZU_EV_REQUEST_SENT,
    ZU_EV_HEADERS_RECEIVED,
    ZU_EV_BODY_CHUNK,
    ZU_EV_REDIRECT_FOLLOWED,
    ZU_EV_CONNECTION_REUSED,
    ZU_EV_REQUEST_DONE,
    ZU_EV_COUNT
} zu_event;

const char *zu_event_name(zu_event e);

/* §35.1's timings, in milliseconds from the start of the operation. -1 means
 * "this phase did not happen", which is a real answer and not a missing one:
 * a pooled connection has no dns or connect time, and an http:// request has
 * no tls time. Zero would claim they took no time. */
typedef struct {
    long dns;
    long connect;
    long tls;
    long request_write;
    long ttfb;              /* first response byte */
    long response_read;
    long total;
    uint64_t body_bytes_wire;
    uint64_t body_bytes_decoded;
} zu_timings;

void zu_timings_init(zu_timings *t);

#define ZU_TRACE_MAX 256

typedef struct {
    zu_event ev;
    long     at_ms;         /* since the operation started */
    uint64_t n;             /* bytes, or an event-specific count */
    char     detail[64];
} zu_trace_entry;

typedef struct {
    zu_millis      t0;
    size_t         n;
    int            dropped;     /* events past ZU_TRACE_MAX */
    zu_trace_entry ev[ZU_TRACE_MAX];
} zu_trace;

void zu_trace_init(zu_trace *t);

/* Append one event. NULL trace is a no-op, which is what makes the seam free
 * when nobody is looking. `detail` may be NULL. */
void zu_trace_add(zu_trace *t, zu_event e, const char *detail, uint64_t n);

/* Milliseconds since the trace started, for filling zu_timings. */
long zu_trace_elapsed(const zu_trace *t);

#endif /* ZUHTTP_TRACE_H */

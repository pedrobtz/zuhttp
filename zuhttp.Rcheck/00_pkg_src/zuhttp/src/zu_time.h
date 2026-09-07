/* zuhttp — monotonic time and deadline composition.
 *
 * Design §24.4 (monotonic clocks only — a system clock adjustment mid-request
 * must not move a deadline) and §24.2 (the composition rule).
 */
#ifndef ZUHTTP_TIME_H
#define ZUHTTP_TIME_H

#include "zu_platform.h"

typedef int64_t zu_millis;

/* Monotonic milliseconds since an unspecified epoch. Never wall time. */
zu_millis zu_now_ms(void);

typedef struct {
    zu_millis at;        /* absolute monotonic ms */
    int       infinite;  /* 1 => never expires */
} zu_deadline;

zu_deadline zu_deadline_never(void);
zu_deadline zu_deadline_in(zu_millis ms);       /* ms < 0 => never */
zu_deadline zu_deadline_at(zu_millis at);

/* Milliseconds until expiry: <= 0 means expired. INT_MAX-ish for infinite. */
zu_millis zu_deadline_remaining(zu_deadline d);
int       zu_deadline_expired(zu_deadline d);

/* Design §24.2:  effective = min(now + phase_timeout, request_deadline)
 *
 * This is the whole timeout model in one function. `phase_ms` < 0 means the
 * phase is unbounded, in which case the total deadline alone applies. */
zu_deadline zu_deadline_min(zu_deadline a, zu_deadline b);
zu_deadline zu_deadline_phase(zu_deadline total, zu_millis phase_ms);

/* Clamp a remaining interval into the int milliseconds poll() wants, never
 * exceeding `tick` so the caller returns to an interrupt checkpoint (§25.1). */
int zu_deadline_poll_ms(zu_deadline d, int tick_ms);

#endif /* ZUHTTP_TIME_H */

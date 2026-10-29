/* zuhttp — monotonic time and deadline composition.
 *
 * Design §24.4 (monotonic clocks only — a system clock adjustment mid-request
 * must not move a deadline) and §24.2 (the composition rule).
 */
#ifndef ZUHTTP_TIME_H
#define ZUHTTP_TIME_H

#include "zuh_platform.h"

typedef int64_t zuh_millis;

/* Monotonic milliseconds since an unspecified epoch. Never wall time. */
zuh_millis zuh_now_ms(void);

typedef struct {
    zuh_millis at;        /* absolute monotonic ms */
    int       infinite;  /* 1 => never expires */
} zuh_deadline;

zuh_deadline zuh_deadline_never(void);
zuh_deadline zuh_deadline_in(zuh_millis ms);       /* ms < 0 => never */
zuh_deadline zuh_deadline_at(zuh_millis at);

/* Milliseconds until expiry: <= 0 means expired. INT_MAX-ish for infinite. */
zuh_millis zuh_deadline_remaining(zuh_deadline d);
int       zuh_deadline_expired(zuh_deadline d);

/* Design §24.2:  effective = min(now + phase_timeout, request_deadline)
 *
 * This is the whole timeout model in one function. `phase_ms` < 0 means the
 * phase is unbounded, in which case the total deadline alone applies. */
zuh_deadline zuh_deadline_min(zuh_deadline a, zuh_deadline b);
zuh_deadline zuh_deadline_phase(zuh_deadline total, zuh_millis phase_ms);

/* Clamp a remaining interval into the int milliseconds poll() wants, never
 * exceeding `tick` so the caller returns to an interrupt checkpoint (§25.1). */
int zuh_deadline_poll_ms(zuh_deadline d, int tick_ms);

#endif /* ZUHTTP_TIME_H */

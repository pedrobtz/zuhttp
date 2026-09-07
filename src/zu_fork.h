/* zuhttp — the fork guard (design §26.4).
 *
 * Shared deliberately. §26.4 has TWO hazards with one mechanism:
 *
 *   1. a forked child inherits the parent's pooled TLS connections, and both
 *      writing into the same session corrupts it (zu_pool);
 *   2. on macOS the system trust evaluator does not survive fork() at all —
 *      Security.framework's XPC connection to trustd is dead in the child and
 *      calling it SIGSEGVs the worker (the trust backend).
 *
 * Hazard 2 is why this is not a member of zu_pool: dropping inherited sockets
 * does not help when the child cannot call the trust API in the first place.
 * S0 finding F-5 measured it — see spike/macos-tls/FINDINGS.md.
 *
 * pthread_atfork() is not sufficient and does not exist on Windows. Comparing
 * the PID on every use is the portable mechanism (§26.4).
 */
#ifndef ZUHTTP_FORK_H
#define ZUHTTP_FORK_H

#include "zu_platform.h"

/* Current process id as a long. On Windows this is GetCurrentProcessId(). */
long zu_pid_current(void);

typedef struct {
    long owner_pid;
    int  armed;
} zu_fork_guard;

/* Record the calling process as the owner. */
void zu_fork_guard_arm(zu_fork_guard *g);

/* 1 if the caller is NOT the process that armed the guard, i.e. we are in a
 * fork()ed child. 0 if the guard was never armed — an unarmed guard has no
 * owner to differ from, so it cannot have been inherited. */
int zu_fork_guard_tripped(const zu_fork_guard *g);

/* The user-facing explanation for hazard 2. One canonical wording so the R
 * condition, the documentation and the C error cannot drift (§34, §6.1). */
const char *zu_fork_message(void);

#endif /* ZUHTTP_FORK_H */

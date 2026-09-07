#include "zu_fork.h"

#if defined(ZU_WINDOWS)
#  include <windows.h>
#else
#  include <unistd.h>
#endif

long zu_pid_current(void) {
#if defined(ZU_WINDOWS)
    return (long)GetCurrentProcessId();
#else
    return (long)getpid();
#endif
}

void zu_fork_guard_arm(zu_fork_guard *g) {
    if (!g) return;
    g->owner_pid = zu_pid_current();
    g->armed = 1;
}

int zu_fork_guard_tripped(const zu_fork_guard *g) {
    if (!g || !g->armed) return 0;
    return g->owner_pid != zu_pid_current();
}

const char *zu_fork_message(void) {
    return
        "zuhttp cannot make HTTPS requests in a forked process on macOS.\n"
        "  The system trust evaluator (Security.framework) does not survive "
        "fork().\n"
        "  * Use a PSOCK cluster or future::plan(\"multisession\") instead of\n"
        "    mclapply() / future::plan(\"multicore\").\n"
        "  * See ?zuhttp_fork.";
}

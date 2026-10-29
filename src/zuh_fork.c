/* getpid() lives behind glibc's __USE_POSIX, which -std=c99 does not enable
 * on its own. It happens to compile today, but zuh_net.c and zuh_time.c both
 * carry this preamble for the same reason and the third file silently not
 * carrying it is exactly how the zuh_time.c defect survived (see 3d2bd18).
 * MUST precede every system header. */
#if !defined(_WIN32)
#  if defined(__APPLE__)
#    define _DARWIN_C_SOURCE
#  else
#    define _POSIX_C_SOURCE 200112L
#  endif
#endif

#include "zuh_fork.h"

#if defined(ZUH_WINDOWS)
#  include <windows.h>
#else
#  include <unistd.h>
#endif

long zuh_pid_current(void) {
#if defined(ZUH_WINDOWS)
    return (long)GetCurrentProcessId();
#else
    return (long)getpid();
#endif
}

void zuh_fork_guard_arm(zuh_fork_guard *g) {
    if (!g) return;
    g->owner_pid = zuh_pid_current();
    g->armed = 1;
}

int zuh_fork_guard_tripped(const zuh_fork_guard *g) {
    if (!g || !g->armed) return 0;
    return g->owner_pid != zuh_pid_current();
}

const char *zuh_fork_message(void) {
    return
        "zuhttp cannot make HTTPS requests in a forked process on macOS.\n"
        "  The system trust evaluator (Security.framework) does not survive "
        "fork().\n"
        "  * Use a PSOCK cluster or future::plan(\"multisession\") instead of\n"
        "    mclapply() / future::plan(\"multicore\").\n"
        "  * See ?zuhttp_fork.";
}

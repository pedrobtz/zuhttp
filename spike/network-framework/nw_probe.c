/* Network.framework probe — D-63 / W13, 2026-09-26.
 *
 * Measures the cells design §13.2 left "unmeasured", which F-11
 * (spike/macos-engine/FINDINGS.md) rejected on reading the API rather than
 * running it:
 *
 *   1. trust is decided by OUR SecTrustEvaluateWithError, via the verify block
 *   2. TLS 1.3 is negotiated
 *   3. an nw_connection can be driven from a synchronous poll() loop, with
 *      every completion bridged to a pipe (the §25.1 model)
 *   4. nw_connection_cancel() from that loop ends a stalled connect promptly
 *   5. native HTTP CONNECT (macOS 14+) reaches an origin through a proxy
 *   6. it builds warning-free at an old deployment target (no --as-cran NOTE)
 *
 * Build:  make   (see Makefile; -mmacosx-version-min=11.0, -Werror)
 * Usage:  ./nw_probe get HOST [PROXYHOST PROXYPORT]
 *         ./nw_probe anchors-only HOST      (trust only an empty anchor set:
 *                                            must FAIL, proving the block decides)
 *         ./nw_probe cancel MS              (connect to a black hole, cancel at MS)
 *         ./nw_probe fork HOST              (request in the parent, then in a
 *                                            forked child: §26.4 hazard 2)
 */
#include <Network/Network.h>
#include <Security/Security.h>
#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/wait.h>
#include <unistd.h>

static int pipefd[2];
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static char rxbuf[1 << 16];
static size_t rxlen;
static int rx_done, verify_ran, anchors_only;
static char errmsg[256];

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

static int thread_count(void) {
    thread_act_array_t t;
    mach_msg_type_number_t n = 0;
    if (task_threads(mach_task_self(), &t, &n) != KERN_SUCCESS) return -1;
    vm_deallocate(mach_task_self(), (vm_address_t)t, n * sizeof *t);
    return (int)n;
}

/* Completions run on Network.framework's queue. They touch only C state under
 * the mutex and write one byte to the pipe — never anything that would be the
 * R API in zuhttp. The poll loop on the main thread is the only consumer. */
static void signal_main(char c) { ssize_t r = write(pipefd[1], &c, 1); (void)r; }

/* One poll slice at a time, as §25.1 requires; returns the event byte or 0 on
 * deadline. `slices` counts the R_CheckUserInterrupt() opportunities. */
static char wait_event(double deadline_ms, int *slices) {
    for (;;) {
        double left = deadline_ms - now_ms();
        struct pollfd p = { pipefd[0], POLLIN, 0 };
        int to = left < 0 ? 0 : (left > 100 ? 100 : (int)left);
        if (poll(&p, 1, to) > 0) { char c; if (read(pipefd[0], &c, 1) == 1) return c; }
        if (slices) (*slices)++;
        if (now_ms() >= deadline_ms) return 0;
    }
}

static void receive_loop(nw_connection_t c) {
    nw_connection_receive(c, 1, 65536,
        ^(dispatch_data_t content, nw_content_context_t ctx, bool complete, nw_error_t err) {
        (void)ctx;
        if (content) {
            dispatch_data_apply(content, ^bool(dispatch_data_t r, size_t off, const void *buf, size_t len) {
                (void)r; (void)off;
                pthread_mutex_lock(&mu);
                if (rxlen + len < sizeof rxbuf) { memcpy(rxbuf + rxlen, buf, len); rxlen += len; }
                pthread_mutex_unlock(&mu);
                return true;
            });
        }
        if (complete || err) { rx_done = 1; signal_main('E'); return; }
        signal_main('D');
        receive_loop(c);
    });
}

static nw_parameters_t make_params(const char *host, const char *phost, const char *pport) {
    char *h = strdup(host);
    nw_parameters_t params = nw_parameters_create_secure_tcp(
        ^(nw_protocol_options_t tls) {
            sec_protocol_options_t so = nw_tls_copy_sec_protocol_options(tls);
            sec_protocol_options_set_min_tls_protocol_version(so, tls_protocol_version_TLSv12);
            sec_protocol_options_add_tls_application_protocol(so, "http/1.1");
            /* §13.1: the engine is Apple's, the trust decision is ours. */
            sec_protocol_options_set_verify_block(so,
                ^(sec_protocol_metadata_t md, sec_trust_t st, sec_protocol_verify_complete_t done) {
                (void)md;
                SecTrustRef tr = sec_trust_copy_ref(st);
                SecPolicyRef pol = SecPolicyCreateSSL(true, CFStringCreateWithCString(NULL, h, kCFStringEncodingUTF8));
                CFErrorRef e = NULL;
                bool ok;
                SecTrustSetPolicies(tr, pol);
                if (anchors_only) {                  /* ca_file semantics, empty */
                    CFArrayRef none = CFArrayCreate(NULL, NULL, 0, &kCFTypeArrayCallBacks);
                    SecTrustSetAnchorCertificates(tr, none);
                    SecTrustSetAnchorCertificatesOnly(tr, true);
                    CFRelease(none);
                }
                ok = SecTrustEvaluateWithError(tr, &e);
                verify_ran = 1;
                if (e) CFRelease(e);
                CFRelease(pol); CFRelease(tr);
                done(ok);
            }, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0));
            sec_release(so);
        },
        NW_PARAMETERS_DEFAULT_CONFIGURATION);

    if (phost) {
        if (__builtin_available(macOS 14.0, *)) {
            nw_endpoint_t pe = nw_endpoint_create_host(phost, pport);
            nw_proxy_config_t pc = nw_proxy_config_create_http_connect(pe, NULL);
            nw_privacy_context_t ctx = nw_privacy_context_create("zuhttp-probe");
            nw_privacy_context_add_proxy(ctx, pc);
            nw_parameters_set_privacy_context(params, ctx);
            nw_release(ctx); nw_release(pc); nw_release(pe);
        } else {
            fprintf(stderr, "native CONNECT needs macOS 14\n");
            exit(2);
        }
    }
    return params;
}

static nw_connection_t start(const char *host, const char *port, nw_parameters_t params) {
    nw_endpoint_t ep = nw_endpoint_create_host(host, port);
    nw_connection_t c = nw_connection_create(ep, params);
    nw_connection_set_queue(c, dispatch_queue_create("zuhttp.nw", DISPATCH_QUEUE_SERIAL));
    nw_connection_set_state_changed_handler(c, ^(nw_connection_state_t s, nw_error_t err) {
        if (s == nw_connection_state_ready) signal_main('R');
        else if (s == nw_connection_state_failed || (s == nw_connection_state_waiting && err)) {
            if (err) snprintf(errmsg, sizeof errmsg, "domain %d code %d",
                              (int)nw_error_get_error_domain(err), nw_error_get_error_code(err));
            signal_main('F');
        } else if (s == nw_connection_state_cancelled) signal_main('C');
    });
    nw_connection_start(c);
    nw_release(ep);
    return c;
}

static int cmd_get(const char *host, const char *phost, const char *pport) {
    int slices = 0, th0 = thread_count();
    double t0 = now_ms();
    nw_connection_t c = start(host, "443", make_params(host, phost, pport));
    char ev = wait_event(t0 + 15000, &slices);
    double t_ready = now_ms() - t0;
    if (ev != 'R') {
        printf("RESULT %s: connect failed (event '%c', %s, verify_ran=%d) after %.1f ms\n",
               anchors_only ? "anchors-only" : "get", ev ? ev : '-', errmsg, verify_ran, t_ready);
        nw_connection_cancel(c);
        return anchors_only ? (verify_ran ? 0 : 1) : 1;
    }
    {
        nw_protocol_metadata_t md = nw_connection_copy_protocol_metadata(c, nw_protocol_copy_tls_definition());
        sec_protocol_metadata_t sm = nw_tls_copy_sec_protocol_metadata(md);
        tls_protocol_version_t v = sec_protocol_metadata_get_negotiated_tls_protocol_version(sm);
        printf("ready in %.1f ms  tls=%s  verify_block_ran=%d  proxy=%s\n", t_ready,
               v == tls_protocol_version_TLSv13 ? "1.3" : v == tls_protocol_version_TLSv12 ? "1.2" : "?",
               verify_ran, phost ? phost : "none");
        sec_release(sm); nw_release(md);
    }
    {
        char req[512];
        int n = snprintf(req, sizeof req, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host);
        dispatch_data_t d = dispatch_data_create(req, (size_t)n, NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
        nw_connection_send(c, d, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, ^(nw_error_t e) { (void)e; });
        dispatch_release(d);
    }
    receive_loop(c);
    while (!rx_done && wait_event(now_ms() + 10000, &slices)) {}
    pthread_mutex_lock(&mu);
    {
        char *eol = memchr(rxbuf, '\r', rxlen);
        printf("status line: %.*s   bytes=%zu\n", eol ? (int)(eol - rxbuf) : 0, rxbuf, rxlen);
    }
    pthread_mutex_unlock(&mu);
    printf("poll slices=%d  threads %d -> %d\n", slices, th0, thread_count());
    nw_connection_cancel(c);
    wait_event(now_ms() + 2000, NULL);
    printf("RESULT get: %s\n", (rxlen > 12 && !memcmp(rxbuf, "HTTP/1.1 ", 9) && verify_ran) ? "PASS" : "FAIL");
    return 0;
}

static int cmd_cancel(int after_ms) {
    /* A non-routable address: the connect never completes on its own. */
    nw_connection_t c = start("10.255.255.1", "443", make_params("10.255.255.1", NULL, NULL));
    double t0 = now_ms();
    char ev = wait_event(t0 + after_ms, NULL);
    double t_cancel = now_ms();
    if (ev) { printf("unexpected early event '%c'\n", ev); return 1; }
    nw_connection_cancel(c);
    while ((ev = wait_event(t_cancel + 5000, NULL)) && ev != 'C') {}
    printf("RESULT cancel: cancelled-state after %.1f ms (%s)\n", now_ms() - t_cancel,
           ev == 'C' ? "PASS" : "FAIL: no cancelled state");
    return ev == 'C' ? 0 : 1;
}

static int cmd_fork(const char *host) {
    pid_t pid;
    int st = 0;
    cmd_get(host, NULL, NULL);                  /* parent has used the stack */
    fflush(stdout);
    pid = fork();
    if (pid == 0) {
        rxlen = 0; rx_done = 0; verify_ran = 0;
        _exit(cmd_get(host, NULL, NULL));
    }
    waitpid(pid, &st, 0);
    if (WIFSIGNALED(st))
        printf("RESULT fork: child KILLED by signal %d\n", WTERMSIG(st));
    else
        printf("RESULT fork: child exited %d\n", WEXITSTATUS(st));
    return 0;
}

int main(int argc, char **argv) {
    if (pipe(pipefd) != 0) return 1;
    if (argc >= 3 && !strcmp(argv[1], "get"))
        return cmd_get(argv[2], argc >= 5 ? argv[3] : NULL, argc >= 5 ? argv[4] : NULL);
    if (argc >= 3 && !strcmp(argv[1], "anchors-only")) { anchors_only = 1; return cmd_get(argv[2], NULL, NULL); }
    if (argc >= 3 && !strcmp(argv[1], "cancel")) return cmd_cancel(atoi(argv[2]));
    if (argc >= 3 && !strcmp(argv[1], "fork")) return cmd_fork(argv[2]);
    fprintf(stderr, "usage: see file header\n");
    return 2;
}

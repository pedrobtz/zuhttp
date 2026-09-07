/* Does SecTrustEvaluateWithError survive fork()?  (design §26.4) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <Security/Security.h>

static CFDataRef load_der(const char *path) {
    FILE *f = fopen(path, "rb"); if (!f) return NULL;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *b = malloc(n);
    if (fread(b, 1, n, f) != (size_t)n) { fclose(f); free(b); return NULL; }
    fclose(f);
    CFDataRef d = CFDataCreate(NULL, b, n); free(b); return d;
}

static void eval_once(const char *tag, CFDataRef der) {
    SecCertificateRef c = SecCertificateCreateWithData(NULL, der);
    SecPolicyRef p = SecPolicyCreateSSL(true, CFSTR("localhost"));
    CFMutableArrayRef certs = CFArrayCreateMutable(NULL, 1, &kCFTypeArrayCallBacks);
    CFArrayAppendValue(certs, c);
    SecTrustRef t = NULL;
    OSStatus s = SecTrustCreateWithCertificates(certs, p, &t);
    fprintf(stderr, "[%s] create -> %d\n", tag, (int)s);
    fflush(stderr);
    if (t) {
        CFErrorRef e = NULL;
        bool ok = SecTrustEvaluateWithError(t, &e);   /* <-- talks to trustd */
        fprintf(stderr, "[%s] evaluate -> %d (this line means the call returned)\n", tag, (int)ok);
        if (e) CFRelease(e);
        CFRelease(t);
    }
    CFRelease(certs); CFRelease(p); CFRelease(c);
    fflush(stderr);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: forktest cert.der\n"); return 2; }
    CFDataRef der = load_der(argv[1]);
    if (!der) { fprintf(stderr, "cannot load %s\n", argv[1]); return 2; }

    if (argc < 3 || strcmp(argv[2], "--no-parent-eval") != 0)
        eval_once("parent-before-fork", der);
    else
        fprintf(stderr, "[parent] skipped pre-fork evaluation\n");

    pid_t pid = fork();
    if (pid == 0) { eval_once("CHILD-after-fork", der); fprintf(stderr, "[CHILD] SURVIVED\n"); _exit(0); }
    int st = 0; waitpid(pid, &st, 0);
    if (WIFSIGNALED(st)) fprintf(stderr, "[parent] child KILLED by signal %d\n", WTERMSIG(st));
    else fprintf(stderr, "[parent] child exited %d\n", WEXITSTATUS(st));
    return 0;
}

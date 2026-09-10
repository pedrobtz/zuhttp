/* Does Secure Transport still work on current macOS, over a CALLER-OWNED
 * socket (SSLSetIOFuncs), and what does it actually negotiate?
 *
 * "Deprecated" is not "removed", and the §9 stream abstraction needs TLS over
 * a socket we own — which is precisely what Network.framework cannot do.
 */
#include <Security/SecureTransport.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static OSStatus rd(SSLConnectionRef c, void *data, size_t *len) {
    size_t want = *len;
    ssize_t n = read(*(const int *)c, data, want);
    if (n > 0) { *len = (size_t)n; return (size_t)n < want ? errSSLWouldBlock : noErr; }
    *len = 0;
    return n == 0 ? errSSLClosedGraceful : errSSLWouldBlock;
}
static OSStatus wr(SSLConnectionRef c, const void *data, size_t *len) {
    size_t want = *len;
    ssize_t n = write(*(const int *)c, data, want);
    if (n > 0) { *len = (size_t)n; return (size_t)n < want ? errSSLWouldBlock : noErr; }
    *len = 0;
    return errSSLWouldBlock;
}

int main(void) {
    struct addrinfo hints, *res;
    SSLContextRef ctx;
    OSStatus st;
    SSLProtocol negotiated = kSSLProtocolUnknown;
    SSLCipherSuite cipher = 0;
    const char *host = "example.com";
    int fd;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, "443", &hints, &res) != 0) { puts("dns failed"); return 1; }
    fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0 || connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        puts("connect failed"); return 1;
    }
    freeaddrinfo(res);

    ctx = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
    if (!ctx) { puts("SSLCreateContext returned NULL: the API is GONE, not merely deprecated"); return 1; }
    SSLSetIOFuncs(ctx, rd, wr);            /* caller-owned socket: the §9 model */
    SSLSetConnection(ctx, &fd);
    SSLSetPeerDomainName(ctx, host, strlen(host));
    SSLSetProtocolVersionMin(ctx, kTLSProtocol12);

    do { st = SSLHandshake(ctx); } while (st == errSSLWouldBlock);
    if (st != noErr) { printf("handshake failed: OSStatus %d\n", (int)st); return 1; }

    SSLGetNegotiatedProtocolVersion(ctx, &negotiated);
    SSLGetNegotiatedCipher(ctx, &cipher);
    printf("Secure Transport WORKS over a caller-owned socket on this macOS.\n");
    printf("  negotiated : %s (enum %d)\n",
           negotiated == kTLSProtocol12 ? "TLS 1.2" :
           negotiated == kTLSProtocol11 ? "TLS 1.1" : "other", (int)negotiated);
    printf("  cipher     : 0x%04x\n", (unsigned)cipher);
    printf("  ceiling    : TLS 1.2 -- kTLSProtocol13 does not exist in the SDK\n");

    SSLClose(ctx);
    CFRelease(ctx);
    close(fd);
    return 0;
}

/* zuhttp — HTTP/2 over a zuh_stream, driven by vendored nghttp2 (design §65).
 *
 * An HTTP/2 connection is itself a zuh_stream: a wrapper that owns the
 * transport (TLS that negotiated "h2", or TCP for prior-knowledge h2c) and one
 * nghttp2_session. Being a stream is what lets the §26 pool keep it unchanged:
 * the pool stores, probes, evicts and frees it like any other connection, and
 * the session's lifetime is the connection's (§65.2).
 *
 * nghttp2 never sees a socket. The driver moves bytes between the inner stream
 * and nghttp2_session_mem_recv2() / nghttp2_session_mem_send2(), so every wait
 * is the inner stream's: deadlines (§24), the §25.1 interrupt tick and the
 * §35 trace work exactly as they do for HTTP/1.1.
 *
 * The engine is synchronous (D-67), so a connection carries at most one open
 * stream; "multiplexing" is the next request reusing the connection with a new
 * stream id and no handshake.
 *
 * The read/write vtable entries of the wrapper fail: bytes on an HTTP/2
 * connection only make sense as frames, and a caller that treated the wrapper
 * as a byte stream would corrupt the session.
 */
#ifndef ZUHTTP_H2_H
#define ZUHTTP_H2_H

#include "zuh_platform.h"
#include "zuh_error.h"
#include "zuh_stream.h"
#include "zuh_headers.h"
#include "zuh_body.h"
#include "zuh_time.h"

/* §65.1. Mirrors zu_client(http2 = ): AUTO is the zeroed default, so a
 * zuh_get_opts that never set it offers h2 by ALPN and uses it when chosen. */
typedef enum {
    ZUH_H2_AUTO = 0,
    ZUH_H2_REQUIRED,
    ZUH_H2_OFF
} zuh_h2_mode;

/* The ALPN preference list a mode offers, comma-separated (§15). */
const char *zuh_h2_alpn_for(zuh_h2_mode m);

/* Does this ALPN selection mean HTTP/2? */
int zuh_h2_alpn_is_h2(const char *selected);

/* Wrap an established transport. On success *out owns `inner` and starts the
 * connection preface and SETTINGS (§65.2), which go out with the first
 * request. On failure `inner` is untouched and still the caller's.
 * `max_header_bytes` is §40's limit, advertised as
 * SETTINGS_MAX_HEADER_LIST_SIZE and enforced on every header block. */
zuh_code zuh_h2_wrap(zuh_stream **out, zuh_stream *inner,
                     size_t max_header_bytes, zuh_error *err);

/* Is `s` an HTTP/2 connection made by zuh_h2_wrap()? */
int zuh_h2_is(const zuh_stream *s);

/* The transport under an HTTP/2 connection, for the §35.2 metadata (TLS
 * version, peer address) that lives on it. `s` itself for any other stream. */
zuh_stream *zuh_h2_transport(zuh_stream *s);

/* One request: pseudo-header values, the regular header block (validated
 * and §17-defaulted by the caller) and an in-memory body. */
typedef struct {
    const char        *method;
    const char        *scheme;      /* "https" or "http" */
    const char        *authority;   /* host[:port], what Host would carry */
    const char        *path;        /* origin-form target */
    const zuh_headers *headers;
    const void        *body;
    size_t             body_len;
} zuh_h2_request;

/* Open a stream, send the request, and read until the final response's
 * header block: 1xx responses are skipped as §18 skips them. `status` and
 * `headers` receive the final response; `*bodiless` is set when that block
 * ended the stream (HEAD, 204, 304, a Trailers-Only response).
 *
 * Connection-specific request headers are not sent (RFC 9113 §8.2.2): Host
 * becomes :authority, and Connection, Keep-Alive, Proxy-Connection,
 * Transfer-Encoding and Upgrade are dropped. A `te` other than "trailers" is
 * ZUH_ERR_PARSE before any byte of the request is written. */
zuh_code zuh_h2_begin(zuh_stream *conn, const zuh_h2_request *rq,
                      int *status, zuh_headers *headers, int *bodiless,
                      zuh_deadline dl, zuh_error *err);

/* Deliver the response body into `pipe` until the stream ends. The pipe
 * enforces max_body and decoding exactly as for HTTP/1.1 (§21, §40). */
zuh_code zuh_h2_body(zuh_stream *conn, zuh_body_pipe *pipe,
                     zuh_deadline dl, zuh_error *err);

/* §26.3 for HTTP/2: may another request be sent on this connection? No once
 * the last stream ended in anything but a clean close, the peer sent GOAWAY,
 * the stream ids are exhausted, or the session failed. */
int zuh_h2_reusable(zuh_stream *conn);

#endif /* ZUHTTP_H2_H */

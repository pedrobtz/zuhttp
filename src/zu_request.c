#include "zu_request.h"
#include "zu_alloc.h"
#include <string.h>

void zu_request_init(zu_request *r) {
    memset(r, 0, sizeof *r);
    zu_headers_init(&r->headers);
    r->form = ZU_TARGET_ORIGIN;
    r->body = ZU_BODY_NONE;
}

void zu_request_free(zu_request *r) {
    if (!r) return;
    zu_headers_free(&r->headers);
}

int zu_method_valid(const char *method) {
    /* Same token rule as a header name (§17.1). */
    return method && zu_header_name_valid(method, strlen(method));
}

int zu_target_valid(const char *target) {
    size_t i;
    if (!target || !*target) return 0;
    for (i = 0; target[i]; i++) {
        unsigned char c = (unsigned char)target[i];
        if (c <= 0x20 || c == 0x7F) return 0;   /* CTLs, SP, DEL */
    }
    return 1;
}

zu_code zu_request_add_defaults(zu_request *r, const char *user_agent) {
    zu_code rc;
    if (!r) return ZU_ERR_PARSE;

    /* Host is mandatory in HTTP/1.1 and is derived, never caller-supplied to a
     * conflicting value (§17.2). CONNECT carries the authority in the target. */
    if (r->host && !zu_headers_has(&r->headers, "Host")) {
        rc = zu_headers_add_str(&r->headers, "Host", r->host);
        if (rc != ZU_OK) return rc;
    }
    if (!zu_headers_has(&r->headers, "User-Agent")) {
        rc = zu_headers_add_str(&r->headers, "User-Agent",
                                user_agent ? user_agent : "zuhttp/0.0.0.9000");
        if (rc != ZU_OK) return rc;
    }
    if (!zu_headers_has(&r->headers, "Accept")) {
        rc = zu_headers_add_str(&r->headers, "Accept", "*/*");
        if (rc != ZU_OK) return rc;
    }
    /* §21.2: gzip by default, and decode transparently. */
    if (!zu_headers_has(&r->headers, "Accept-Encoding")) {
        rc = zu_headers_add_str(&r->headers, "Accept-Encoding", "gzip");
        if (rc != ZU_OK) return rc;
    }
    if (!zu_headers_has(&r->headers, "Connection")) {
        rc = zu_headers_add_str(&r->headers, "Connection", "keep-alive");
        if (rc != ZU_OK) return rc;
    }
    return ZU_OK;
}

zu_code zu_request_write(const zu_request *r, zu_buffer *out) {
    if (!r || !out) return ZU_ERR_PARSE;

    if (!zu_method_valid(r->method)) return ZU_ERR_PARSE;
    if (!zu_target_valid(r->target)) return ZU_ERR_PARSE;

    /* HTTP/1.1 requires Host. Its absence is a bug in the caller, not a
     * degraded request to send anyway. */
    if (r->form != ZU_TARGET_AUTHORITY && !zu_headers_has(&r->headers, "Host"))
        return ZU_ERR_PARSE;

    /* A request may be framed by length or by chunking, never both (§18.1
     * applies to requests we generate just as much as responses we accept). */
    if (zu_headers_has(&r->headers, "Content-Length") &&
        zu_headers_has(&r->headers, "Transfer-Encoding"))
        return ZU_ERR_PARSE;

    if (!zu_buf_append_str(out, r->method))  return ZU_ERR_NOMEM;
    if (!zu_buf_append_byte(out, ' '))       return ZU_ERR_NOMEM;
    if (!zu_buf_append_str(out, r->target))  return ZU_ERR_NOMEM;
    if (!zu_buf_append_str(out, " HTTP/1.1\r\n")) return ZU_ERR_NOMEM;

    if (!zu_headers_write(&r->headers, out)) return ZU_ERR_NOMEM;

    /* Body framing headers are emitted from the struct, not trusted from the
     * caller's header list, so the two can never disagree on the wire. */
    if (r->body == ZU_BODY_LENGTH) {
        if (!zu_headers_has(&r->headers, "Content-Length")) {
            if (!zu_buf_append_str(out, "Content-Length: ")) return ZU_ERR_NOMEM;
            if (!zu_buf_append_u64(out, r->content_length))  return ZU_ERR_NOMEM;
            if (!zu_buf_append_str(out, "\r\n"))             return ZU_ERR_NOMEM;
        }
    } else if (r->body == ZU_BODY_CHUNKED) {
        if (!zu_headers_has(&r->headers, "Transfer-Encoding")) {
            if (!zu_buf_append_str(out, "Transfer-Encoding: chunked\r\n"))
                return ZU_ERR_NOMEM;
        }
    }

    if (!zu_buf_append_str(out, "\r\n")) return ZU_ERR_NOMEM;
    return ZU_OK;
}

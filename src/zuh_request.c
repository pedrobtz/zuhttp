#include "zuh_request.h"
#include "zuh_alloc.h"
#include <string.h>

void zuh_request_init(zuh_request *r) {
    memset(r, 0, sizeof *r);
    zuh_headers_init(&r->headers);
    r->form = ZUH_TARGET_ORIGIN;
    r->body = ZUH_BODY_NONE;
}

void zuh_request_free(zuh_request *r) {
    if (!r) return;
    zuh_headers_free(&r->headers);
}

int zuh_method_valid(const char *method) {
    /* Same token rule as a header name (§17.1). */
    return method && zuh_header_name_valid(method, strlen(method));
}

int zuh_target_valid(const char *target) {
    size_t i;
    if (!target || !*target) return 0;
    for (i = 0; target[i]; i++) {
        unsigned char c = (unsigned char)target[i];
        if (c <= 0x20 || c == 0x7F) return 0;   /* CTLs, SP, DEL */
    }
    return 1;
}

zuh_code zuh_request_add_defaults(zuh_request *r, const char *user_agent) {
    zuh_code rc;
    if (!r) return ZUH_ERR_PARSE;

    /* Host is mandatory in HTTP/1.1 and is derived, never caller-supplied to a
     * conflicting value (§17.2). CONNECT carries the authority in the target. */
    if (r->host && !zuh_headers_has(&r->headers, "Host")) {
        rc = zuh_headers_add_str(&r->headers, "Host", r->host);
        if (rc != ZUH_OK) return rc;
    }
    if (!zuh_headers_has(&r->headers, "User-Agent")) {
        rc = zuh_headers_add_str(&r->headers, "User-Agent",
                                user_agent ? user_agent : "zuhttp/0.0.0.9000");
        if (rc != ZUH_OK) return rc;
    }
    if (!zuh_headers_has(&r->headers, "Accept")) {
        rc = zuh_headers_add_str(&r->headers, "Accept", "*/*");
        if (rc != ZUH_OK) return rc;
    }
    /* §21.2: gzip by default, and decode transparently. */
    if (!zuh_headers_has(&r->headers, "Accept-Encoding")) {
        rc = zuh_headers_add_str(&r->headers, "Accept-Encoding", "gzip");
        if (rc != ZUH_OK) return rc;
    }
    if (!zuh_headers_has(&r->headers, "Connection")) {
        rc = zuh_headers_add_str(&r->headers, "Connection", "keep-alive");
        if (rc != ZUH_OK) return rc;
    }
    return ZUH_OK;
}

zuh_code zuh_request_write(const zuh_request *r, zuh_buffer *out) {
    if (!r || !out) return ZUH_ERR_PARSE;

    if (!zuh_method_valid(r->method)) return ZUH_ERR_PARSE;
    if (!zuh_target_valid(r->target)) return ZUH_ERR_PARSE;

    /* HTTP/1.1 requires Host. Its absence is a bug in the caller, not a
     * degraded request to send anyway. */
    if (r->form != ZUH_TARGET_AUTHORITY && !zuh_headers_has(&r->headers, "Host"))
        return ZUH_ERR_PARSE;

    /* A request may be framed by length or by chunking, never both (§18.1
     * applies to requests we generate just as much as responses we accept). */
    if (zuh_headers_has(&r->headers, "Content-Length") &&
        zuh_headers_has(&r->headers, "Transfer-Encoding"))
        return ZUH_ERR_PARSE;

    if (!zuh_buf_append_str(out, r->method))  return ZUH_ERR_NOMEM;
    if (!zuh_buf_append_byte(out, ' '))       return ZUH_ERR_NOMEM;
    if (!zuh_buf_append_str(out, r->target))  return ZUH_ERR_NOMEM;
    if (!zuh_buf_append_str(out, " HTTP/1.1\r\n")) return ZUH_ERR_NOMEM;

    if (!zuh_headers_write(&r->headers, out)) return ZUH_ERR_NOMEM;

    /* Body framing headers are emitted from the struct. A framing header
     * already in the list is kept instead, so agreement between the two is
     * the caller's to guarantee: the engine does, by refusing a caller
     * Transfer-Encoding or mismatched Content-Length and never passing a
     * caller Content-Length through (D-78). */
    if (r->body == ZUH_BODY_LENGTH) {
        if (!zuh_headers_has(&r->headers, "Content-Length")) {
            if (!zuh_buf_append_str(out, "Content-Length: ")) return ZUH_ERR_NOMEM;
            if (!zuh_buf_append_u64(out, r->content_length))  return ZUH_ERR_NOMEM;
            if (!zuh_buf_append_str(out, "\r\n"))             return ZUH_ERR_NOMEM;
        }
    } else if (r->body == ZUH_BODY_CHUNKED) {
        if (!zuh_headers_has(&r->headers, "Transfer-Encoding")) {
            if (!zuh_buf_append_str(out, "Transfer-Encoding: chunked\r\n"))
                return ZUH_ERR_NOMEM;
        }
    }

    if (!zuh_buf_append_str(out, "\r\n")) return ZUH_ERR_NOMEM;
    return ZUH_OK;
}

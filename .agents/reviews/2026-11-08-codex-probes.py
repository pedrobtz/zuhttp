import gzip, socket, threading, subprocess, time


def run(label, response=None, code=None, upload=False, delayed=False):
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    port = server.getsockname()[1]
    seen = {}

    def serve():
        conn, _ = server.accept()
        with conn:
            conn.settimeout(2)
            data = b""
            while b"\r\n\r\n" not in data:
                data += conn.recv(65536)
            if upload:
                head, body = data.split(b"\r\n\r\n", 1)
                conn.settimeout(0.2)
                try:
                    while True:
                        part = conn.recv(65536)
                        if not part:
                            break
                        body += part
                except socket.timeout:
                    pass
                seen["body_bytes"] = len(body)
                seen["content_length"] = [
                    x.decode()
                    for x in head.split(b"\r\n")
                    if x.lower().startswith(b"content-length:")
                ]
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                )
            elif delayed:
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n"
                )
                time.sleep(0.5)
                conn.sendall(b"hello")
            else:
                conn.sendall(response)
        server.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    prefix = (
        'library(zuhttp, lib.loc="/tmp/zuhttp-review-library"); u <- "http://127.0.0.1:%s/"; '
        % port
    )
    p = subprocess.run(
        ["Rscript", "-e", prefix + code], text=True, capture_output=True, timeout=15
    )
    t.join(3)
    print(label, "exit=", p.returncode, seen, "\n" + p.stdout + p.stderr, flush=True)


run(
    "upload 40000",
    upload=True,
    code='r <- zu_post(u, body=raw(40000), proxy=NULL, timeout=3); cat(zu_resp_status(r), "\\n")',
)
gz = gzip.compress(b"hello", mtime=0)
for chunk in (False, True):
    framing = (
        b"Transfer-Encoding: chunked"
        if chunk
        else b"Content-Length: " + str(len(gz)).encode()
    )
    body = (
        (hex(len(gz))[2:].encode() + b"\r\n" + gz + b"\r\n0\r\n\r\n") if chunk else gz
    )
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n"
        + framing
        + b"\r\nConnection: close\r\n\r\n"
        + body
    )
    run(
        "gzip max_body=5 chunked=" + str(chunk),
        response=response,
        code='tryCatch(cat(zu_resp_text(zu_get(u, max_body=5, proxy=NULL)), "\\n"),error=function(e) cat(class(e)[1], conditionMessage(e), "\\n"))',
    )
double = gzip.compress(gz, mtime=0)
response = (
    b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Encoding: gzip\r\nContent-Length: "
    + str(len(double)).encode()
    + b"\r\nConnection: close\r\n\r\n"
    + double
)
run(
    "duplicate encoding",
    response=response,
    code='r <- zu_get(u, proxy=NULL); cat("returned bytes:", length(zu_resp_raw(r)), "magic:", as.integer(zu_resp_raw(r)[1:2]), "encoding headers:", length(zu_resp_header(r,"Content-Encoding")), "\\n")',
)
run(
    "fork streamed response",
    delayed=True,
    code='r <- zu_perform(zu_request("GET",u),client=zu_client(proxy=NULL,timeout=2),stream=TRUE); job <- parallel::mcparallel(tryCatch(rawToChar(zu_resp_read(r)), error=function(e) class(e)[1])); print(parallel::mccollect(job)); tryCatch(print(rawToChar(zu_resp_read(r))),error=function(e) cat("parent:",class(e)[1],conditionMessage(e),"\\n"))',
)
response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nX\r\nATTACK\r\n0\r\n\r\n"
run(
    "malformed chunks callback",
    response=response,
    code='got <- raw(); tryCatch(zu_get(u,proxy=NULL,callback=function(b) {got <<- c(got,b); TRUE}),error=function(e) cat(class(e)[1],"\\n")); cat("callback received:",paste(as.integer(got),collapse=","),"\\n")',
)
run(
    "abort buffered remainder",
    response=b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
    code='r <- zu_perform(zu_request("GET",u),client=zu_client(proxy=NULL),stream=TRUE); cat("first:",rawToChar(zu_resp_read(r,1)),"\\n"); zu_resp_abort(r); tryCatch(cat("after abort:",rawToChar(zu_resp_read(r)),"\\n"),error=function(e) cat(class(e)[1],"\\n"))',
)

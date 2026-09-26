# Large responses: downloads, streaming and limits

By default a response body is read into memory, which is right for an
API reply and wrong for a 2 GB file. zuhttp has two other destinations —
a file, and a function you supply — and in both the body is never held
in memory whole. This article also covers compression, and the limits
that stop a response from growing without bound.

The examples use a local test server
([webfakes](https://webfakes.r-lib.org)) with one extra endpoint, a
compressed response that would inflate to 50 MB:

``` r

library(zuhttp)

app <- webfakes::httpbin_app()
app$get("/bomb", function(req, res) {
  # 50 MB of zeros, gzip-compressed on the fly: about 50 KB on the wire.
  tf <- tempfile()
  con <- gzfile(tf, "wb"); writeBin(raw(50e6), con); close(con)
  res$set_header("Content-Encoding", "gzip")$
    set_type("application/octet-stream")$
    send(readBin(tf, "raw", file.size(tf)))
})
srv <- webfakes::new_app_process(app)
url <- function(path) srv$url(path)
```

## Downloading to a file

`path =` writes the body straight to disk:

``` r

dest <- tempfile(fileext = ".bin")
r <- zu_get(url("/bytes/10000"), path = dest)
zu_resp_path(r)
#> [1] "/tmp/RtmpttDpcO/file1f7c490789ea.bin"
file.size(dest)
#> [1] 10000
length(zu_resp_raw(r))   # nothing was kept in memory
#> [1] 0
```

The file appears at `dest` only once the body has arrived whole. zuhttp
writes to a temporary file beside it and renames at the end, so a
download that fails part-way leaves nothing behind, and a file that was
already at `dest` is untouched:

``` r

writeLines("the previous version", dest)

# Five bytes spread over three seconds, and a one-second budget.
e <- tryCatch(
  zu_get(url("/drip?numbytes=5&duration=3"), path = dest, timeout = 1),
  error = function(e) e
)
class(e)[1]
#> [1] "zu_timeout_error"
readLines(dest)            # the old file is still intact
#> [1] "the previous version"
list.files(dirname(dest), pattern = basename(dest))   # and no partial file
#> [1] "file1f7c490789ea.bin"
```

One thing a file sink does not do is judge the status code. A 404 page
is a complete body, so with `check = FALSE` it is written like any
other; check
[`zu_resp_ok()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp.md)
before trusting the file.

## Streaming to a function

`callback =` receives the body in chunks as they arrive, already
decompressed. Return `FALSE` to stop. Here the server sends five bytes
over two seconds, and the callback sees them as they come:

``` r

seen <- character()
r <- zu_get(url("/drip?numbytes=5&duration=2"), callback = function(chunk) {
  seen <<- c(seen, format(Sys.time(), "%H:%M:%OS1"))
  TRUE
})
length(seen)      # one call per chunk
#> [1] 5
seen
#> [1] "06:29:49.5" "06:29:50.0" "06:29:50.3" "06:29:50.7" "06:29:51.2"
```

That makes line-oriented streams easy to process incrementally — for
example newline-delimited JSON, parsed a record at a time without ever
holding the whole response:

``` r

records <- list()
pending <- ""
r <- zu_get(url("/stream/5"), callback = function(chunk) {
  lines <- strsplit(paste0(pending, rawToChar(chunk)), "\n", fixed = TRUE)[[1]]
  pending <<- if (endsWith(rawToChar(chunk), "\n")) "" else lines[length(lines)]
  complete <- if (nzchar(pending)) lines[-length(lines)] else lines
  for (l in complete[nzchar(complete)]) {
    records[[length(records) + 1]] <<- jsonlite::fromJSON(l)$id
  }
  TRUE
})
unlist(records)
#> [1] 0 1 2 3 4
```

Returning `FALSE` ends the transfer cleanly — useful when the first part
of a response already answers the question:

``` r

chunks <- 0
r <- zu_get(url("/drip?numbytes=10&duration=2"), callback = function(chunk) {
  chunks <<- chunks + 1
  chunks < 2        # stop after the second chunk
})
chunks
#> [1] 2
zu_resp_status(r)   # the response is still a response
#> [1] 200
```

An error inside the callback stops the transfer too, and reaches you as
the error you raised, not wrapped in a zuhttp one:

``` r

zu_get(url("/stream/5"), callback = function(chunk) stop("not what I expected"))
#> Error in `f()`:
#> ! not what I expected
```

## Compression

zuhttp asks for gzip and decompresses transparently.
[`zu_resp_raw()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_raw.md)
and
[`zu_resp_text()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_text.md)
return the decoded body, and the timings show what actually crossed the
wire:

``` r

r <- zu_get(url("/gzip"))
zu_resp_json(r)$gzipped
#> [1] TRUE
zu_resp_timings(r)[c("body_bytes_wire", "body_bytes_decoded")]
#>    body_bytes_wire body_bytes_decoded 
#>                220                368
```

`decode = FALSE` keeps the bytes exactly as sent — what you want when
checking them against a published checksum:

``` r

r <- zu_get(url("/gzip"), decode = FALSE)
zu_resp_header(r, "content-encoding")
#> [1] "gzip"
head(zu_resp_raw(r), 4)                 # the gzip magic number, 1f 8b
#> [1] 1f 8b 08 00
```

## Limits

A response body is capped at 16 MiB by default, counted *after*
decompression, on every destination — memory, file or callback. Raise it
with `max_body` when you expect more:

``` r

zu_get(url("/bytes/5000"), max_body = 1000)
#> Error in `zu_transport_perform.zu_native_transport()`:
#> ! response body exceeds the configured limit
```

The limit is enforced while decompressing, which is what makes it a
defence and not only a setting. The `/bomb` endpoint sends about 50 KB
that would inflate to 50 MB; zuhttp stops at the limit instead of
allocating the rest:

``` r

zu_get(url("/bomb"))
#> Error in `zu_transport_perform.zu_native_transport()`:
#> ! decompressed body exceeds the configured limit
```

For a file you expect to be large, raise `max_body` on that request, or
on a client used for downloads.

# Stream the response body to a file

The composable equivalent of `zu_get(url, path = )`. The body is written
to a temporary file in the same directory as `path` and renamed once it
has arrived whole (§27.1), so a failed, cancelled or interrupted
transfer never leaves a truncated file where the caller will find it and
trust it.

## Usage

``` r
zu_req_path(req, path)
```

## Arguments

- req:

  A `zu_request`.

- path:

  Destination path.

## Value

The request, modified.

## Details

The same directory, rather than
[`tempdir()`](https://rdrr.io/r/base/tempfile.html): `rename()` is
atomic only within a filesystem, and a temporary directory on another
mount turns the commit into a copy that can itself fail halfway.

An existing file at `path` is **replaced**, and only at that final step
— so a download that fails leaves whatever was already there untouched.
A non-2xx response is not a failed download, though: the server sent a
body and it is written like any other, so a 404 page replaces the file
and
[`zu_resp_check()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_check.md)
raises after the fact rather than instead of it. Setting both this and
[`zu_req_callback()`](https://pedrobtz.github.io/zuhttp/reference/zu_req_callback.md)
is an error, raised when the request is performed: a response body has
one destination.

## See also

[`zu_body_file()`](https://pedrobtz.github.io/zuhttp/reference/zu_body.md),
which is the opposite direction — a request body read *from* a file.

## Examples

``` r
req <- zu_req_path(zu_request("GET", "https://x.test/big.bin"),
                   file.path(tempdir(), "big.bin"))
```

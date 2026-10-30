## Submission

This is a first submission.

## R CMD check results

0 errors | 0 warnings | 1 note

* This is a new release.

## Test environments

`R CMD check --as-cran` on GitHub Actions, through the reusable workflows in
<https://github.com/pedrobtz/r-actions>:

* macOS (latest), R release — the Network.framework backend
* Windows (latest), R release and R-devel — the Schannel backend
* Ubuntu 24.04, R release and oldrel-1 — the OpenSSL backend
* R-hub containers matching CRAN's r-devel Linux flavours: `clang23`
  (`-std=gnu23 -pedantic`), `ubuntu-clang`, `ubuntu-gcc16`
* `nosuggests` (no Suggests installed)
* `nold` (R built `--disable-long-double`)

and, on the compiled code: UBSan (clang and gcc) and ASan (R-hub
`clang-asan`, `gcc-asan`), valgrind with `--leak-check=full`, rchk, LTO,
`gctorture`, GCC `-fanalyzer`, and CRAN's `rcnst`, `rlibro` and `vnu`
checks.

## Notes for the reviewer

* **System requirements.** zuhttp links each platform's own TLS stack and
  trust store rather than bundling one: 'Schannel' on Windows (part of the
  operating system), Apple's 'Network.framework' on macOS (part of the
  operating system), and 'OpenSSL' >= 1.1.1 elsewhere, which `configure`
  locates with `pkg-config` and a compile-and-link fallback, naming the
  package to install when it is missing. zlib is linked on every platform.
  No certificate bundle is shipped.

* **Bundled code.** Two small libraries are compiled in: 'picohttpparser'
  (MIT) and a subset of 'uriparser' (BSD-3-Clause). Their copyright holders
  are in `Authors@R` with role `cph`, their details in `inst/COPYRIGHTS`, and
  their full licence texts are installed under `licenses/`.

* **No network access during checks.** Examples use a mock transport and run
  offline; the few that make a real request are guarded by `interactive()`.
  Tests that need the network run only when `ZU_TEST_NETWORK=1` is set, which
  CRAN does not set; the certificate tests use a locally generated CA and a
  loopback server, and skip on CRAN.

* **Method references.** There is no publication describing the package's
  methods. It implements HTTP/1.1 as specified in RFC 9110
  (<doi:10.17487/RFC9110>) and RFC 9112 (<doi:10.17487/RFC9112>).

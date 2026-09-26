## Submission

This is a first submission.

## R CMD check results

0 errors | 0 warnings | 1 note

* This is a new release.

<!-- Fill in at submission (roadmap W16): the platforms actually checked, e.g.
     win-builder (release, devel), the macOS builder, R-hub (Linux, clang,
     sanitizers), and GitHub Actions on all three operating systems.
     Until W13 replaces Secure Transport, macOS also reports a
     "pragmas in C/C++ headers and code" NOTE; do not submit with it. -->

## Notes for the reviewer

* **System requirements.** zuhttp links each platform's own TLS stack and
  trust store rather than bundling one: 'Schannel' on Windows (part of the
  operating system), Apple's native TLS on macOS (part of the operating
  system), and 'OpenSSL' >= 1.1.1 elsewhere, which `configure` locates with
  `pkg-config` and a compile-and-link fallback, naming the package to install
  when it is missing. zlib is linked on every platform. No certificate bundle
  is shipped.

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

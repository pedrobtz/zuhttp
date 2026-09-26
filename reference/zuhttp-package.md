# zuhttp: Minimal HTTP Client Using Native System TLS

A small HTTP/1.1 client for HTTP and HTTPS requests that uses the
operating system's own TLS implementation and certificate trust store
rather than a bundled cryptography library or certificate bundle.
Provides structured timeouts, reliable cancellation from R, connection
reuse, streaming request and response bodies, structured error
conditions, and a pluggable transport layer for testing. Intended as a
focused alternative to full multi-protocol clients for packages whose
only requirement is reliable HTTPS.

## See also

Useful links:

- <https://github.com/pedrobtz/zuhttp>

- Report bugs at <https://github.com/pedrobtz/zuhttp/issues>

## Author

**Maintainer**: Pedro Baltazar <pedrobtz@gmail.com>

Authors:

- Pedro Baltazar <pedrobtz@gmail.com>

Other contributors:

- Kazuho Oku (picohttpparser, see inst/COPYRIGHTS) \[copyright holder\]

- Tokuhiro Matsuno (picohttpparser, see inst/COPYRIGHTS) \[copyright
  holder\]

- Daisuke Murase (picohttpparser, see inst/COPYRIGHTS) \[copyright
  holder\]

- Shigeo Mitsunari (picohttpparser, see inst/COPYRIGHTS) \[copyright
  holder\]

- Weijia Song (uriparser, see inst/COPYRIGHTS) \[copyright holder\]

- Sebastian Pipping (uriparser, see inst/COPYRIGHTS) \[copyright
  holder\]

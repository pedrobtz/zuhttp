# zuhttp: Minimal HTTP Client Using Native System TLS

A small client for the Hypertext Transfer Protocol (HTTP/1.1), over
plain connections and over Transport Layer Security (TLS), that uses the
operating system's own TLS implementation and certificate trust store
instead of a bundled cryptography library or certificate bundle:
'Schannel' on 'Windows', Apple's native TLS on 'macOS', and 'OpenSSL'
elsewhere. Provides a total request timeout, cancellation from 'R' with
an interrupt, connection reuse, streaming of response bodies to files or
callbacks, structured error conditions, and a pluggable transport layer
for testing without a network. Intended as a focused alternative to full
multi-protocol clients for packages that only need reliable HTTP
requests.

## See also

Useful links:

- <https://github.com/pedrobtz/zuhttp>

- <https://pedrobtz.github.io/zuhttp/>

- Report bugs at <https://github.com/pedrobtz/zuhttp/issues>

## Author

**Maintainer**: Pedro Baltazar <pedrobtz@gmail.com> \[copyright holder\]

Authors:

- Pedro Baltazar <pedrobtz@gmail.com> \[copyright holder\]

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

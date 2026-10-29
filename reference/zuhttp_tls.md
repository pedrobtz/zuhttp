# TLS backends and their limits

Which TLS implementation `zuhttp` used, and what each one can and cannot
do.

## Details

`zuhttp` bundles no cryptography and no CA bundle. It uses the TLS stack
and the trust store the platform already ships, chosen by `./configure`
at install time and reported by
[`zu_tls_backend()`](https://pedrobtz.github.io/zuhttp/reference/zu_tls_backend.md):

|              |                   |                                           |
|--------------|-------------------|-------------------------------------------|
| **Platform** | **Engine**        | **Trust store**                           |
| Windows      | Schannel          | the system certificate stores             |
| macOS        | Network.framework | Keychain, via `SecTrustEvaluateWithError` |
| elsewhere    | system OpenSSL    | the system CA directory                   |

The consequence worth knowing is that behaviour is not uniform, because
the platforms are not. What follows is what actually differs.

## Refused, never downgraded

Every
[`zu_tls()`](https://pedrobtz.github.io/zuhttp/reference/zu_tls.md)
setting is a request for a stronger connection. When the linked backend
cannot honour one, the request raises `zu_tls_unsupported_error` (a
`zu_tls_error`) **before any network I/O**, rather than connecting
without it. `zu_info()$tls_capabilities` lists what this build honours:

|                     |             |                   |             |
|---------------------|-------------|-------------------|-------------|
| **Setting**         | **OpenSSL** | **macOS**         | **Windows** |
| `pins`              | yes         | refused           | refused     |
| `min_version = 13`  | yes         | yes               | refused     |
| `ca_file`           | yes         | yes               | refused     |
| `ca_extra`          | yes         | yes               | refused     |
| `revocation = TRUE` | refused     | yes, with caveats | yes         |

A refusal is `zu_tls_unsupported_error`; a pin that does not match is
`zu_tls_pin_error`. The two are different classes so that "this backend
cannot pin" is never mistaken for "the pin was checked and failed".

## Maximum TLS version

TLS 1.3 is negotiated wherever the server offers it, except on Windows,
where `zu_tls(min_version = 13)` is refused rather than silently
downgraded: the Schannel build available through Rtools lacks
`SCH_CREDENTIALS`. Asking for 1.3 there raises rather than quietly
giving you 1.2 — silently weakening a security setting is worse than
failing. Connections still negotiate the highest version both ends
support; it is the *floor* that cannot be raised.

## Certificate pinning

[`zu_tls()`](https://pedrobtz.github.io/zuhttp/reference/zu_tls.md)'s
`pins` works on **OpenSSL only**. On macOS and Windows the platform will
not hand over the SubjectPublicKeyInfo without hand-parsing DER, and
that parser is not written yet. Both refuse, because a pin that silently
compares the wrong bytes is worse than no pin. A pinned request either
enforces the pin or raises; it never quietly succeeds unpinned.

## Custom certificate authorities

`ca_file` **replaces** the system trust store; `ca_extra` **adds** to
it. The distinction is deliberate and is the usual source of confusion —
with `ca_file` set, a public certificate that verified a moment ago will
not. **Neither is implemented on Windows yet**: Schannel refuses both,
rather than verifying against the Windows store and ignoring the file.

## Revocation

Off by default: `zuhttp` asks for no revocation check unless told to.
What the platform then does differs. OpenSSL and Schannel check nothing.
**macOS may check anyway**: the system's trust evaluation consults
Apple's own revocation data when it has it, with no policy asking for
it, so a certificate Apple knows to be revoked can be rejected even with
`revocation = FALSE` – on one run and not the next. `zuhttp` cannot
switch that off and does not try.

`zu_tls(revocation = TRUE)` opts in, and what that buys you is
backend-dependent in a way worth knowing before you rely on it:

- **OpenSSL: refused.** OpenSSL neither downloads CRLs nor performs OCSP
  on its own, so a CRL check with no CRL source fails *every* chain,
  valid ones included. Rather than offer a flag that means "no
  connection will ever succeed", this backend raises
  `zu_tls_unsupported_error`.

- **macOS:** it works, in that revoked certificates are rejected — but
  so are valid certificates from CAs that no longer answer revocation
  queries. Let's Encrypt retired OCSP, so a large share of the web fails
  under it.

- **Windows:** Schannel checks the chain, excluding the root, through
  the platform's own revocation machinery.

Both caveats are recorded rather than papered over, and both are why
revocation is not merely off by default but is a setting to reach for
deliberately.

## HTTPS through a proxy on macOS

On macOS the TLS engine is Network.framework, which opens the connection
and runs the proxy's `CONNECT` itself. Its API for that starts with
**macOS 14**: on macOS 11 to 13, HTTPS through a proxy raises
`zu_proxy_error` saying so, rather than going direct. Plain `http://`
through a proxy, and direct HTTPS, work on every macOS R supports.

Three smaller differences. A proxy that refuses the tunnel is reported
as refused but without its HTTP status, which Network.framework does not
pass on; a 407 is still `zu_proxy_auth_error`. Credentials go to the
proxy when it asks for them, after its 407, rather than with the first
request. And with `proxy = FALSE`, `zuhttp` asks for a direct
connection, which on a Mac with a system-wide proxy configured is a
preference the system may override.

## Name resolution is not bounded

DNS resolution uses the system resolver (`getaddrinfo()`), which is
synchronous. **Neither `timeout` nor Ctrl-C interrupts it**, so a host
whose resolver stalls can hold R for as long as the resolver takes — on
a misconfigured network, minutes. Every later phase (connect, handshake,
response) is bounded by both. The exception is HTTPS on macOS, where
Network.framework resolves the name itself and both apply.

## See also

[`zu_tls()`](https://pedrobtz.github.io/zuhttp/reference/zu_tls.md) for
the settings,
[`zu_tls_backend()`](https://pedrobtz.github.io/zuhttp/reference/zu_tls_backend.md)
for what this build linked,
[`zu_info()`](https://pedrobtz.github.io/zuhttp/reference/zu_info.md)
for the whole configuration at once.

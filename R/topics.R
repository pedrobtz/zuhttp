# Two help topics that shipped code already points at.
#
# The fork guard's error message ends "See ?zuhttp_fork", configure prints
# "see ?zuhttp_tls", and the TLS backends cite the same topic when they refuse
# a setting — and neither existed. §26.4 calls turning the
# forked-HTTPS segfault into a diagnosable error "the whole mitigation", which
# is half-defeated when the pointer it hands the user goes nowhere.
#
# Written as topics rather than folded into ?zu_client because that is what
# those messages promise, and a cross-reference has to resolve to the name it
# names.

#' HTTPS in a forked process
#'
#' Why `zuhttp` raises `zu_fork_error` inside `mclapply()` on macOS, and what
#' to use instead.
#'
#' @details
#' `parallel::mclapply()`, `parallel::mcparallel()` and `future`'s `multicore`
#' plan all work by forking the R process. Two separate things go wrong when a
#' forked child makes an HTTPS request.
#'
#' **The TLS engine does not survive `fork()` (macOS).**
#' Network.framework runs on Grand Central Dispatch, which refuses to run in a
#' forked child of a process that already used it, and the system's trust
#' evaluator keeps a connection to `trustd` that is not inherited either. A
#' child that tries is killed outright — measured during the design spikes: a
#' parent that had made one HTTPS request, then forked, produced children
#' killed by `SIGILL` (`SIGSEGV` under the earlier engine); a parent that had
#' made none produced children that survived. It is fork-*after-use*, not
#' fork-at-all, which is why the failure looks intermittent and why it usually
#' appears only once a script grows a warm-up request.
#'
#' `zuhttp` therefore records the process ID that first opened an HTTPS
#' connection and refuses to open one in a different process, raising
#' `zu_fork_error`. That
#' does not make forked HTTPS work. It makes it diagnosable: an error naming
#' the cause instead of a worker vanishing.
#'
#' **Inherited connections.** A forked child also inherits the parent's open
#' sockets, pooled TLS sessions included. If both processes write into one TLS
#' session the session is corrupted, and the resulting failure is
#' nondeterministic and appears far from its cause. The same PID guard drops
#' every inherited connection on first use in the child, without a graceful
#' TLS shutdown — a polite close would write to a socket the parent still owns.
#' `zu_pool_stats()` reports these as `discarded_fork` and `forks_detected`.
#'
#' @section What to use instead:
#' `PSOCK` clusters and `future::plan("multisession")` start fresh R processes
#' with `exec()` rather than forking, so neither hazard exists:
#'
#' ```r
#' cl <- parallel::makeCluster(4)
#' parallel::clusterEvalQ(cl, library(zuhttp))
#' parallel::parLapply(cl, urls, function(u) zu_get(u, path = basename(u)))
#' parallel::stopCluster(cl)
#' ```
#'
#' Plain HTTP in a forked child does not touch the trust evaluator, so it is
#' not subject to the first hazard — but it is still subject to the second, and
#' relying on that distinction is not worth the surprise when a URL later
#' becomes `https://`.
#'
#' `zuhttp` performs one request at a time; there is no built-in concurrency,
#' so parallelism is always the caller's to arrange.
#'
#' @seealso [zu_pool_stats()] for the counters, [zu_client()] for the pool.
#' @name zuhttp_fork
NULL

#' TLS backends and their limits
#'
#' Which TLS implementation `zuhttp` used, and what each one can and cannot do.
#'
#' @details
#' `zuhttp` bundles no cryptography and no CA bundle. It uses the TLS stack and
#' the trust store the platform already ships, chosen by `./configure` at
#' install time and reported by [zu_tls_backend()]:
#'
#' \tabular{lll}{
#'   **Platform** \tab **Engine** \tab **Trust store** \cr
#'   Windows \tab Schannel \tab the system certificate stores \cr
#'   macOS \tab Network.framework \tab Keychain, via `SecTrustEvaluateWithError` \cr
#'   elsewhere \tab system OpenSSL \tab the system CA directory \cr
#' }
#'
#' The consequence worth knowing is that behaviour is not uniform, because the
#' platforms are not. What follows is what actually differs.
#'
#' @section Refused, never downgraded:
#' Every [zu_tls()] setting is a request for a stronger connection. When the
#' linked backend cannot honour one, the request raises
#' `zu_tls_unsupported_error` (a `zu_tls_error`) **before any network I/O**,
#' rather than connecting without it. `zu_info()$tls_capabilities` lists what
#' this build honours:
#'
#' \tabular{llll}{
#'   **Setting** \tab **OpenSSL** \tab **macOS** \tab **Windows** \cr
#'   `pins` \tab yes \tab refused \tab refused \cr
#'   `min_version = 13` \tab yes \tab yes \tab refused \cr
#'   `ca_file` \tab yes \tab yes \tab refused \cr
#'   `ca_extra` \tab yes \tab yes \tab refused \cr
#'   `revocation = TRUE` \tab refused \tab yes, with caveats \tab yes \cr
#' }
#'
#' A refusal is `zu_tls_unsupported_error`; a pin that does not match is
#' `zu_tls_pin_error`. The two are different classes so that "this backend
#' cannot pin" is never mistaken for "the pin was checked and failed".
#'
#' @section Maximum TLS version:
#' TLS 1.3 is negotiated wherever the server offers it, except on Windows,
#' where `zu_tls(min_version = 13)` is refused rather than silently
#' downgraded: the Schannel build available through Rtools lacks
#' `SCH_CREDENTIALS`. Asking for 1.3 there raises rather than quietly giving
#' you 1.2 — silently weakening a
#' security setting is worse than failing. Connections still negotiate the
#' highest version both ends support; it is the *floor* that cannot be raised.
#'
#' @section Certificate pinning:
#' [zu_tls()]'s `pins` works on **OpenSSL only**. On macOS and Windows the
#' platform will not hand over the SubjectPublicKeyInfo without hand-parsing
#' DER, and that parser is not written yet. Both
#' refuse, because a pin that silently compares the wrong bytes is worse than
#' no pin. A pinned request either enforces the pin or raises; it never quietly
#' succeeds unpinned.
#'
#' @section Custom certificate authorities:
#' `ca_file` **replaces** the system trust store; `ca_extra` **adds** to it.
#' The distinction is deliberate and is the usual source of confusion — with
#' `ca_file` set, a public certificate that verified a moment ago will not.
#' **Neither is implemented on Windows yet**: Schannel refuses both, rather
#' than verifying against the Windows store and ignoring the file.
#'
#' @section Revocation:
#' Off by default: `zuhttp` asks for no revocation check unless told to. What
#' the platform then does differs. OpenSSL and Schannel check nothing. **macOS
#' may check anyway**: the system's trust evaluation consults Apple's own
#' revocation data when it has it, with no policy asking for it, so a
#' certificate Apple knows to be revoked can be rejected even with
#' `revocation = FALSE` -- on one run and not the next.
#' `zuhttp` cannot switch that off and does not try.
#'
#' `zu_tls(revocation = TRUE)` opts in, and what that buys you is
#' backend-dependent in a way worth knowing before you rely on it:
#'
#' * **OpenSSL: refused.** OpenSSL neither downloads CRLs nor performs OCSP on
#'   its own, so a CRL check with no CRL source fails *every* chain, valid
#'   ones included. Rather than offer a flag that means "no connection will
#'   ever succeed", this backend raises `zu_tls_unsupported_error`.
#' * **macOS:** it works, in that revoked certificates are rejected — but so
#'   are valid certificates from CAs that no longer answer revocation queries.
#'   Let's Encrypt retired OCSP, so a large share of the web fails under it.
#' * **Windows:** Schannel checks the chain, excluding the root, through the
#'   platform's own revocation machinery.
#'
#' Both caveats are recorded rather than papered over, and both are why
#' revocation is not merely off by default but is a setting to reach for
#' deliberately.
#'
#' @section HTTPS through a proxy on macOS:
#' On macOS the TLS engine is Network.framework, which opens the connection
#' and runs the proxy's `CONNECT` itself. Its API for that starts with
#' **macOS 14**: on macOS 11 to 13, HTTPS through a proxy raises
#' `zu_proxy_error` saying so, rather than going direct. Plain `http://`
#' through a proxy, and direct HTTPS, work on every macOS R supports.
#'
#' Three smaller differences. A proxy that refuses the tunnel is reported as
#' refused but without its HTTP status, which Network.framework does not pass
#' on; a 407 is still `zu_proxy_auth_error`. Credentials go to the proxy when
#' it asks for them, after its 407, rather than with the first request. And
#' with `proxy = FALSE`, `zuhttp` asks for a direct connection, which on a Mac
#' with a system-wide proxy configured is a preference the system may
#' override.
#'
#' @section Name resolution is not bounded:
#' DNS resolution uses the system resolver (`getaddrinfo()`), which is
#' synchronous. **Neither `timeout` nor Ctrl-C interrupts it**, so a host whose
#' resolver stalls can hold R for as long as the resolver takes — on a
#' misconfigured network, minutes. Every later phase (connect, handshake,
#' response) is bounded by both. The exception is HTTPS on macOS, where
#' Network.framework resolves the name itself and both apply.
#'
#' @seealso [zu_tls()] for the settings, [zu_tls_backend()] for what this
#'   build linked, [zu_info()] for the whole configuration at once.
#' @name zuhttp_tls
NULL

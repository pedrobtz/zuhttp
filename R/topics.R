# Two help topics that shipped code already points at.
#
# The fork guard's error message ends "See ?zuhttp_fork", configure prints
# "see ?zuhttp_tls", and the Secure Transport backend cites the same topic
# when it refuses TLS 1.3 — and neither existed. §26.4 calls turning the
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
#' **The trust evaluator does not survive `fork()` (macOS).**
#' Security.framework opens an XPC connection to `trustd` the first time it
#' evaluates trust, and that connection is not inherited. A child that tries to
#' use it is killed outright — measured during the design spike: a parent that
#' had made one HTTPS request, then forked, produced children killed by
#' `SIGSEGV`; a parent that had made none produced children that survived. It
#' is fork-*after-use*, not fork-at-all, which is why the failure looks
#' intermittent and why it usually appears only once a script grows a warm-up
#' request.
#'
#' `zuhttp` therefore records the process ID that armed the trust evaluator and
#' refuses to evaluate trust in a different one, raising `zu_fork_error`. That
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
#'   macOS \tab Secure Transport \tab Keychain, via `SecTrustEvaluateWithError` \cr
#'   elsewhere \tab system OpenSSL \tab the system CA directory \cr
#' }
#'
#' The consequence worth knowing is that behaviour is not uniform, because the
#' platforms are not. What follows is what actually differs.
#'
#' @section Maximum TLS version:
#' `zu_tls(min_version = 13)` is refused rather than silently downgraded on
#' both macOS and Windows: Secure Transport has no TLS 1.3 constant, and the
#' Schannel build available through Rtools lacks `SCH_CREDENTIALS`. Asking for
#' 1.3 there raises rather than quietly giving you 1.2 — silently weakening a
#' security setting is worse than failing. Connections still negotiate the
#' highest version both ends support; it is the *floor* that cannot be raised.
#'
#' @section Certificate pinning:
#' [zu_tls()]'s `pins` works on OpenSSL and Schannel. On macOS it raises:
#' Security.framework will not hand over the SubjectPublicKeyInfo without
#' hand-parsing DER, and a pin that silently compares the wrong bytes is worse
#' than no pin. A pinned request either enforces the pin or raises
#' `zu_tls_pin_error`; it never quietly succeeds unpinned.
#'
#' @section Custom certificate authorities:
#' `ca_file` **replaces** the system trust store; `ca_extra` **adds** to it.
#' The distinction is deliberate and is the usual source of confusion — with
#' `ca_file` set, a public certificate that verified a moment ago will not.
#' Additive trust is not yet implemented on Schannel.
#'
#' @section Revocation:
#' Off by default, on every platform, because none of them checks revocation
#' by default and pretending otherwise would misrepresent what verification
#' means here. `zu_tls(revocation = TRUE)` turns it on where the platform
#' supports it.
#'
#' @seealso [zu_tls()] for the settings, [zu_tls_backend()] for what this
#'   build linked, [zu_info()] for the whole configuration at once.
#' @name zuhttp_tls
NULL

# HTTPS in a forked process

Why `zuhttp` raises `zu_fork_error` inside `mclapply()` on macOS, and
what to use instead.

## Details

[`parallel::mclapply()`](https://rdrr.io/r/parallel/mclapply.html),
[`parallel::mcparallel()`](https://rdrr.io/r/parallel/mcparallel.html)
and `future`'s `multicore` plan all work by forking the R process. Two
separate things go wrong when a forked child makes an HTTPS request.

**The trust evaluator does not survive `fork()` (macOS).**
Security.framework opens an XPC connection to `trustd` the first time it
evaluates trust, and that connection is not inherited. A child that
tries to use it is killed outright — measured during the design spike: a
parent that had made one HTTPS request, then forked, produced children
killed by `SIGSEGV`; a parent that had made none produced children that
survived. It is fork-*after-use*, not fork-at-all, which is why the
failure looks intermittent and why it usually appears only once a script
grows a warm-up request.

`zuhttp` therefore records the process ID that armed the trust evaluator
and refuses to evaluate trust in a different one, raising
`zu_fork_error`. That does not make forked HTTPS work. It makes it
diagnosable: an error naming the cause instead of a worker vanishing.

**Inherited connections.** A forked child also inherits the parent's
open sockets, pooled TLS sessions included. If both processes write into
one TLS session the session is corrupted, and the resulting failure is
nondeterministic and appears far from its cause. The same PID guard
drops every inherited connection on first use in the child, without a
graceful TLS shutdown — a polite close would write to a socket the
parent still owns.
[`zu_pool_stats()`](https://pedrobtz.github.io/zuhttp/reference/zu_pool_stats.md)
reports these as `discarded_fork` and `forks_detected`.

## What to use instead

`PSOCK` clusters and `future::plan("multisession")` start fresh R
processes with `exec()` rather than forking, so neither hazard exists:

    cl <- parallel::makeCluster(4)
    parallel::clusterEvalQ(cl, library(zuhttp))
    parallel::parLapply(cl, urls, function(u) zu_get(u, path = basename(u)))
    parallel::stopCluster(cl)

Plain HTTP in a forked child does not touch the trust evaluator, so it
is not subject to the first hazard — but it is still subject to the
second, and relying on that distinction is not worth the surprise when a
URL later becomes `https://`.

`zuhttp` performs one request at a time; there is no built-in
concurrency, so parallelism is always the caller's to arrange.

## See also

[`zu_pool_stats()`](https://pedrobtz.github.io/zuhttp/reference/zu_pool_stats.md)
for the counters,
[`zu_client()`](https://pedrobtz.github.io/zuhttp/reference/zu_client.md)
for the pool.

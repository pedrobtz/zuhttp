# §39 the information API.
#
# Two sections lean on this existing, which is why it is not cosmetic:
#
#   §14.5  "whatever the three platforms do, zu_info() must report the
#          effective revocation policy, because this is exactly the kind of
#          silent asymmetry that produces 'it works on my machine' reports."
#   §31.3  the default client's configuration "is never invisible" BECAUSE
#          zu_info() reports it.
#
# Until now both were claims the code did not support.

#' What this build of zuhttp can do
#'
#' Networking diagnostics in one place: which TLS engine is linked, which
#' store decides trust, whether revocation is checked, what the default client
#' is configured to do, and what the environment says about proxies.
#'
#' @return A `zu_info` list, printed as a report. Fields: `version`, `http`,
#'   `tls_backend`, `trust`, `tls_available`, `revocation_default`,
#'   `compression`, `ipv6`, `proxy_env` and `default_client`.
#'
#' @section Why the TLS engine and the trust store are listed separately:
#' §13.1 splits them deliberately. A build can speak TLS with one library and
#' decide trust with another — that is exactly what the macOS build does — and
#' "which store trusted this certificate?" is a question users genuinely ask
#' when a certificate works in a browser and not here.
#'
#' @export
#' @examples
#' zu_info()
zu_info <- function() {
  b <- .Call(C_zu_build_info)
  cl <- zu_default_client()
  structure(
    c(list(version = as.character(utils::packageVersion("zuhttp"))), b,
      list(
        # §20.1's asymmetry is worth showing rather than describing: uppercase
        # HTTP_PROXY is deliberately ignored, and a user staring at a request
        # that will not proxy needs to see that it was not read.
        proxy_env = proxy_env_report(),
        default_client = default_client_report(cl)
      )),
    class = "zu_info"
  )
}

proxy_env_report <- function() {
  read <- c("http_proxy", "https_proxy", "HTTPS_PROXY", "all_proxy",
            "ALL_PROXY", "no_proxy", "NO_PROXY")
  vals <- vapply(read, function(v) Sys.getenv(v, unset = NA_character_),
                 character(1))
  vals <- vals[!is.na(vals) & nzchar(vals)]
  # Redacted: a proxy URL routinely carries credentials, and this function
  # exists to be pasted into bug reports (§42.2).
  vals <- vapply(vals, zu_redact_url, character(1))
  ignored <- Sys.getenv("HTTP_PROXY", unset = NA_character_)
  list(set = vals,
       ignored_uppercase_http_proxy = !is.na(ignored) && nzchar(ignored))
}

default_client_report <- function(cl) {
  list(
    base_url = cl$base_url,
    timeout  = cl$timeout %||% zu_defaults()$timeout,
    verify   = cl$verify %||% zu_defaults()$verify,
    check    = cl$check %||% zu_defaults()$check,
    retry    = (cl$retry %||% zu_defaults()$retry)$attempts,
    pool     = if (is.null(cl$pool)) "disabled"
               else sprintf("max_idle %d, max_per_host %d, idle %gs",
                            cl$pool$max_idle, cl$pool$max_per_host,
                            cl$pool$idle_timeout_ms / 1000),
    proxy    = if (isFALSE(cl$proxy)) "disabled (proxy = FALSE)"
               else if (is.null(cl$proxy)) "from the environment"
               else zu_redact_url(cl$proxy)
  )
}

#' @export
print.zu_info <- function(x, ...) {
  f <- function(label, value) cat(format(label, width = 20), value, "\n", sep = "")
  cat("zuhttp ", x$version, "\n\n", sep = "")
  f("HTTP:", x$http)
  f("TLS backend:", if (isTRUE(x$tls_available)) x$tls_backend
                    else paste0(x$tls_backend, " (https unavailable)"))
  f("Trust:", x$trust)
  f("Revocation:", if (isTRUE(x$revocation_default)) "on" else "off by default")
  f("Compression:", x$compression)
  f("IPv6:", if (isTRUE(x$ipv6)) "yes" else "no")

  cat("\nDefault client\n")
  d <- x$default_client
  f("  base_url:", d$base_url %||% "(none)")
  f("  timeout:", paste0(d$timeout, "s"))
  f("  verify:", if (isTRUE(d$verify)) "yes" else "NO")
  f("  check:", if (isTRUE(d$check)) "4xx/5xx raise" else "statuses returned")
  f("  retry:", if (d$retry <= 1L) "off" else paste(d$retry, "attempts"))
  f("  pool:", d$pool)
  f("  proxy:", d$proxy)

  cat("\nProxy environment\n")
  p <- x$proxy_env
  if (!length(p$set)) cat("  (nothing set)\n")
  else for (nm in names(p$set)) f(paste0("  ", nm, ":"), p$set[[nm]])
  if (isTRUE(p$ignored_uppercase_http_proxy))
    cat("  NOTE: HTTP_PROXY is set and is deliberately IGNORED\n",
        "        (the httpoxy rule). Use http_proxy, lowercase.\n", sep = "")
  invisible(x)
}

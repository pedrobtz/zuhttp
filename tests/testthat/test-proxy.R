# S10 — §20 proxy support, from R.
#
# The §20.1 and §20.2 rules are table-tested in C (ctest/test_proxy.c, 36
# cases). What could not be tested there is whether the ENGINE actually
# routes through a proxy: absolute-form for plain HTTP, CONNECT for HTTPS,
# and the §20.4 rule that a credential never reaches an origin.
#
# So this file runs a real, minimal proxy in a helper process. Offline, on
# loopback, one connection, then it exits. That is enough to observe the exact
# bytes the engine sent to the proxy — which is the only way to assert
# "absolute-form" or "Proxy-Authorization was present" rather than to infer it
# from the fact that a request succeeded.

# --- §20.1 / §20.2 resolution (offline, no proxy needed) -----------------

test_that("proxy = FALSE forces a direct connection, NULL consults the env", {
  # The three states are genuinely three (D-48). NULL cannot mean "disabled",
  # because §31.9 already gives NULL the meaning "reset to the package
  # default" for every other policy argument.
  expect_null(zu_client()$proxy)
  expect_false(zu_client(proxy = FALSE)$proxy)
  expect_identical(zu_client(proxy = "http://p:3128")$proxy, "http://p:3128")
})

test_that("a bogus proxy in the environment is actually used, and FALSE escapes it", {
  skip_unless_online()
  old <- Sys.getenv("http_proxy", unset = NA)
  on.exit(
    if (is.na(old)) {
      Sys.unsetenv("http_proxy")
    } else {
      Sys.setenv(http_proxy = old)
    },
    add = TRUE
  )

  # Port 9 (discard) refuses, so reaching it proves the request went to the
  # proxy rather than to the origin.
  Sys.setenv(http_proxy = "http://127.0.0.1:9")
  expect_error(
    zu_get("http://example.com", timeout = 5),
    class = "zu_connect_error"
  )
  expect_identical(
    zu_resp_status(zu_get("http://example.com", proxy = FALSE)),
    200L
  )
})

test_that("NO_PROXY takes a host out of the proxy's path", {
  skip_unless_online()
  old_p <- Sys.getenv("http_proxy", unset = NA)
  old_n <- Sys.getenv("no_proxy", unset = NA)
  on.exit(
    {
      if (is.na(old_p)) {
        Sys.unsetenv("http_proxy")
      } else {
        Sys.setenv(http_proxy = old_p)
      }
      if (is.na(old_n)) {
        Sys.unsetenv("no_proxy")
      } else {
        Sys.setenv(no_proxy = old_n)
      }
    },
    add = TRUE
  )

  Sys.setenv(http_proxy = "http://127.0.0.1:9", no_proxy = "example.com")
  expect_identical(zu_resp_status(zu_get("http://example.com")), 200L)
})

# --- §20.3 request forms, observed at the proxy --------------------------

test_that("plain HTTP through a proxy uses absolute-form (§20.3)", {
  skip_unless_forkable()
  seen <- with_fake_proxy("ok", function(px) {
    r <- zu_get(
      "http://target.example/some/path?q=1",
      proxy = px,
      timeout = 15,
      check = FALSE
    )
    expect_identical(zu_resp_status(r), 200L)
  })
  skip_if(is.null(seen), "the helper proxy recorded nothing")

  # The request line carries the whole origin, which is how the proxy knows
  # where to forward. Origin-form here would be a request the proxy cannot
  # route.
  expect_match(
    seen,
    "^GET http://target\\.example/some/path\\?q=1 HTTP/1\\.1\r\n"
  )
  expect_match(seen, "Host: target\\.example")
})

test_that("proxy credentials go to the proxy and are not in the URL (§20.4)", {
  skip_unless_forkable()
  seen <- with_fake_proxy("ok", function(px) {
    # Credentials in the proxy URL, percent-encoded, as a corporate proxy
    # config usually supplies them.
    auth_px <- sub("^http://", "http://user:p%40ss@", px)
    r <- zu_get(
      "http://target.example/x",
      proxy = auth_px,
      timeout = 15,
      check = FALSE
    )
    expect_identical(zu_resp_status(r), 200L)
  })
  skip_if(is.null(seen), "the helper proxy recorded nothing")

  # base64("user:p@ss") — the %40 must have been decoded before encoding, or
  # the proxy authenticates as the literal "p%40ss".
  expect_match(seen, "Proxy-Authorization: Basic dXNlcjpwQHNz", fixed = TRUE)
  # ...and the credential is nowhere in the request line.
  expect_false(grepl("user:", strsplit(seen, "\r\n")[[1]][1], fixed = TRUE))
})

test_that("the request line never carries proxy credentials or origin userinfo", {
  skip_unless_forkable()
  seen <- with_fake_proxy("ok", function(px) {
    auth_px <- sub("^http://", "http://user:secret@", px)
    invisible(zu_get(
      "http://target.example/x",
      proxy = auth_px,
      timeout = 15,
      check = FALSE
    ))
  })
  skip_if(is.null(seen), "the helper proxy recorded nothing")

  line <- strsplit(seen, "\r\n")[[1]][1]
  # §20.3: absolute-form "never includes userinfo". The proxy's credentials
  # are how it authenticates, never part of the target.
  expect_false(grepl("@", line, fixed = TRUE))
  expect_false(grepl("secret", seen, fixed = TRUE))

  # Origin userinfo is refused before anything is sent (#331, D-110), so the
  # proxy is never reached with it at all.
  seen2 <- with_fake_proxy("ok", function(px) {
    e <- tryCatch(
      zu_get("http://u:pw@target.example/x", proxy = px, timeout = 15),
      error = function(e) e
    )
    expect_s3_class(e, "zu_url_error")
  })
  expect_null(seen2)
})

# --- §20.3 CONNECT failures ----------------------------------------------

test_that("a 407 CONNECT is zu_proxy_auth_error, not a generic failure", {
  skip_unless_forkable()
  seen <- with_fake_proxy("407", function(px) {
    e <- tryCatch(
      zu_get("https://target.example/x", proxy = px, timeout = 15),
      condition = function(e) e
    )
    expect_s3_class(e, "zu_proxy_auth_error")
    expect_s3_class(e, "zu_proxy_error")
    expect_match(conditionMessage(e), "407")
  })
  skip_if(is.null(seen), "the helper proxy recorded nothing")
  # HTTPS tunnels: the proxy sees CONNECT with an authority, not a path, and
  # emphatically not the TLS bytes.
  expect_match(seen, "^CONNECT target\\.example:443 HTTP/1\\.1\r\n")
})

test_that("a non-2xx CONNECT surfaces the proxy's own status (§20.3)", {
  skip_unless_forkable()
  invisible(with_fake_proxy("502", function(px) {
    e <- tryCatch(
      zu_get("https://target.example/x", proxy = px, timeout = 15),
      condition = function(e) e
    )
    expect_s3_class(e, "zu_proxy_error")
    expect_false(inherits(e, "zu_proxy_auth_error"))
    # In a corporate environment the proxy's status is frequently the only
    # diagnostic the user gets, so flattening it into "connection failed"
    # would remove the one useful piece of information. Network.framework runs
    # the CONNECT itself and does not report that status (D-71, §20.3), so on
    # macOS the message must at least say the proxy refused the tunnel.
    if (identical(zu_tls_backend(), "network-framework")) {
      expect_match(conditionMessage(e), "proxy did not open a tunnel")
    } else {
      expect_match(conditionMessage(e), "502")
    }
  }))
})

# --- #244: proxy selection against libcurl -------------------------------
#
# The same (environment, URL) rows through zuhttp and through libcurl, with
# a recording server as the proxy: proxied or direct is whether it saw the
# request. A direct request goes to a closed loopback port or to a name in
# .invalid (RFC 6761 §6.4: never resolves), so it fails fast and touches no
# network. Each row states what zuhttp does (§20.1, §20.2); a row where
# libcurl differs says why, and which of the two is right.

test_that("proxy and NO_PROXY selection matches libcurl's (#244)", {
  skip_if_not_installed("curl")
  skip_if_not_installed("withr")
  closed <- free_port()
  h <- function(host, scheme = "http") {
    sprintf("%s://%s:%d/", scheme, host, closed)
  }
  # zu: does zuhttp proxy? curl: does libcurl, where it differs (NA = same).
  rows <- list(
    list(
      env = c(http_proxy = "PROXY"),
      url = h("a.example.invalid"),
      zu = TRUE
    ),
    # §20.1: HTTP_PROXY is ignored (httpoxy); libcurl ignores it too.
    list(
      env = c(HTTP_PROXY = "PROXY"),
      url = h("a.example.invalid"),
      zu = FALSE
    ),
    list(
      env = c(https_proxy = "PROXY"),
      url = h("a.example.invalid", "https"),
      zu = TRUE
    ),
    list(
      env = c(HTTPS_PROXY = "PROXY"),
      url = h("a.example.invalid", "https"),
      zu = TRUE
    ),
    # An http_proxy is not for https URLs, nor https_proxy for http.
    list(
      env = c(http_proxy = "PROXY"),
      url = h("a.example.invalid", "https"),
      zu = FALSE
    ),
    list(
      env = c(https_proxy = "PROXY"),
      url = h("a.example.invalid"),
      zu = FALSE
    ),
    list(env = c(all_proxy = "PROXY"), url = h("a.example.invalid"), zu = TRUE),
    list(
      env = c(ALL_PROXY = "PROXY"),
      url = h("a.example.invalid", "https"),
      zu = TRUE
    ),
    list(
      env = c(http_proxy = "PROXY", no_proxy = "*"),
      url = h("a.example.invalid"),
      zu = FALSE
    ),
    list(
      env = c(http_proxy = "PROXY", no_proxy = ""),
      url = h("a.example.invalid"),
      zu = TRUE
    ),
    # Suffix matching on label boundaries.
    list(
      env = c(http_proxy = "PROXY", no_proxy = "example.invalid"),
      url = h("a.example.invalid"),
      zu = FALSE
    ),
    list(
      env = c(http_proxy = "PROXY", no_proxy = "example.invalid"),
      url = h("example.invalid"),
      zu = FALSE
    ),
    list(
      env = c(http_proxy = "PROXY", no_proxy = "example.invalid"),
      url = h("notexample.invalid"),
      zu = TRUE
    ),
    list(
      env = c(http_proxy = "PROXY", no_proxy = "a.example.invalid"),
      url = h("example.invalid"),
      zu = TRUE
    ),
    # A leading dot is ignored, so it also matches the bare domain.
    list(
      env = c(http_proxy = "PROXY", no_proxy = ".example.invalid"),
      url = h("a.example.invalid"),
      zu = FALSE
    ),
    list(
      env = c(http_proxy = "PROXY", no_proxy = ".example.invalid"),
      url = h("example.invalid"),
      zu = FALSE
    ),
    # Case-insensitive, list separators, and the uppercase variable.
    list(
      env = c(http_proxy = "PROXY", no_proxy = "EXAMPLE.Invalid"),
      url = h("a.example.invalid"),
      zu = FALSE
    ),
    list(
      env = c(http_proxy = "PROXY", no_proxy = "x.invalid, example.invalid"),
      url = h("a.example.invalid"),
      zu = FALSE
    ),
    list(
      env = c(http_proxy = "PROXY", NO_PROXY = "example.invalid"),
      url = h("a.example.invalid"),
      zu = FALSE
    ),
    list(
      env = c(https_proxy = "PROXY", no_proxy = "example.invalid"),
      url = h("a.example.invalid", "https"),
      zu = FALSE
    ),
    # The lowercase variable wins when both are set.
    list(
      env = c(
        http_proxy = "PROXY",
        no_proxy = "x.invalid",
        NO_PROXY = "example.invalid"
      ),
      url = h("a.example.invalid"),
      zu = TRUE
    ),
    # A root dot on the host is stripped (§8.2) before matching.
    list(
      env = c(http_proxy = "PROXY", no_proxy = "example.invalid"),
      url = h("a.example.invalid."),
      zu = FALSE
    ),
    # "*" is special only alone; "*.example.invalid" is not a glob.
    list(
      env = c(http_proxy = "PROXY", no_proxy = "*.example.invalid"),
      url = h("a.example.invalid"),
      zu = TRUE
    ),
    list(
      env = c(http_proxy = "PROXY", no_proxy = "localhost"),
      url = h("localhost"),
      zu = FALSE
    ),
    # IP literals match exactly, never by suffix.
    list(
      env = c(http_proxy = "PROXY", no_proxy = "127.0.0.1"),
      url = h("127.0.0.1"),
      zu = FALSE
    ),
    # An address has no labels: a partial one is not a suffix (#266).
    list(
      env = c(http_proxy = "PROXY", no_proxy = "0.0.1"),
      url = h("127.0.0.1"),
      zu = TRUE
    ),
    list(
      env = c(http_proxy = "PROXY", no_proxy = "1"),
      url = h("127.0.0.1"),
      zu = TRUE
    ),
    list(
      env = c(http_proxy = "PROXY", no_proxy = "::1"),
      url = h("[::1]"),
      zu = FALSE
    ),
    # Expected difference: zuhttp reads an IPv6 entry in brackets, the form
    # an entry needs to carry a port ("[::1]:8080", §20.2), and libcurl
    # compares the brackets as text and never matches.
    list(
      env = c(http_proxy = "PROXY", no_proxy = "[::1]"),
      url = h("[::1]"),
      zu = FALSE,
      curl = TRUE
    ),
    # Expected difference: §20.2 does not support CIDR, so the entry matches
    # nothing and the request is proxied, the safe side of the gap; libcurl
    # (7.86 and later) supports CIDR and goes direct.
    list(
      env = c(http_proxy = "PROXY", no_proxy = "127.0.0.0/8"),
      url = h("127.0.0.1"),
      zu = TRUE,
      curl = FALSE
    ),
    # Expected difference: §20.2 lets an entry carry a port, which must
    # match too; libcurl has no port syntax and the entry never matches.
    list(
      env = c(
        http_proxy = "PROXY",
        no_proxy = paste0("example.invalid:", closed)
      ),
      url = h("a.example.invalid"),
      zu = FALSE,
      curl = TRUE
    ),
    list(
      env = c(http_proxy = "PROXY", no_proxy = "example.invalid:1"),
      url = h("a.example.invalid"),
      zu = TRUE
    ),
    # A root dot on an entry is stripped like the host's (#267).
    list(
      env = c(http_proxy = "PROXY", no_proxy = "example.invalid."),
      url = h("a.example.invalid"),
      zu = FALSE
    )
  )
  results <- with_raw_server_seq(
    crlf("HTTP/1.1 200 OK", "Content-Length: 2", "Connection: close", "", "hi"),
    function(srv) {
      lapply(rows, function(row) {
        local_proxy_env(row$env, srv$url)
        c(
          zu = reached_proxy(srv, zu_fetch_env_proxy(row$url)),
          curl = reached_proxy(srv, curl_fetch_env_proxy(row$url))
        )
      })
    }
  )
  for (i in seq_along(rows)) {
    row <- rows[[i]]
    label <- paste0(
      "row ",
      i,
      ": ",
      paste0(names(row$env), "=", row$env, collapse = " "),
      " ",
      row$url
    )
    want_curl <- if (is.null(row$curl)) row$zu else row$curl
    expect_identical(
      results[[i]][["zu"]],
      row$zu,
      label = paste("zuhttp", label)
    )
    expect_identical(
      results[[i]][["curl"]],
      want_curl,
      label = paste("libcurl", label)
    )
  }
})

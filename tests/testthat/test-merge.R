# §31.9's merge rules, stated as tests. The table in the design has three
# rules and two erasers; each gets its own test, because "how do I turn this
# off" is the first question the rules provoke and the answer must not drift.

test_that("collection-like options combine (headers)", {
  api <- zu_client(
    headers = c(Accept = "application/json", Authorization = "Bearer xxx")
  )
  r <- resolved(
    zu_headers(zu_request("GET", "https://x/"), "X-Debug" = "1"),
    api
  )

  expect_setequal(names(r$headers), c("Accept", "Authorization", "X-Debug"))
})

test_that("a request header replaces a same-name client header, case-insensitively", {
  api <- zu_client(headers = c(accept = "text/html"))
  r <- resolved(
    zu_headers(zu_request("GET", "https://x/"), Accept = "application/json"),
    api
  )

  expect_identical(unname(r$headers), "application/json")
  expect_identical(length(r$headers), 1L) # not two Accept headers on the wire
})

test_that("NA removes an inherited header", {
  api <- zu_client(
    headers = c(Accept = "application/json", Authorization = "Bearer xxx")
  )
  r <- resolved(
    zu_headers(zu_request("GET", "https://x/"), Authorization = NA),
    api
  )

  expect_identical(names(r$headers), "Accept")
})

test_that("query parameters combine, and NULL or NA removes one", {
  api <- zu_client(query = list(api_version = "2", trace = "on"))
  req <- zu_query(zu_request("GET", "https://x/"), q = "HTTP", trace = NULL)
  r <- resolved(req, api)

  expect_match(r$url, "api_version=2")
  expect_match(r$url, "q=HTTP")
  expect_false(grepl("trace", r$url, fixed = TRUE))
})

test_that("scalar policy: the request replaces the client's value", {
  api <- zu_client(timeout = 30, redirects = 9L)
  r <- resolved(zu_req_timeout(zu_request("GET", "https://x/"), total = 5), api)

  expect_identical(r$resolved$timeout, 5)
  expect_identical(r$resolved$redirects, 9L) # untouched fields still inherit
})

test_that("NULL for a policy resets to the package default, not the client's", {
  # The client's value is deliberately NOT the package default here: if it
  # were, this test would pass without the rule being implemented at all.
  api <- zu_client(timeout = 90)
  r <- resolved(zu_req_timeout(zu_request("GET", "https://x/"), NULL), api)

  expect_identical(r$resolved$timeout, zuhttp:::zu_defaults()$timeout)
  expect_false(identical(r$resolved$timeout, 90))
})

test_that("a client with nothing set produces the package defaults", {
  r <- resolved(zu_request("GET", "https://x/"), zu_client())
  expect_identical(
    r$resolved[names(zuhttp:::zu_defaults())],
    zuhttp:::zu_defaults()
  )
})

test_that("zu_client_update() does not mutate its argument (§31.10)", {
  api <- zu_client(
    base_url = "https://api.example.com",
    headers = c(Accept = "application/json")
  )
  admin <- zu_client_update(api, headers = c(Authorization = "Bearer admin"))

  expect_identical(names(api$headers), "Accept")
  expect_setequal(names(admin$headers), c("Accept", "Authorization"))
  expect_identical(admin$base_url, api$base_url)
})

test_that("zu_client_update() rejects a setting that does not exist", {
  expect_error(
    zu_client_update(zu_client(), timout = 5),
    "not a client setting"
  )
})

test_that("zu_client_update(x, field = NULL) resets the field and keeps it (§31.9)", {
  # `client[[nm]] <- NULL` deletes a list element, so this once removed
  # `timeout` from the client, and the next update of it was rejected as
  # "not a client setting".
  api <- zu_client(timeout = 10)
  reset <- zu_client_update(api, timeout = NULL)
  expect_identical(names(reset), names(api))
  expect_null(reset$timeout)
  expect_identical(
    resolved(zu_request("GET", "https://x/"), reset)$resolved$timeout,
    zuhttp:::zu_defaults()$timeout
  )
  expect_identical(zu_client_update(reset, timeout = 5)$timeout, 5)
})

test_that("base_url is joined, not resolved", {
  api <- zu_client(base_url = "https://api.example.com/v1")
  # RFC 3986 resolution would drop /v1 here. That surprise is the reason the
  # join is textual (§31.3).
  expect_identical(
    resolved(zu_request("GET", "/users"), api)$url,
    "https://api.example.com/v1/users"
  )
  expect_identical(
    resolved(zu_request("GET", "users"), api)$url,
    "https://api.example.com/v1/users"
  )
  # An absolute URL ignores base_url entirely.
  expect_identical(
    resolved(zu_request("GET", "https://other.example/x"), api)$url,
    "https://other.example/x"
  )
})

test_that("a relative URL with no base_url is a clear error, not a bad request", {
  e <- tryCatch(
    resolved(zu_request("GET", "/users"), zu_client()),
    zu_url_error = function(e) e
  )
  expect_s3_class(e, "zu_url_error")
  expect_match(conditionMessage(e), "base_url")
})

test_that("the body's content type loses to an explicit header (§31.2)", {
  req <- zu_body_json(zu_request("POST", "https://x/"), list(a = 1))
  req <- zu_headers(req, "Content-Type" = "application/vnd.api+json")
  r <- resolved(req, zu_client())

  expect_identical(
    unname(r$headers[["Content-Type"]]),
    "application/vnd.api+json"
  )
  expect_identical(sum(tolower(names(r$headers)) == "content-type"), 1L)
})

test_that("verify = FALSE warns, wherever it is set", {
  expect_warning(
    resolved(zu_request("GET", "https://x/"), zu_client(verify = FALSE)),
    "disables certificate AND hostname"
  )
})

test_that("verify, check and decode must be TRUE or FALSE, never read as the weaker one", {
  # Downstream reads all three with isTRUE(), so NA or "yes" used to switch
  # verification off with only a warning, and check and decode off silently.
  req <- zu_request("GET", "https://x/")
  for (f in c("verify", "check", "decode")) {
    for (bad in list(NA, "yes", 1, c(TRUE, TRUE), logical())) {
      cli <- do.call(zu_client, stats::setNames(list(bad), f))
      expect_error(
        suppressWarnings(resolved(req, cli)),
        paste0("`", f, "` must be TRUE or FALSE"),
        fixed = TRUE,
        info = paste(f, deparse(bad))
      )
    }
  }
  expect_no_error(resolved(req, zu_client(check = FALSE, decode = FALSE)))
})

test_that("max_body = Inf means no limit, as timeout = Inf does", {
  r <- resolved(zu_request("GET", "https://x/"), zu_client(max_body = Inf))
  expect_identical(r$resolved$max_body, Inf)
  expect_error(
    resolved(zu_request("GET", "https://x/"), zu_client(max_body = NA)),
    "max_body"
  )
})

test_that("query values are encoded, and a vector repeats the key", {
  r <- resolved(
    zu_query(
      zu_request("GET", "https://x/"),
      q = "a b&c",
      ok = TRUE,
      id = c(1, 2)
    ),
    zu_client()
  )
  expect_match(r$url, "q=a%20b%26c", fixed = TRUE)
  expect_match(r$url, "ok=true", fixed = TRUE)
  expect_match(r$url, "id=1&id=2", fixed = TRUE)
})

test_that("a URL that already has a query keeps it", {
  r <- resolved(
    zu_query(zu_request("GET", "https://x/?a=1"), b = "2"),
    zu_client()
  )
  expect_identical(r$url, "https://x/?a=1&b=2")
})

test_that("a printed client shows policy objects as readable lines", {
  # print.zu_client() formats every policy field; without format() methods a
  # retry policy printed as its fields pasted together
  # ("3exponential160TRUETRUE60NULL") and a TLS config likewise.
  out <- capture.output(print(zu_client(
    retry = zu_retry(attempts = 3),
    tls = zu_tls(ca_extra = "/etc/hosts", min_version = 12)
  )))
  retry <- grep("^  retry: ", out, value = TRUE)
  tls <- grep("^  tls: ", out, value = TRUE)
  expect_identical(
    retry,
    "  retry: 3 attempts, exponential backoff, honours Retry-After"
  )
  expect_match(tls, "ca_extra /etc/hosts (adds to system trust)", fixed = TRUE)
  expect_match(tls, "min TLS 1.2", fixed = TRUE)
  expect_match(
    grep("^  retry: ", capture.output(print(zu_client())), value = TRUE),
    "off (1 attempt)",
    fixed = TRUE
  )
})

test_that("zu_client_update() can erase a client's only header or parameter", {
  # The merge was NULL once nothing was left, and `$<-` with NULL dropped
  # the change, so a lone Authorization header could not be removed.
  c1 <- zu_client(headers = c(Authorization = "Bearer s"))
  expect_null(zu_client_update(c1, headers = c(Authorization = NA))$headers)
  c2 <- zu_client(query = list(token = "x"))
  expect_null(zu_client_update(c2, query = list(token = NA))$query)
  c3 <- zu_client(headers = c(Authorization = "Bearer s", Accept = "a/b"))
  expect_identical(
    names(zu_client_update(c3, headers = c(Authorization = NA))$headers),
    "Accept"
  )
})

test_that("client settings are refused by name, not by a raw R error", {
  expect_error(zu_client(base_url = NA_character_), "base_url")
  expect_error(zu_client(base_url = c("a", "b")), "base_url")
  expect_error(
    zu_client_update(zu_client(), base_url = NA_character_),
    "base_url"
  )
  m <- zu_mock_transport(zu_stub(response = zu_response(200L, body = "x")))
  expect_error(
    zu_get("https://x.test", retry = 3, client = zu_client(transport = m)),
    "zu_retry"
  )
  expect_error(
    zu_get("https://x.test", retry = TRUE, client = zu_client(transport = m)),
    "zu_retry"
  )
})

test_that("a client prints its base_url redacted (§42.2)", {
  out <- capture.output(print(zu_client(
    base_url = "http://u:pw@h.test/?token=x"
  )))
  line <- grep("base_url", out, value = TRUE)
  expect_false(grepl("pw", line, fixed = TRUE))
  expect_false(grepl("token=x", line, fixed = TRUE))
})

test_that("timeouts round up to whole milliseconds, never down to none", {
  expect_identical(zuhttp:::timeout_ms(1.001), 1001L)
  expect_identical(zuhttp:::timeout_ms(0.3), 300L)
  expect_identical(zuhttp:::timeout_ms(0.0005), 1L)
  expect_identical(zuhttp:::timeout_ms(30), 30000L)
})

test_that("user_agent and zu_retry() flags are refused unless they say what they mean", {
  m <- zu_mock_transport(zu_stub(response = zu_response(200L, body = "x")))
  cl <- zu_client(transport = m)
  for (ua in list(NA_character_, c("a", "b"), 5)) {
    expect_error(
      zu_get("https://x.test", user_agent = ua, client = cl),
      "user_agent"
    )
  }
  expect_error(zu_retry(jitter = 1), "jitter")
  expect_error(zu_retry(retry_after = "yes"), "retry_after")
  expect_error(
    zu_req_retry(zu_request("POST", "https://x.test"), replay_safe = "yes"),
    "replay_safe"
  )
})

test_that("an explicit Content-Type of NA sends none, even for a JSON body", {
  seen <- with_raw_server(
    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    function(url) {
      req <- zu_body_json(zu_request("POST", paste0(url, "/j")), list(a = 1))
      zu_perform(zu_headers(req, "Content-Type" = NA))
    }
  )
  expect_false(grepl("Content-Type", seen, ignore.case = TRUE))
})

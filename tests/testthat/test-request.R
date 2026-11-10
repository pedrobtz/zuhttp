# §31.4/§31.6 — request composition. Building a request is a pure operation;
# these tests never reach a transport.

test_that("method and URL are request identity (§31.5)", {
  req <- zu_request("post", "https://x/")
  expect_identical(req$method, "POST")
  expect_identical(req$url, "https://x/")
  # Arbitrary methods stay possible.
  expect_identical(zu_request("PROPFIND", "https://x/")$method, "PROPFIND")
  expect_error(zu_request("BAD METHOD", "https://x/"), "valid HTTP method")
})

test_that("transformers return a new request and leave the original alone", {
  a <- zu_request("GET", "https://x/")
  b <- zu_headers(a, Accept = "text/plain")
  expect_null(a$headers)
  expect_identical(unname(b$headers[["Accept"]]), "text/plain")
})

test_that("zu_headers() accepts a named vector as well as named arguments", {
  a <- zu_headers(
    zu_request("GET", "https://x/"),
    c(Accept = "text/plain", "X-A" = "1")
  )
  b <- zu_headers(
    zu_request("GET", "https://x/"),
    Accept = "text/plain",
    "X-A" = "1"
  )
  expect_identical(a$headers, b$headers)
})

test_that("the body helpers set bytes and an implied content type", {
  expect_identical(
    rawToChar(zu_body_raw(zu_request("POST", "https://x/"), "hi")$body),
    "hi"
  )
  expect_identical(
    zu_body_raw(zu_request("POST", "https://x/"), "hi")$content_type,
    "text/plain; charset=UTF-8"
  )

  f <- zu_body_form(zu_request("POST", "https://x/"), list(a = "1 2", b = TRUE))
  expect_identical(rawToChar(f$body), "a=1%202&b=true")
  expect_identical(f$content_type, "application/x-www-form-urlencoded")

  path <- tempfile()
  on.exit(unlink(path), add = TRUE)
  writeBin(charToRaw("filebytes"), path)
  expect_identical(
    rawToChar(zu_body_file(zu_request("PUT", "https://x/"), path)$body),
    "filebytes"
  )
})

test_that("body arguments are mutually exclusive", {
  expect_error(
    zu_post(
      "https://x/",
      body = "a",
      json = list(b = 1),
      client = zu_client(
        transport = zu_mock_transport(function(req) zu_response())
      )
    ),
    "mutually exclusive"
  )
})

test_that("a request prints its method, URL, headers and body (§31.4)", {
  req <- zu_request("POST", "https://api.example.com/users")
  req <- zu_query(req, verbose = TRUE)
  req <- zu_headers(req, Accept = "application/json")
  req <- zu_body_json(req, list(name = "Alice"))
  req <- zu_req_timeout(req, total = 10)

  out <- paste(capture.output(print(req)), collapse = "\n")
  expect_match(
    out,
    "POST https://api.example.com/users?verbose=true",
    fixed = TRUE
  )
  expect_match(out, "Accept: application/json", fixed = TRUE)
  expect_match(out, "Content-Type: application/json", fixed = TRUE)
  expect_match(out, "Body: JSON, 16 bytes", fixed = TRUE)
  expect_match(out, "timeout: 10", fixed = TRUE)
})

test_that("the one-shot helpers lower to the same request (§31.1 principle 3)", {
  seen <- NULL
  api <- zu_client(
    transport = zu_mock_transport(function(req) {
      seen <<- req
      zu_response(200L)
    })
  )

  zu_post(
    "https://x/users",
    json = list(name = "Alice"),
    timeout = 10,
    client = api
  )
  one_shot <- seen

  req <- zu_request("POST", "https://x/users")
  req <- zu_body_json(req, list(name = "Alice"))
  req <- zu_req_timeout(req, total = 10)
  zu_perform(req, client = api)
  composed <- seen

  # Same wire request, same resolved policy, whichever way it was written.
  expect_identical(one_shot$method, composed$method)
  expect_identical(one_shot$url, composed$url)
  expect_identical(one_shot$headers, composed$headers)
  expect_identical(one_shot$body, composed$body)
  # identical(), not all.equal(): the resolved policy is the §31.9 merge and
  # nothing else. The attempt's time budget (§24.3) is a separate field, so a
  # clock reading cannot leak in here and make the two differ by a tick.
  expect_identical(one_shot$resolved, composed$resolved)
  expect_true(one_shot$attempt_budget <= one_shot$resolved$timeout)
})

test_that("every method helper sends its own method", {
  seen <- NULL
  api <- zu_client(
    transport = zu_mock_transport(function(req) {
      seen <<- req$method
      zu_response(200L)
    })
  )
  for (m in c("get", "head", "post", "put", "patch", "delete")) {
    do.call(paste0("zu_", m), list("https://x/", client = api))
    expect_identical(seen, toupper(m))
  }
})

test_that("a client is never argument one (§31.3)", {
  # The zu_client_*() wrappers went with D-65; the rule they softened stays.
  api <- zu_client(
    base_url = "https://api.example.com",
    transport = zu_mock_transport(function(req) {
      zu_response(200L, body = req$url)
    })
  )
  expect_identical(
    zu_resp_text(zu_get("/users", client = api)),
    "https://api.example.com/users"
  )
  # The plain form refuses a client in argument one, with a message that says
  # what to do rather than failing somewhere in the URL parser.
  expect_error(zu_get(api), "url")
})

test_that("zu_perform() rejects a non-client and a non-request", {
  expect_error(
    zu_perform(zu_request("GET", "https://x/"), client = list()),
    "must be a zu_client"
  )
  expect_error(zu_perform("https://x/"), "zu_request")
})

test_that("a transport must return a response", {
  api <- zu_client(
    transport = zu_mock_transport(function(req) "not a response")
  )
  expect_error(zu_get("https://x/", client = api), "must return a zu_response")
})

test_that("a request header carrying CR/LF is refused before connecting, naming it (§17.1, D-85)", {
  # Port 1 on loopback: were anything attempted, this would be a connect error.
  cli <- zu_client(pool = NULL, proxy = FALSE)
  e <- expect_error(
    zu_get(
      "http://127.0.0.1:1/",
      headers = c(`X-Evil` = "a\r\nInjected: 1"),
      client = cli
    ),
    class = "zu_http_parse_error"
  )
  expect_match(conditionMessage(e), "`X-Evil`", fixed = TRUE)
  expect_false(grepl("Injected", conditionMessage(e), fixed = TRUE))
})

test_that("the body decides the framing: a conflicting header is refused before connecting (D-78)", {
  # Port 1 on loopback: were anything sent, this would be a connect error.
  url <- "http://127.0.0.1:1/"
  cli <- zu_client(pool = NULL, proxy = FALSE, retry = zu_retry(1))
  expect_error(
    zu_post(
      url,
      body = "hello",
      headers = c(`Content-Length` = "1"),
      client = cli
    ),
    class = "zu_http_parse_error",
    regexp = "does not match the 5-byte body"
  )
  expect_error(
    zu_post(
      url,
      body = "hello",
      headers = c(`Transfer-Encoding` = "chunked"),
      client = cli
    ),
    class = "zu_http_parse_error",
    regexp = "Transfer-Encoding"
  )
  # A matching length is not a conflict, so the request proceeds to connect.
  expect_error(
    zu_post(
      url,
      body = "hello",
      headers = c(`Content-Length` = "5"),
      client = cli,
      timeout = 5
    ),
    class = "zu_connect_error"
  )
})

test_that("query parameters go before a URL's fragment, not into it (#219)", {
  # Appended after the whole URL they landed inside the fragment, which the
  # URI parser then dropped, parameters and all, without an error.
  seen <- character()
  cli <- zu_client(
    transport = zu_mock_transport(function(req) {
      seen <<- c(seen, req$url)
      zu_response()
    })
  )
  zu_get("http://h.test/p#sec", query = list(x = "hello"), client = cli)
  zu_get("http://h.test/p?a=1#sec", query = list(x = "hello"), client = cli)
  # A `?` inside the fragment is not a query: the separator is still `?`.
  zu_get("http://h.test/p#a?b", query = list(x = "hello"), client = cli)
  expect_identical(
    seen,
    c(
      "http://h.test/p?x=hello#sec",
      "http://h.test/p?a=1&x=hello#sec",
      "http://h.test/p?x=hello#a?b"
    )
  )
})

test_that("`redirects` beyond an integer is refused, not read as no redirects (#221)", {
  # as.integer(1e10) is NA, which C read as INT_MIN: every redirect test
  # failed and the 3xx came back with only a coercion warning.
  cli <- zu_client(transport = zu_mock_transport(function(req) zu_response()))
  for (bad in list(1e10, .Machine$integer.max + 1, Inf)) {
    expect_error(
      zu_get("http://h.test/", redirects = bad, client = cli),
      "`redirects` must be"
    )
  }
  expect_identical(
    zu_resp_status(zu_get(
      "http://h.test/",
      redirects = .Machine$integer.max,
      client = cli
    )),
    200L
  )
})

# --- #243: percent-encoding against three references ----------------------
#
# §8.2: zu_query() and zu_body_form() encode from UTF-8, every byte outside
# RFC 3986 §2.3's unreserved set as %XX (uppercase, §2.1), space as %20. The
# references: that rule computed here from the RFC, libcurl's
# curl_easy_escape() and Python's urllib.parse.quote(safe=""). A random
# string set, seeded, with the characters a hand-written case forgets: "~"
# and "*" (unreserved in RFC 3986, reserved in RFC 2396), "+", the controls,
# and code points of two, three and four UTF-8 bytes.

test_that("query and form values are RFC 3986 percent-encoded UTF-8 (#243)", {
  s <- encoding_inputs()
  want <- vapply(s, rfc3986_encode, character(1), USE.NAMES = FALSE)
  q <- vapply(s, zu_query_encoded, character(1), USE.NAMES = FALSE)
  f <- vapply(s, zu_form_encoded, character(1), USE.NAMES = FALSE)
  expect_identical(q, want)
  expect_identical(f, paste0("k=", want))
  # A name is encoded by the same rule as a value.
  nm <- s[nzchar(s)][1:50]
  got <- vapply(
    nm,
    function(n) {
      rawToChar(
        zu_body_form(
          zu_request("POST", "https://x/"),
          stats::setNames(list("v"), n)
        )$body
      )
    },
    character(1),
    USE.NAMES = FALSE
  )
  expect_identical(
    got,
    paste0(vapply(nm, rfc3986_encode, character(1), USE.NAMES = FALSE), "=v")
  )
})

test_that("query encoding matches libcurl's curl_escape() (#243)", {
  skip_if_not_installed("curl")
  s <- encoding_inputs()
  q <- vapply(s, zu_query_encoded, character(1), USE.NAMES = FALSE)
  expect_identical(q, curl::curl_escape(s))
})

test_that("query encoding matches Python's urllib.parse.quote() (#243)", {
  skip_unless_python()
  s <- encoding_inputs()
  ref <- run_python_json("quote.py", charToRaw(enc2utf8(zujson::json_write(s))))
  q <- vapply(s, zu_query_encoded, character(1), USE.NAMES = FALSE)
  expect_identical(q, unlist(ref))
})

test_that("a form body round-trips through Python's form decoder (#243)", {
  skip_unless_python()
  s <- encoding_inputs()
  # Names and values together, several pairs to a body, so "&" and "="
  # inside a value are tested where they could split a pair.
  forms <- lapply(seq(1, length(s) - 2L, by = 3L), function(i) {
    stats::setNames(as.list(s[i + 1:2]), c(paste0("n", s[i]), "x=&y"))
  })
  bodies <- vapply(
    forms,
    function(x) {
      rawToChar(zu_body_form(zu_request("POST", "https://x/"), x)$body)
    },
    character(1)
  )
  ref <- run_python_json(
    "form_decode.py",
    charToRaw(enc2utf8(zujson::json_write(bodies)))
  )
  got <- lapply(ref, function(pairs) {
    pairs <- lapply(pairs, unlist)
    stats::setNames(lapply(pairs, `[[`, 2L), vapply(pairs, `[[`, "", 1L))
  })
  want <- lapply(forms, function(x) lapply(x, enc2utf8))
  expect_identical(got, want)
})

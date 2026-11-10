# zu_request()'s method check and the absolute-URL check, written without a
# regex (#282): R's TRE engine can report "no match" when an allocation
# fails, which refused a valid `GET`. The regexes they replace are the oracle.
test_that("the token and scheme checks agree with the regexes they replace (#282)", {
  withr::local_seed(282)
  # Every class boundary: tchar and its neighbours, scheme characters, ':',
  # '/', whitespace, a control byte, and UTF-8.
  alphabet <- c(
    strsplit("!#$%&'*+-.^_`|~:/@\"(),;<=>?[\\]{} \t09AZazGm", "")[[1]],
    "\001",
    "\u00e9",
    "\u4e2d"
  )
  draw <- function(n) {
    vapply(
      seq_len(n),
      function(i) paste(sample(alphabet, sample(0:6, 1), TRUE), collapse = ""),
      character(1)
    )
  }
  old_token <- function(s) {
    !is.na(s) && grepl("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$", s)
  }
  tokens <- c(draw(4000), "", "GET", "M-SEARCH", "get", "G E", NA)
  got <- vapply(tokens, zuhttp:::is_token, logical(1), USE.NAMES = FALSE)
  want <- vapply(tokens, old_token, logical(1), USE.NAMES = FALSE)
  expect_identical(got, want)

  old_abs <- function(x) grepl("^[A-Za-z][A-Za-z0-9+.-]*://", x)
  urls <- c(
    paste0(draw(3000), "://h/"),
    draw(1000),
    "http://h/",
    "HTTPS://h",
    "a+b.c-d://h",
    "1http://h",
    "://h",
    "h://",
    "/path",
    "x:/y",
    "a://b://c",
    NA
  )
  expect_identical(zuhttp:::is_absolute_url(urls), old_abs(urls))
})

test_that("zu_request() still refuses a method that is not a token", {
  expect_error(zu_request("G E", "http://h.test/"), "not a valid HTTP method")
  expect_error(zu_request("", "http://h.test/"), "not a valid HTTP method")
  expect_error(
    zu_request("G\u00e9T", "http://h.test/"),
    "not a valid HTTP method"
  )
  expect_identical(zu_request("m-search", "http://h.test/")$method, "M-SEARCH")
})

test_that("a mock body reaches a callback, as a native one does (§27)", {
  m <- zu_mock_transport(zu_stub(
    response = zu_response(200L, body = strrep("x", 1000))
  ))
  cl <- zu_client(transport = m)
  got <- raw()
  r <- zu_get(
    "https://m.test/",
    callback = function(b) {
      got <<- c(got, b)
      TRUE
    },
    client = cl
  )
  expect_length(got, 1000)
  expect_identical(zu_resp_raw(r), raw())
})

test_that("a cassette in auto mode records a retry, not the attempt it retried", {
  d <- withr::local_tempdir()
  busy <- "HTTP/1.1 503 Busy\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
  with_raw_server_seq(
    list(
      busy,
      busy,
      "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
    ),
    function(srv) {
      cl <- zu_client(
        transport = zu_cassette_transport(d, "retry", mode = "auto"),
        retry = zu_retry(attempts = 4, base = 0.01)
      )
      expect_identical(
        zu_resp_status(zu_get(
          paste0(srv$url, "/x"),
          client = cl,
          timeout = 10
        )),
        200L
      )
      replay <- zu_client(
        transport = zu_cassette_transport(d, "retry", mode = "replay")
      )
      expect_identical(
        zu_resp_status(zu_get(paste0(srv$url, "/x"), client = replay)),
        200L
      )
    }
  )
})

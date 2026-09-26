# Match a request and return a canned response

A stub pairs a matcher with a response. Every supplied criterion must
match (they are ANDed); an omitted criterion matches anything.

## Usage

``` r
zu_stub(
  response,
  method = NULL,
  url = NULL,
  regex = NULL,
  headers = NULL,
  body = NULL,
  times = Inf
)
```

## Arguments

- response:

  A
  [`zu_response()`](https://pedrobtz.github.io/zuhttp/reference/zu_response.md),
  or a function of one request returning one. The function form is for
  stubs whose reply depends on the request.

- method:

  HTTP method to match, case-insensitive. `NULL` matches any.

- url:

  URL to match. A plain string must match exactly *after* client merging
  — that is, the absolute URL with the query attached. Use `regex` for
  anything looser.

- regex:

  A regular expression matched against the URL, as an alternative to
  `url`.

- headers:

  Named character vector of headers that must be present with these
  values. Names are matched case-insensitively (§18.3); headers not
  named here are ignored.

- body:

  Raw or character body that must match exactly.

- times:

  Maximum number of times this stub may match; `Inf` by default. A stub
  with `times = 1` is how you assert a request is not retried.

## Value

A `zu_stub`, for
[`zu_mock_transport()`](https://pedrobtz.github.io/zuhttp/reference/zu_transport.md).

## See also

[`zu_mock_transport()`](https://pedrobtz.github.io/zuhttp/reference/zu_transport.md)

## Examples

``` r
stub <- zu_stub(zu_response(201L), method = "POST", regex = "/users$")
api  <- zu_client(transport = zu_mock_transport(stub))
zu_resp_status(zu_perform(zu_request("POST", "https://x.test/users"),
                          client = api))
#> [1] 201
```

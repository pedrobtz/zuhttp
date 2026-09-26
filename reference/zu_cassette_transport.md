# Record and replay HTTP interactions

A transport that plays responses back from a cassette on disk, so a
downstream package's tests run with no network. In `"auto"` mode it
records whatever it has not seen before and replays everything else,
which means a test suite is written once against the real service and
then runs offline.

## Usage

``` r
zu_cassette_transport(
  dir = file.path(tempdir(), "zuhttp-cassettes"),
  name = "default",
  mode = c("auto", "replay", "record"),
  transport = zu_native_transport()
)
```

## Arguments

- dir:

  Directory holding cassettes. Defaults to a subdirectory of
  [`tempdir()`](https://rdrr.io/r/base/tempfile.html), so nothing is
  written outside the session unless asked.

- name:

  Cassette name; one file, `<name>.rds`, inside `dir`.

- mode:

  `"auto"` records on a miss and replays on a hit; `"replay"` never
  touches the network and errors on a miss; `"record"` always performs
  the request and overwrites the stored interaction.

- transport:

  The transport used when actually performing a request. A
  [`zu_mock_transport()`](https://pedrobtz.github.io/zuhttp/reference/zu_transport.md)
  here is how this package tests itself.

## Value

A transport object, for `zu_client(transport = )`.

## What is written

Credentials are removed *before* anything reaches the disk: userinfo and
secret query parameters in URLs, secret headers in both directions, and
form-encoded bodies, all through the §42 policy that the rest of the
package uses. A cassette is the one egress that outlives the session, so
this is the egress where redaction matters most.

Requests are matched on method, URL and body — not on headers, which
vary with client configuration in ways that do not change what a server
would reply. The URL and body used for matching are the redacted ones,
so a cassette cannot be made to carry a secret by way of its index.

## See also

[`zu_cassette_interactions()`](https://pedrobtz.github.io/zuhttp/reference/zu_cassette_interactions.md),
[`zu_cassette_clear()`](https://pedrobtz.github.io/zuhttp/reference/zu_cassette_interactions.md)

## Examples

``` r
dir <- file.path(tempdir(), "zuhttp-example")
live <- zu_mock_transport(function(req) zu_response(200L, body = "hello"))

rec <- zu_cassette_transport(dir, "demo", transport = live)
zu_resp_text(zu_get("https://x.test/a", client = zu_client(transport = rec)))
#> [1] "hello"

# Now offline: the same request never reaches `live`.
rep <- zu_cassette_transport(dir, "demo", mode = "replay")
zu_resp_text(zu_get("https://x.test/a", client = zu_client(transport = rep)))
#> [1] "hello"
zu_cassette_clear(dir, "demo")
```

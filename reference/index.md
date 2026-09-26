# Package index

## All functions

- [`zu_body_json()`](https://pedrobtz.github.io/zuhttp/reference/zu_body.md)
  [`zu_body_form()`](https://pedrobtz.github.io/zuhttp/reference/zu_body.md)
  [`zu_body_raw()`](https://pedrobtz.github.io/zuhttp/reference/zu_body.md)
  [`zu_body_file()`](https://pedrobtz.github.io/zuhttp/reference/zu_body.md)
  : Set the request body
- [`zu_body_rewindable()`](https://pedrobtz.github.io/zuhttp/reference/zu_body_rewindable.md)
  : Can this request's body be replayed?
- [`zu_cassette_interactions()`](https://pedrobtz.github.io/zuhttp/reference/zu_cassette_interactions.md)
  [`zu_cassette_clear()`](https://pedrobtz.github.io/zuhttp/reference/zu_cassette_interactions.md)
  : Inspect or delete a cassette
- [`zu_cassette_transport()`](https://pedrobtz.github.io/zuhttp/reference/zu_cassette_transport.md)
  : Record and replay HTTP interactions
- [`zu_client()`](https://pedrobtz.github.io/zuhttp/reference/zu_client.md)
  : Create a reusable client
- [`zu_client_get()`](https://pedrobtz.github.io/zuhttp/reference/zu_client_methods.md)
  [`zu_client_head()`](https://pedrobtz.github.io/zuhttp/reference/zu_client_methods.md)
  [`zu_client_post()`](https://pedrobtz.github.io/zuhttp/reference/zu_client_methods.md)
  [`zu_client_put()`](https://pedrobtz.github.io/zuhttp/reference/zu_client_methods.md)
  [`zu_client_patch()`](https://pedrobtz.github.io/zuhttp/reference/zu_client_methods.md)
  [`zu_client_delete()`](https://pedrobtz.github.io/zuhttp/reference/zu_client_methods.md)
  : Client-first wrappers
- [`zu_client_update()`](https://pedrobtz.github.io/zuhttp/reference/zu_client_update.md)
  : Derive a client from another
- [`zu_code_retryable()`](https://pedrobtz.github.io/zuhttp/reference/zu_code_retryable.md)
  : Is an error code worth retrying?
- [`zu_condition()`](https://pedrobtz.github.io/zuhttp/reference/zu_condition.md)
  : Construct a zuhttp condition
- [`zu_default_client()`](https://pedrobtz.github.io/zuhttp/reference/zu_default_client.md)
  : The package-managed default client
- [`zu_error_codes()`](https://pedrobtz.github.io/zuhttp/reference/zu_error_codes.md)
  : Error codes used by zuhttp
- [`zu_headers()`](https://pedrobtz.github.io/zuhttp/reference/zu_headers.md)
  : Add headers
- [`zu_hooks()`](https://pedrobtz.github.io/zuhttp/reference/zu_hooks.md)
  : Register lifecycle hooks
- [`zu_info()`](https://pedrobtz.github.io/zuhttp/reference/zu_info.md)
  : What this build of zuhttp can do
- [`zu_is_secret_header()`](https://pedrobtz.github.io/zuhttp/reference/zu_is_secret_header.md)
  : Which header names carry a secret value?
- [`zu_is_secret_param()`](https://pedrobtz.github.io/zuhttp/reference/zu_is_secret_param.md)
  : Which query parameter names carry a secret value?
- [`zu_get()`](https://pedrobtz.github.io/zuhttp/reference/zu_methods.md)
  [`zu_head()`](https://pedrobtz.github.io/zuhttp/reference/zu_methods.md)
  [`zu_post()`](https://pedrobtz.github.io/zuhttp/reference/zu_methods.md)
  [`zu_put()`](https://pedrobtz.github.io/zuhttp/reference/zu_methods.md)
  [`zu_patch()`](https://pedrobtz.github.io/zuhttp/reference/zu_methods.md)
  [`zu_delete()`](https://pedrobtz.github.io/zuhttp/reference/zu_methods.md)
  : Perform a request in one call
- [`zu_perform()`](https://pedrobtz.github.io/zuhttp/reference/zu_perform.md)
  : Perform a request
- [`zu_pool()`](https://pedrobtz.github.io/zuhttp/reference/zu_pool.md)
  : Connection pool settings
- [`zu_pool_reset()`](https://pedrobtz.github.io/zuhttp/reference/zu_pool_reset.md)
  : Close a client's idle connections
- [`zu_pool_stats()`](https://pedrobtz.github.io/zuhttp/reference/zu_pool_stats.md)
  : Connection reuse counters
- [`zu_query()`](https://pedrobtz.github.io/zuhttp/reference/zu_query.md)
  : Add query parameters
- [`zu_redact_form()`](https://pedrobtz.github.io/zuhttp/reference/zu_redact_form.md)
  : Redact a form-encoded request body
- [`zu_redact_headers()`](https://pedrobtz.github.io/zuhttp/reference/zu_redact_headers.md)
  : Additional header names to redact
- [`zu_redact_headers_for_display()`](https://pedrobtz.github.io/zuhttp/reference/zu_redact_headers_for_display.md)
  : Redact a set of headers for display
- [`zu_redact_params()`](https://pedrobtz.github.io/zuhttp/reference/zu_redact_params.md)
  : Additional query parameter names to redact
- [`zu_redact_url()`](https://pedrobtz.github.io/zuhttp/reference/zu_redact_url.md)
  : Redact credentials from a URL
- [`zu_req_callback()`](https://pedrobtz.github.io/zuhttp/reference/zu_req_callback.md)
  : Stream the response body to a callback
- [`zu_req_path()`](https://pedrobtz.github.io/zuhttp/reference/zu_req_path.md)
  : Stream the response body to a file
- [`zu_req_timeout()`](https://pedrobtz.github.io/zuhttp/reference/zu_req_policy.md)
  [`zu_req_redirects()`](https://pedrobtz.github.io/zuhttp/reference/zu_req_policy.md)
  [`zu_req_check()`](https://pedrobtz.github.io/zuhttp/reference/zu_req_policy.md)
  : Set request policy
- [`zu_req_replay_safe()`](https://pedrobtz.github.io/zuhttp/reference/zu_req_replay_safe.md)
  : Is this request safe to replay?
- [`zu_req_retry()`](https://pedrobtz.github.io/zuhttp/reference/zu_req_retry.md)
  : Per-request retry settings
- [`zu_req_trace()`](https://pedrobtz.github.io/zuhttp/reference/zu_req_trace.md)
  : Record a §35.3 event trace for this request
- [`zu_request()`](https://pedrobtz.github.io/zuhttp/reference/zu_request.md)
  : Build a request without performing it
- [`zu_resp_status()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp.md)
  [`zu_resp_path()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp.md)
  [`zu_resp_ok()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp.md)
  [`zu_resp_headers()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp.md)
  [`zu_resp_header()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp.md)
  [`zu_resp_url()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp.md)
  [`zu_resp_method()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp.md)
  [`zu_resp_timings()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp.md)
  : Response accessors
- [`zu_resp_check()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_check.md)
  : Raise a condition for an error status
- [`zu_resp_connection()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_connection.md)
  : Connection metadata
- [`zu_resp_json()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_json.md)
  : The response body as parsed JSON
- [`zu_resp_raw()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_raw.md)
  : The response body, decoded
- [`zu_resp_text()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_text.md)
  : The response body as text
- [`zu_resp_trace()`](https://pedrobtz.github.io/zuhttp/reference/zu_resp_trace.md)
  : The event trace for a request
- [`zu_response()`](https://pedrobtz.github.io/zuhttp/reference/zu_response.md)
  : Construct a response
- [`zu_retry()`](https://pedrobtz.github.io/zuhttp/reference/zu_retry.md)
  : Retry policy
- [`zu_set_default_client()`](https://pedrobtz.github.io/zuhttp/reference/zu_set_default_client.md)
  : Replace the default client
- [`zu_set_json_backend()`](https://pedrobtz.github.io/zuhttp/reference/zu_set_json_backend.md)
  : Choose the JSON implementation
- [`zu_stub()`](https://pedrobtz.github.io/zuhttp/reference/zu_stub.md)
  : Match a request and return a canned response
- [`zu_tls()`](https://pedrobtz.github.io/zuhttp/reference/zu_tls.md) :
  TLS and certificate trust settings
- [`zu_tls_backend()`](https://pedrobtz.github.io/zuhttp/reference/zu_tls_backend.md)
  : Which TLS backend was this build linked against?
- [`zu_native_transport()`](https://pedrobtz.github.io/zuhttp/reference/zu_transport.md)
  [`zu_mock_transport()`](https://pedrobtz.github.io/zuhttp/reference/zu_transport.md)
  : Transports
- [`zu_transport_perform()`](https://pedrobtz.github.io/zuhttp/reference/zu_transport_perform.md)
  : Perform a request through a transport
- [`zu_verbose()`](https://pedrobtz.github.io/zuhttp/reference/zu_verbose.md)
  : Print a trace of each request
- [`zuhttp_fork`](https://pedrobtz.github.io/zuhttp/reference/zuhttp_fork.md)
  : HTTPS in a forked process
- [`zuhttp_tls`](https://pedrobtz.github.io/zuhttp/reference/zuhttp_tls.md)
  : TLS backends and their limits

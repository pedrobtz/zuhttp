# Test fixtures

Committed with their provenance; nothing here is generated at test time.

- `tls/` — the §50.5 certificate matrix: two CAs (`ca`, `rogueca`) and
  five leaves (`good`, `wronghost`, `untrusted`, `expired`, `notyet`), each
  a `.pem` and its `.key`. Made by `tools/make-tls-fixture`; `tls/PROVENANCE`
  records when and with which OpenSSL. The keys are test material and
  protect nothing. The CAs are valid for ten years; the live leaves for
  397 days from generation, the most Apple's SecTrust accepts for a TLS
  server certificate. `test-certs.R` fails, naming the generator, when
  they are within 45 days of expiry: re-run it and commit (review #193).
- `pool-config-pre-w21.rds` — a `zu_pool_config` as a build before W21
  (2026-11-04) saved it, with the three fields `zu_pool()` had then and no
  keepalive fields. Made on 2026-11-07 by `tools/make-fixtures.R`, for the
  `readRDS()` compatibility branch in `R/pool.R` (§26.5; review #195).

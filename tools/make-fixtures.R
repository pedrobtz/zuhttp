# Regenerates tests/testthat/fixtures/. Run from the package root:
#   Rscript tools/make-fixtures.R
# Each fixture is committed with its provenance in fixtures/README.md.

# A zu_pool_config as a build before W21 saved it: the three fields of the
# time, in the class, and no keepalive fields (§26.5's readRDS() case).
cfg <- structure(
  list(max_idle = 8L, max_per_host = 4L, idle_timeout_ms = 60000L),
  class = "zu_pool_config"
)
saveRDS(
  cfg,
  "tests/testthat/fixtures/pool-config-pre-w21.rds",
  version = 2,
  compress = FALSE
)

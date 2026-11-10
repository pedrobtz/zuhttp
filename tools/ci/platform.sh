#!/bin/sh
# zuhttp's per-OS checks, one job per OS: run by r-actions' platforms.yml as
#
#   bash tools/ci/platform.sh macos|windows
#
# with R_ACTIONS_PROFILE quick or full (.claude/shared/ci.md, "A package's own
# workflows"). These were eight macOS jobs and four Windows jobs across
# c-core, network and fuzz.yaml; a pull request now waits for one runner of
# each. Every check is a command that `set -e` stops at, preceded by a
# `::group::` line, so the log still names the check that failed. Linux keeps
# its own jobs in those workflows.
set -eu
os=$1
full=false; [ "${R_ACTIONS_PROFILE:-full}" = full ] && full=true
step() { echo "::endgroup::"; echo "::group::$*"; }
trap 'echo "::endgroup::"' EXIT
echo "::group::start ($os, profile ${R_ACTIONS_PROFILE:-full})"

macos() {
  brew list openssl@3 >/dev/null 2>&1 || brew install openssl@3
  openssl_bin="$(brew --prefix openssl@3)/bin/openssl"
  export PKG_CONFIG_PATH="/opt/homebrew/opt/openssl@3/lib/pkgconfig:/usr/local/opt/openssl@3/lib/pkgconfig"

  step "C core: warnings as errors (c-core)"
  ZU_TEST_TRACE=1 make -C ctest strict
  step "C core: ASan + UBSan (c-core)"
  ZU_TEST_TRACE=1 make -C ctest asan
  step "C core with the DNS assertions (network: net-online)"
  ZU_TEST_DNS=1 make -C ctest run

  step "TLS engine tests on OpenSSL (network: S7)"
  make -C ctest tls
  make -C ctest tls-asan
  step "63.2 slice in C on OpenSSL, and under ASan + UBSan (#231)"
  make -C ctest engine
  make -C ctest engine-asan
  step "OpenSSL end of stream, pool liveness, renegotiation (D-86, #215)"
  OPENSSL="$openssl_bin" make -C ctest tls-eof
  OPENSSL="$openssl_bin" make -C ctest tls-eof-asan
  step "Network.framework fork drop (#249)"
  OPENSSL="$openssl_bin" make -C ctest tls-fork-nw
  OPENSSL="$openssl_bin" make -C ctest tls-fork-nw-asan

  step "S9 slice on Network.framework + SecTrust, and under ASan + UBSan"
  make -C ctest engine-nw
  make -C ctest engine-nw-asan
  step "S9 slice as macOS < 14 sees it (proxied HTTPS refused)"
  rm -f ctest/zuh_engtest_nw
  make -C ctest engine-nw NW_FLAGS=-DZUH_NW_ASSUME_NO_PROXY_API=1

  step "Install the package"
  R CMD INSTALL .
  step "Fork guard (R-12)"
  NOT_CRAN=true ZU_TEST_NETWORK=1 Rscript tools/ci-fork-guard.R
  step "h11, for the HTTP/1.1 parser comparison"
  python3 -m venv "$RUNNER_TEMP/h11venv"
  "$RUNNER_TEMP/h11venv/bin/pip" install --quiet h11==0.16.0
  step "63.2 slice from R, with the network suite"
  PATH="$RUNNER_TEMP/h11venv/bin:$PATH" ZU_TEST_NETWORK=1 NOT_CRAN=true \
    Rscript tools/ci-run-tests.R

  if $full; then
    step "Fuzz corpus replay, and under ASan + UBSan (full profile)"
    make -C fuzz replay-run
    make -C fuzz replay-asan
  fi
}

windows() {
  cc=$(R CMD config CC)
  step "C core: warnings as errors, with R's toolchain (c-core)"
  echo "using the R toolchain: $cc"; $cc --version | head -2
  ZU_TEST_TRACE=1 make -C ctest strict CC="$cc"

  step "S1: Rtools' Schannel headers"
  # Toolchain identity
  (cd spike/windows-schannel && {
    echo "R CC     : $(R CMD config CC)"
    echo "R CFLAGS : $(R CMD config CFLAGS)"
    $(R CMD config CC) --version | head -2
  })
  # Probe A — macro-level report (always compiles)
  (cd spike/windows-schannel && {
    CC=$(R CMD config CC)
    $CC -O1 -o probe.exe probe.c -lsecur32 -lcrypt32 -lws2_32
    ./probe.exe
  })
  # Probe B — does SCH_CREDENTIALS exist at the default target?
  (cd spike/windows-schannel && {
    CC=$(R CMD config CC)
    if $CC -fsyntax-only probe_struct.c 2> struct_err.txt; then
      echo "SCH_CREDENTIALS: PRESENT at the toolchain's default _WIN32_WINNT."
    else
      echo "SCH_CREDENTIALS: MISSING at the toolchain's default _WIN32_WINNT."
      echo "--- compiler output (first 5 lines) ---"
      head -5 struct_err.txt
    fi
  })
  # Probe C — retry with _WIN32_WINNT=0x0A00  (gate for R-3)
  (cd spike/windows-schannel && {
    CC=$(R CMD config CC)
    echo "Retrying with -D_WIN32_WINNT=0x0A00 -DNTDDI_VERSION=0x0A000000"
    if $CC -fsyntax-only -D_WIN32_WINNT=0x0A00 -DNTDDI_VERSION=0x0A000000 \
           probe_struct.c 2> struct_err_win10.txt; then
      echo
      echo "SCH_CREDENTIALS: PRESENT once the target is raised to Windows 10."
      echo "::notice::S1 verdict: Rtools DOES ship the TLS 1.3 Schannel declarations; they are gated behind _WIN32_WINNT>=0x0A00. Fix is a compile flag, not local struct declarations. R-3 downgraded."
      $CC -O1 -D_WIN32_WINNT=0x0A00 -DNTDDI_VERSION=0x0A000000 \
          -o probe_win10.exe probe.c -lsecur32 -lcrypt32 -lws2_32
      echo
      echo "--- full report at _WIN32_WINNT=0x0A00 ---"
      ./probe_win10.exe
    else
      echo
      echo "SCH_CREDENTIALS: STILL MISSING even at _WIN32_WINNT=0x0A00."
      echo "--- compiler output ---"
      cat struct_err_win10.txt
      echo "::warning::S1 verdict: Rtools genuinely lacks SCH_CREDENTIALS. zuhttp must declare it locally (design 47.4) or ship Windows TLS 1.2-only. R-3 confirmed."
    fi
  })

  step "S8: the Schannel backend compiled on its own"
  $cc -std=c99 -Wall -Wextra -c -Isrc -Isrc/vendor/picohttpparser \
      -o /tmp/sch.o src/zuh_tls_schannel.c
  step "S8: the slice in C on Schannel"
  ZU_TEST_TRACE=1 make -C ctest engine-sch CC="$cc"
  step "S8: scripted TLS servers on Schannel (#286)"
  make -C ctest tls-eof-sch CC="$cc"
  step "S8: the slice in C with R's compiler flags"
  make -C ctest clean
  ZU_TEST_TRACE=1 make -C ctest engine-sch CC="$cc" \
    BASE="-std=gnu2x -O2 -Wall -mfpmath=sse -msse2 -mstackrealign -I../src -I../src/vendor/picohttpparser -I../src/vendor/uriparser -I."
  step "S8: install, load, backend identity, the slice from R"
  R CMD INSTALL .
  Rscript --vanilla -e 'library(zuhttp); cat("loaded\n")'
  Rscript --vanilla -e 'library(zuhttp); cat("backend:", zu_tls_backend(), "\n"); stopifnot(identical(zu_tls_backend(), "schannel"))'
  Rscript --vanilla tools/ci/schannel-slice.R

  if $full; then
    step "Fuzz corpus replay (full profile)"
    make -C fuzz replay-run CC="$cc"
  fi
}

case "$os" in
  macos) macos ;;
  windows) windows ;;
  *) echo "::error::platform.sh has no checks for '$os'"; exit 1 ;;
esac

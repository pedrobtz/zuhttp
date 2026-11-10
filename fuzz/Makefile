# Fuzz targets for the zuhttp core (design §43, roadmap S18).
#
# Two ways to build the SAME harnesses:
#
#   make fuzz     libFuzzer + ASan + UBSan. Needs clang. This is the one that
#                 finds bugs.
#   make replay   a plain driver that feeds corpus files in. Needs no special
#                 toolchain, so it runs on every CI platform including Rtools,
#                 and turns the corpus into a cross-platform regression suite.
#
# `fuzz/` is in .Rbuildignore: none of this reaches CRAN (§48).

SRC     := ../src
VENDOR  := $(SRC)/vendor/picohttpparser
URIDIR  := $(SRC)/vendor/uriparser
CORPUS  := corpus

NGDIR   := $(SRC)/vendor/nghttp2
INC     := -I$(SRC) -I$(VENDOR) -I$(URIDIR) -I$(NGDIR) -I../ctest
URIFLAGS := -DURI_NO_UNICODE -DURI_STATIC_BUILD
# nghttp2 (design §48, §65) is compiled into the engine and h2 targets with the
# definitions src/Makevars.in gives it, minus NDEBUG, so its assert()s are
# oracles too. gnu99 rather than c99 because nghttp2_time.c needs
# clock_gettime(), which glibc hides under strict C99; ctest's `strict` build is
# where project code is held to C99.
ifeq ($(OS),Windows_NT)
NGHAVE  := -DHAVE_WINDOWS_H -DHAVE_GETTICKCOUNT64
else
NGHAVE  := -DHAVE_ARPA_INET_H -DHAVE_NETINET_IN_H -DHAVE_CLOCK_GETTIME \
           -DHAVE_DECL_CLOCK_MONOTONIC=1
endif
NGDEFS  := -DNGHTTP2_STATICLIB -DBUILDING_NGHTTP2 $(NGHAVE)
NGSRC   := $(wildcard $(NGDIR)/*.c)
BASE    := -std=gnu99 -g -O1 $(INC) $(URIFLAGS) $(NGDEFS)

CORE := $(SRC)/zuh_alloc.c $(SRC)/zuh_buffer.c $(SRC)/zuh_error.c \
        $(SRC)/zuh_time.c $(SRC)/zuh_stream.c $(SRC)/zuh_headers.c \
        $(SRC)/zuh_request.c $(SRC)/zuh_framing.c $(SRC)/zuh_response.c \
        $(SRC)/zuh_uri.c $(SRC)/zuh_redirect.c $(SRC)/zuh_inflate.c \
        $(SRC)/zuh_proxy.c $(SRC)/zuh_redact.c \
        $(SRC)/zuh_sink.c $(SRC)/zuh_body.c ../ctest/zuh_mock_stream.c $(SRC)/zuh_fork.c \
        $(VENDOR)/picohttpparser.c \
        $(URIDIR)/UriParse.c $(URIDIR)/UriParseBase.c $(URIDIR)/UriResolve.c \
        $(URIDIR)/UriRecompose.c $(URIDIR)/UriCommon.c $(URIDIR)/UriMemory.c \
        $(URIDIR)/UriIp4.c $(URIDIR)/UriIp4Base.c

TARGETS := response chunked headers uri redirect inflate proxy redact body engine h2 pull pool

# The engine target links the whole request path. zuh_net.c is compiled but
# never dialled (the harness supplies connections through the §50.1 seam), and
# ctest/tls_none.c stands in for a TLS backend.
# zuh_net.c needs Winsock on Windows (Rtools), as in ctest/Makefile.
ifeq ($(OS),Windows_NT)
NETLIBS := -lws2_32
else
NETLIBS :=
endif
ENGINE_EXTRA := $(SRC)/zuh_engine.c $(SRC)/zuh_net.c $(SRC)/zuh_pool.c \
                $(SRC)/zuh_trace.c $(SRC)/zuh_tls.c ../ctest/tls_none.c \
                $(SRC)/zuh_h2.c $(NGSRC)

# --- libFuzzer -------------------------------------------------------------
FUZZ_CC     ?= clang
FUZZ_FLAGS  := -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer \
               -fno-sanitize-recover=undefined

fuzz: $(addprefix fuzz_,$(TARGETS))

fuzz_%: fuzz_%.c $(CORE)
	$(FUZZ_CC) $(BASE) $(FUZZ_FLAGS) -o $@ $< $(CORE) -lz

fuzz_engine: fuzz_engine.c $(CORE) $(ENGINE_EXTRA)
	$(FUZZ_CC) $(BASE) $(FUZZ_FLAGS) -o $@ $< $(CORE) $(ENGINE_EXTRA) -lz $(NETLIBS)

# Target twelve (§65.8): the whole engine over prior-knowledge h2c, the
# server's bytes from the fuzzer, through the same seam as `engine`.
fuzz_h2: fuzz_h2.c $(CORE) $(ENGINE_EXTRA)
	$(FUZZ_CC) $(BASE) $(FUZZ_FLAGS) -o $@ $< $(CORE) $(ENGINE_EXTRA) -lz $(NETLIBS)

# Target thirteen (#229): the pulled body's API as a state machine.
fuzz_pull: fuzz_pull.c $(CORE) $(ENGINE_EXTRA)
	$(FUZZ_CC) $(BASE) $(FUZZ_FLAGS) -o $@ $< $(CORE) $(ENGINE_EXTRA) -lz $(NETLIBS)

# Target fourteen (#247): the connection pool against a model. The harness
# stands in for zuh_fork.c, so a fork is a change of process id it controls.
POOL_CORE := $(filter-out $(SRC)/zuh_fork.c,$(CORE))
fuzz_pool: fuzz_pool.c $(CORE) $(ENGINE_EXTRA)
	$(FUZZ_CC) $(BASE) $(FUZZ_FLAGS) -o $@ $< $(POOL_CORE) $(ENGINE_EXTRA) -lz $(NETLIBS)

# One short run of every target. `make fuzz-run SECS=3600` for a longer soak;
# S18's exit criterion is 24 h per target, which is a scheduled job, not CI.
SECS ?= 60
fuzz-run: fuzz
	@for t in $(TARGETS); do \
	  echo "=== $$t ($(SECS)s) ==="; \
	  mkdir -p $(CORPUS)/$$t; \
	  ./fuzz_$$t $(CORPUS)/$$t -max_total_time=$(SECS) -print_final_stats=1 \
	    -artifact_prefix=./crash-$$t- || exit 1; \
	done

# --- portable replay -------------------------------------------------------
CC ?= cc
REPLAY_FLAGS ?=

replay: $(addprefix replay_,$(TARGETS))

replay_%: fuzz_%.c replay_main.c $(CORE)
	$(CC) $(BASE) $(REPLAY_FLAGS) -o $@ $< replay_main.c $(CORE) -lz

replay_engine: fuzz_engine.c replay_main.c $(CORE) $(ENGINE_EXTRA)
	$(CC) $(BASE) $(REPLAY_FLAGS) -o $@ $< replay_main.c $(CORE) $(ENGINE_EXTRA) -lz $(NETLIBS)

replay_h2: fuzz_h2.c replay_main.c $(CORE) $(ENGINE_EXTRA)
	$(CC) $(BASE) $(REPLAY_FLAGS) -o $@ $< replay_main.c $(CORE) $(ENGINE_EXTRA) -lz $(NETLIBS)

replay_pull: fuzz_pull.c replay_main.c $(CORE) $(ENGINE_EXTRA)
	$(CC) $(BASE) $(REPLAY_FLAGS) -o $@ $< replay_main.c $(CORE) $(ENGINE_EXTRA) -lz $(NETLIBS)

replay_pool: fuzz_pool.c replay_main.c $(CORE) $(ENGINE_EXTRA)
	$(CC) $(BASE) $(REPLAY_FLAGS) -o $@ $< replay_main.c $(POOL_CORE) $(ENGINE_EXTRA) -lz $(NETLIBS)

# Replay every seed. Two things this must get right:
#   - an empty corpus directory must not silently pass, so the count is checked;
#   - a soak-grown corpus is tens of thousands of files, which overflows argv,
#     so paths go through xargs rather than a shell glob.
replay-run: replay
	@for t in $(TARGETS); do \
	  n=$$(find $(CORPUS)/$$t -type f 2>/dev/null | wc -l | tr -d ' '); \
	  if [ "$$n" = "0" ]; then echo "no corpus for $$t" >&2; exit 1; fi; \
	  echo "=== $$t ($$n seeds) ==="; \
	  find $(CORPUS)/$$t -type f -print0 | xargs -0 -n 500 ./replay_$$t || exit 1; \
	done

# -fno-sanitize-recover: UBSan prints and continues by default, and the
# replay driver returns 0, so a finding would not fail the job (review #190).
replay-asan: REPLAY_FLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer \
                             -fno-sanitize-recover=undefined
replay-asan: clean-bin replay-run

clean-bin:
	rm -rf $(addprefix fuzz_,$(TARGETS)) $(addprefix replay_,$(TARGETS)) *.dSYM

clean: clean-bin
	rm -f crash-* leak-* timeout-*

# --- deterministic mutants -------------------------------------------------
# mutate-corpus.py derives MUT_N mutants per target from the curated seeds,
# reproducibly (same MUT_SEED, same bytes on every platform), and the replay
# driver runs them: a cheap, clang-free soak that a reviewer can re-run and
# name a finding from. mut/ is ignored by git; a mutant that finds something
# is promoted into corpus/ through seed-corpus.py.
MUT      := mut
MUT_N    ?= 3000
MUT_SEED ?= 0

mutate:
	python3 mutate-corpus.py --n $(MUT_N) --seed $(MUT_SEED) --out $(MUT)

mutate-run: replay mutate
	@for t in $(TARGETS); do \
	  n=$$(find $(MUT)/$$t -type f 2>/dev/null | wc -l | tr -d ' '); \
	  if [ "$$n" = "0" ]; then echo "no mutants for $$t" >&2; exit 1; fi; \
	  echo "=== $$t ($$n mutants) ==="; \
	  find $(MUT)/$$t -type f -print0 | sort -z | xargs -0 -n 500 ./replay_$$t || exit 1; \
	done

mutate-asan: REPLAY_FLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer \
                             -fno-sanitize-recover=undefined
mutate-asan: clean-bin mutate-run

# Restore the curated seeds, discarding anything a local fuzz run added.
reseed:
	./seed-corpus.sh

clean-mut:
	rm -rf $(MUT)

.PHONY: fuzz fuzz-run replay replay-run replay-asan clean clean-bin reseed \
        mutate mutate-run mutate-asan clean-mut

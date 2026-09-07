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

INC     := -I$(SRC) -I$(VENDOR) -I$(URIDIR)
URIFLAGS := -DURI_NO_UNICODE -DURI_STATIC_BUILD
BASE    := -std=c99 -g -O1 $(INC) $(URIFLAGS)

CORE := $(SRC)/zu_alloc.c $(SRC)/zu_buffer.c $(SRC)/zu_error.c \
        $(SRC)/zu_time.c $(SRC)/zu_stream.c $(SRC)/zu_headers.c \
        $(SRC)/zu_request.c $(SRC)/zu_framing.c $(SRC)/zu_response.c \
        $(SRC)/zu_uri.c $(SRC)/zu_redirect.c $(SRC)/zu_inflate.c \
        $(SRC)/zu_proxy.c \
        $(VENDOR)/picohttpparser.c \
        $(URIDIR)/UriParse.c $(URIDIR)/UriParseBase.c $(URIDIR)/UriResolve.c \
        $(URIDIR)/UriRecompose.c $(URIDIR)/UriCommon.c $(URIDIR)/UriMemory.c \
        $(URIDIR)/UriIp4.c $(URIDIR)/UriIp4Base.c

TARGETS := response chunked headers uri redirect inflate proxy

# --- libFuzzer -------------------------------------------------------------
FUZZ_CC     ?= clang
FUZZ_FLAGS  := -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer \
               -fno-sanitize-recover=undefined

fuzz: $(addprefix fuzz_,$(TARGETS))

fuzz_%: fuzz_%.c $(CORE)
	$(FUZZ_CC) $(BASE) $(FUZZ_FLAGS) -o $@ $< $(CORE) -lz

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

replay-asan: REPLAY_FLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer
replay-asan: clean-bin replay-run

clean-bin:
	rm -rf $(addprefix fuzz_,$(TARGETS)) $(addprefix replay_,$(TARGETS)) *.dSYM

clean: clean-bin
	rm -f crash-* leak-* timeout-*

# Restore the curated seeds, discarding anything a local fuzz run added.
reseed:
	./seed-corpus.sh

.PHONY: fuzz fuzz-run replay replay-run replay-asan clean clean-bin reseed

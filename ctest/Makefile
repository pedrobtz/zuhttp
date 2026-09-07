# Standalone C tests for the zuhttp core.
#
# The point of this target is that it links NO R headers (design §11): the same
# objects the package builds also link into a bare binary and, later, a fuzz
# harness (§43). If this stops building, the R/C separation has been broken.
#
# Project-owned code is compiled with warnings as errors under `make strict`.
# Vendored code is compiled separately with warnings off, per §44 ("vendored
# code may use separate warning policy") — picohttpparser and the uriparser
# subset are deliberately unmodified (§48), so their warnings are not ours to
# fix. (For the record the uriparser subset emits 10 -Wsign-conversion
# warnings and nothing else under our full warning set.)

CC      ?= cc
SRC     := ../src
VENDOR  := $(SRC)/vendor/picohttpparser
URIDIR  := $(SRC)/vendor/uriparser
# Vendored objects are cached, so the directory is keyed on the build flavour.
# Without this, `make asan` left ASan-instrumented picohttpparser.o behind and
# the next plain `make zu_ctest` reused it, failing to link with an obscure
# "___asan_init not found".
BUILD   := build$(BUILD_SUFFIX)

INC     := -I$(SRC) -I$(VENDOR) -I$(URIDIR) -I.
WARN    := -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion \
           -Wstrict-prototypes -Wold-style-definition -Wvla
BASE    := -std=c99 -O1 -g $(INC)

# Winsock is not linked by default.
ifeq ($(OS),Windows_NT)
NETLIBS := -lws2_32
else
NETLIBS :=
endif

CFLAGS  += $(BASE) $(WARN)
# See src/vendor/uriparser/VENDOR: both flags are required. zu_uriparser.h sets
# them too, so our own TUs stay correct even if this line is lost.
URIFLAGS := -DURI_NO_UNICODE -DURI_STATIC_BUILD
CFLAGS  += $(URIFLAGS)
VCFLAGS := $(BASE) $(URIFLAGS) -w

OWN   := $(SRC)/zu_alloc.c $(SRC)/zu_buffer.c $(SRC)/zu_error.c \
         $(SRC)/zu_time.c $(SRC)/zu_stream.c $(SRC)/zu_mock_stream.c \
         $(SRC)/zu_headers.c $(SRC)/zu_request.c $(SRC)/zu_framing.c \
         $(SRC)/zu_response.c $(SRC)/zu_uri.c $(SRC)/zu_redirect.c \
         $(SRC)/zu_inflate.c $(SRC)/zu_net.c \
         $(SRC)/zu_fork.c $(SRC)/zu_pool.c $(SRC)/zu_proxy.c $(SRC)/zu_redact.c
TESTS := test_main.c test_alloc.c test_buffer.c test_error.c test_time.c \
         test_stream.c test_headers.c test_request.c test_framing.c \
         test_response.c test_redirect.c test_uri.c \
         test_inflate.c test_net.c test_pool.c test_redact.c \
         test_proxy.c
URISRC := UriParse.c UriParseBase.c UriResolve.c UriRecompose.c \
          UriCommon.c UriMemory.c UriIp4.c UriIp4Base.c
VOBJ  := $(BUILD)/picohttpparser.o $(patsubst %.c,$(BUILD)/%.o,$(URISRC))

all: run

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/picohttpparser.o: $(VENDOR)/picohttpparser.c | $(BUILD)
	$(CC) $(VCFLAGS) -c -o $@ $<

$(BUILD)/%.o: $(URIDIR)/%.c | $(BUILD)
	$(CC) $(VCFLAGS) -c -o $@ $<

zu_ctest: $(OWN) $(TESTS) $(VOBJ)
	$(CC) $(CFLAGS) -o $@ $(OWN) $(TESTS) $(VOBJ) -lz $(NETLIBS)

run: zu_ctest
	./zu_ctest

strict: CFLAGS += -Werror
strict: clean zu_ctest
	./zu_ctest

asan: BUILD_SUFFIX := -asan
asan: CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer
asan: VCFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer
asan: zu_ctest_asan
	./zu_ctest_asan

zu_ctest_asan: $(OWN) $(TESTS) $(VOBJ)
	$(CC) $(CFLAGS) -o $@ $(OWN) $(TESTS) $(VOBJ) -lz $(NETLIBS)

# --- S7 TLS engine tests -------------------------------------------------
# A SEPARATE binary: these need a real TLS peer and therefore the network,
# while zu_ctest must stay deterministic and offline. Run by tls-spike.yaml.
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS   := $(shell pkg-config --libs   openssl 2>/dev/null)
ifeq ($(strip $(OPENSSL_LIBS)),)
OPENSSL_PREFIX ?= /opt/homebrew/opt/openssl@3
OPENSSL_CFLAGS := -I$(OPENSSL_PREFIX)/include
OPENSSL_LIBS   := -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto
endif

TLSSRC := $(SRC)/zu_alloc.c $(SRC)/zu_buffer.c $(SRC)/zu_error.c \
          $(SRC)/zu_time.c $(SRC)/zu_stream.c $(SRC)/zu_net.c \
          $(SRC)/zu_tls_openssl.c

zu_tlstest: $(TLSSRC) test_tls.c
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -o $@ $(TLSSRC) test_tls.c \
	      $(OPENSSL_LIBS) $(NETLIBS)

tls: zu_tlstest
	./zu_tlstest

clean:
	rm -rf zu_ctest zu_ctest_asan zu_tlstest *.dSYM build build-asan *.o

.PHONY: all run strict asan clean tls

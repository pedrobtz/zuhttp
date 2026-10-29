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
# the next plain `make zuh_ctest` reused it, failing to link with an obscure
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
# See src/vendor/uriparser/VENDOR: both flags are required. zuh_uriparser.h sets
# them too, so our own TUs stay correct even if this line is lost.
URIFLAGS := -DURI_NO_UNICODE -DURI_STATIC_BUILD
CFLAGS  += $(URIFLAGS)
VCFLAGS := $(BASE) $(URIFLAGS) -w

OWN   := $(SRC)/zuh_alloc.c $(SRC)/zuh_buffer.c $(SRC)/zuh_error.c \
         $(SRC)/zuh_time.c $(SRC)/zuh_stream.c $(SRC)/zuh_mock_stream.c \
         $(SRC)/zuh_headers.c $(SRC)/zuh_request.c $(SRC)/zuh_framing.c \
         $(SRC)/zuh_response.c $(SRC)/zuh_uri.c $(SRC)/zuh_redirect.c \
         $(SRC)/zuh_inflate.c $(SRC)/zuh_net.c \
         $(SRC)/zuh_fork.c $(SRC)/zuh_pool.c $(SRC)/zuh_proxy.c $(SRC)/zuh_redact.c \
         $(SRC)/zuh_sink.c $(SRC)/zuh_body.c $(SRC)/zuh_tls.c $(SRC)/zuh_trace.c \
         $(SRC)/zuh_engine.c tls_none.c
TESTS := test_main.c test_alloc.c test_buffer.c test_error.c test_time.c \
         test_stream.c test_headers.c test_request.c test_framing.c \
         test_response.c test_redirect.c test_uri.c \
         test_inflate.c test_net.c test_pool.c test_redact.c \
         test_proxy.c test_body.c test_trace.c test_engine_mock.c
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

zuh_ctest: $(OWN) $(TESTS) $(VOBJ)
	$(CC) $(CFLAGS) -o $@ $(OWN) $(TESTS) $(VOBJ) -lz $(NETLIBS)

run: zuh_ctest
	./zuh_ctest

strict: CFLAGS += -Werror
strict: clean zuh_ctest
	./zuh_ctest

asan: BUILD_SUFFIX := -asan
asan: CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer
asan: VCFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer
asan: zuh_ctest_asan
	./zuh_ctest_asan

zuh_ctest_asan: $(OWN) $(TESTS) $(VOBJ)
	$(CC) $(CFLAGS) -o $@ $(OWN) $(TESTS) $(VOBJ) -lz $(NETLIBS)

# --- S7 TLS engine tests -------------------------------------------------
# A SEPARATE binary: these need a real TLS peer and therefore the network,
# while zuh_ctest must stay deterministic and offline. Run by network.yaml.
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS   := $(shell pkg-config --libs   openssl 2>/dev/null)
ifeq ($(strip $(OPENSSL_LIBS)),)
OPENSSL_PREFIX ?= /opt/homebrew/opt/openssl@3
OPENSSL_CFLAGS := -I$(OPENSSL_PREFIX)/include
OPENSSL_LIBS   := -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto
endif

# zuh_net.c emits §35.3 trace events, so it needs zuh_trace.c, which redacts
# URLs and so needs zuh_redact.c (D-51). Neither is here because this binary
# tests TLS; they are here because the link demands them.
TLSSRC := $(SRC)/zuh_alloc.c $(SRC)/zuh_buffer.c $(SRC)/zuh_error.c \
          $(SRC)/zuh_time.c $(SRC)/zuh_stream.c $(SRC)/zuh_net.c \
          $(SRC)/zuh_tls.c $(SRC)/zuh_tls_openssl.c \
          $(SRC)/zuh_trace.c $(SRC)/zuh_redact.c $(SRC)/zuh_headers.c

zuh_tlstest: $(TLSSRC) test_tls.c
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -o $@ $(TLSSRC) test_tls.c \
	      $(OPENSSL_LIBS) $(NETLIBS)

tls: zuh_tlstest
	./zuh_tlstest

# --- 63.2 vertical slice ------------------------------------------------
# Also network-dependent, and also a separate binary for the same reason.
ENGSRC := $(SRC)/zuh_alloc.c $(SRC)/zuh_buffer.c $(SRC)/zuh_error.c \
          $(SRC)/zuh_time.c $(SRC)/zuh_stream.c $(SRC)/zuh_net.c \
          $(SRC)/zuh_headers.c $(SRC)/zuh_request.c $(SRC)/zuh_framing.c \
          $(SRC)/zuh_response.c $(SRC)/zuh_uri.c $(SRC)/zuh_redirect.c \
          $(SRC)/zuh_inflate.c $(SRC)/zuh_tls.c $(SRC)/zuh_tls_openssl.c \
          $(SRC)/zuh_engine.c $(SRC)/zuh_fork.c $(SRC)/zuh_pool.c \
          $(SRC)/zuh_sink.c $(SRC)/zuh_body.c $(SRC)/zuh_proxy.c $(SRC)/zuh_trace.c \
          $(SRC)/zuh_redact.c \
          $(VENDOR)/picohttpparser.c \
          $(URIDIR)/UriParse.c $(URIDIR)/UriParseBase.c $(URIDIR)/UriResolve.c \
          $(URIDIR)/UriRecompose.c $(URIDIR)/UriCommon.c $(URIDIR)/UriMemory.c \
          $(URIDIR)/UriIp4.c $(URIDIR)/UriIp4Base.c

zuh_engtest: $(ENGSRC) test_engine.c
	$(CC) $(BASE) $(URIFLAGS) $(OPENSSL_CFLAGS) -o $@ $(ENGSRC) test_engine.c \
	      $(OPENSSL_LIBS) -lz $(NETLIBS)

engine: zuh_engtest
	./zuh_engtest

# The same slice on the macOS system TLS stack (§13.2, D-63): Network.framework
# for the protocol, SecTrust for trust, nothing bundled. The backend dials
# HTTPS itself (D-71), so this also runs the engine's dialled path.
# NW_FLAGS=-DZUH_NW_ASSUME_NO_PROXY_API=1 builds the macOS < 14 proxy refusal.
NWSRC := $(subst $(SRC)/zuh_tls_openssl.c,$(SRC)/zuh_tls_nw.c,$(ENGSRC))

zuh_engtest_nw: $(NWSRC) test_engine.c
	$(CC) $(BASE) $(URIFLAGS) $(NW_FLAGS) -o $@ $(NWSRC) test_engine.c \
	      -framework Network -framework Security -framework CoreFoundation -lz $(NETLIBS)

engine-nw: zuh_engtest_nw
	./zuh_engtest_nw

# The same slice on the Windows system stack (§13.4, D-5). Exists so a crash
# in the Schannel backend reports a C location instead of taking an R process
# down with it — there is no Windows machine in the loop, so CI is the only
# debugger and it needs to say something useful.
SCHSRC := $(subst $(SRC)/zuh_tls_openssl.c,$(SRC)/zuh_tls_schannel.c,$(ENGSRC))

zuh_engtest_sch: $(SCHSRC) test_engine.c
	$(CC) $(BASE) $(URIFLAGS) -o $@ $(SCHSRC) test_engine.c \
	      -lsecur32 -lcrypt32 -lz $(NETLIBS)

engine-sch: zuh_engtest_sch
	./zuh_engtest_sch

clean:
	rm -rf zuh_ctest zuh_ctest_asan zuh_tlstest zuh_engtest zuh_engtest_nw zuh_engtest_sch *.dSYM build build-asan *.o

.PHONY: all run strict asan clean tls engine engine-nw engine-sch

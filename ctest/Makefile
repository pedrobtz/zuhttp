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
# Vendored objects are cached, so each build flavour has its own directory:
# build/ for plain, build-asan/ for `asan`. Shared, `make asan` reused plain
# vendored objects and ran picohttpparser, uriparser and nghttp2 unsanitised
# with nothing failing; the other order failed to link ("___asan_init not
# found"). The directory used to be keyed on a target-specific BUILD_SUFFIX,
# which comes too late to change a `:=` variable, so it never was (#262).
# ctest/check-flavours.sh holds both orders.
BUILD   := build
ABUILD  := build-asan
ASANFLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer

NGDIR   := $(SRC)/vendor/nghttp2
INC     := -I$(SRC) -I$(VENDOR) -I$(URIDIR) -I$(NGDIR) -I.
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
CFLAGS  += $(URIFLAGS) -DNGHTTP2_STATICLIB
VCFLAGS := $(BASE) $(URIFLAGS) -w

# nghttp2 (design §48, §65): the definitions src/Makevars.in gives it, minus
# NDEBUG, so its assert()s run in the tests and under the sanitizers. gnu99,
# not c99: nghttp2_time.c needs clock_gettime(), which glibc hides under
# strict C99. Compiled warning-free like the other vendored code.
ifeq ($(OS),Windows_NT)
NGHAVE  := -DHAVE_WINDOWS_H -DHAVE_GETTICKCOUNT64
else
NGHAVE  := -DHAVE_ARPA_INET_H -DHAVE_NETINET_IN_H -DHAVE_CLOCK_GETTIME \
           -DHAVE_DECL_CLOCK_MONOTONIC=1
endif
NGDEFS  := -DNGHTTP2_STATICLIB -DBUILDING_NGHTTP2 $(NGHAVE)
NGSRC   := $(wildcard $(NGDIR)/*.c)
NGFLAGS := $(subst -std=c99,-std=gnu99,$(BASE)) $(NGDEFS) -w
# The network binaries below compile every source in one command, so they
# take nghttp2 that way, under the same gnu99 flags.
ENGBASE := $(subst -std=c99,-std=gnu99,$(BASE)) $(NGDEFS)

OWN   := $(SRC)/zuh_alloc.c $(SRC)/zuh_buffer.c $(SRC)/zuh_error.c \
         $(SRC)/zuh_time.c $(SRC)/zuh_stream.c zuh_mock_stream.c \
         $(SRC)/zuh_headers.c $(SRC)/zuh_request.c $(SRC)/zuh_framing.c \
         $(SRC)/zuh_response.c $(SRC)/zuh_uri.c $(SRC)/zuh_redirect.c \
         $(SRC)/zuh_inflate.c $(SRC)/zuh_net.c \
         $(SRC)/zuh_fork.c $(SRC)/zuh_pool.c $(SRC)/zuh_proxy.c $(SRC)/zuh_redact.c \
         $(SRC)/zuh_sink.c $(SRC)/zuh_body.c $(SRC)/zuh_tls.c $(SRC)/zuh_trace.c \
         $(SRC)/zuh_engine.c $(SRC)/zuh_h2.c tls_none.c
TESTS := test_main.c test_alloc.c test_buffer.c test_error.c test_time.c \
         test_stream.c test_headers.c test_request.c test_framing.c \
         test_response.c test_redirect.c test_uri.c \
         test_inflate.c test_net.c test_pool.c test_redact.c \
         test_proxy.c test_body.c test_trace.c test_engine_mock.c test_h2.c
URISRC := UriParse.c UriParseBase.c UriResolve.c UriRecompose.c \
          UriCommon.c UriMemory.c UriIp4.c UriIp4Base.c
VOBJ  := $(BUILD)/picohttpparser.o $(patsubst %.c,$(BUILD)/%.o,$(URISRC)) \
         $(patsubst $(NGDIR)/%.c,$(BUILD)/ng_%.o,$(NGSRC))

all: run

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/picohttpparser.o: $(VENDOR)/picohttpparser.c | $(BUILD)
	$(CC) $(VCFLAGS) -c -o $@ $<

$(BUILD)/%.o: $(URIDIR)/%.c | $(BUILD)
	$(CC) $(VCFLAGS) -c -o $@ $<

$(BUILD)/ng_%.o: $(NGDIR)/%.c | $(BUILD)
	$(CC) $(NGFLAGS) -c -o $@ $<

# The same objects, instrumented, for zuh_ctest_asan. The flags are in the
# rules rather than target-specific, so building zuh_ctest_asan directly
# instruments them too.
AVOBJ := $(patsubst $(BUILD)/%,$(ABUILD)/%,$(VOBJ))

$(ABUILD):
	mkdir -p $(ABUILD)

$(ABUILD)/picohttpparser.o: $(VENDOR)/picohttpparser.c | $(ABUILD)
	$(CC) $(VCFLAGS) $(ASANFLAGS) -c -o $@ $<

$(ABUILD)/%.o: $(URIDIR)/%.c | $(ABUILD)
	$(CC) $(VCFLAGS) $(ASANFLAGS) -c -o $@ $<

$(ABUILD)/ng_%.o: $(NGDIR)/%.c | $(ABUILD)
	$(CC) $(NGFLAGS) $(ASANFLAGS) -c -o $@ $<

# One object per source, each from a compile command of its own, with header
# dependencies (-MMD). Mutation testing needs this: Mull re-parses every file
# from its recorded command line, and one command compiling 46 files cannot
# be re-parsed (#238). The objects sit in $(OBJDIR), apart from the vendored
# ones, so a change of CC (Mull's plugin) is a `make clean` away.
OBJDIR  := $(BUILD)/own
OWNOBJ  := $(patsubst %.c,$(OBJDIR)/%.o,$(notdir $(OWN)))
TESTOBJ := $(patsubst %.c,$(OBJDIR)/%.o,$(TESTS))

# The compiler and flags that built the objects. The stamp is rewritten, and
# so every object rebuilt, whenever they change: ctest-lcov.sh and Mull pass
# their own CC, and reusing objects from a plain build would give them an
# uninstrumented binary that reports nothing, silently. Compared when the
# Makefile is read, so it sees CC and CFLAGS from the command line but not
# target-specific additions; `strict` and `asan` do not reuse these objects
# (strict cleans first, asan compiles its sources in one command).
FLAGSTAMP := $(OBJDIR)/.flags
FLAGSNOW  := $(CC) $(CFLAGS)
ifneq ($(FLAGSNOW),$(shell cat $(FLAGSTAMP) 2>/dev/null))
$(shell mkdir -p $(OBJDIR) && printf '%s\n' '$(FLAGSNOW)' > $(FLAGSTAMP))
endif
# Recreated when missing, as after the `clean` that `strict` runs.
$(FLAGSTAMP): | $(OBJDIR)
	printf '%s\n' '$(FLAGSNOW)' > $@

$(OBJDIR):
	mkdir -p $@

$(OBJDIR)/%.o: $(SRC)/%.c $(FLAGSTAMP) | $(OBJDIR)
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

$(OBJDIR)/%.o: %.c $(FLAGSTAMP) | $(OBJDIR)
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<


-include $(wildcard $(OBJDIR)/*.d)

zuh_ctest: $(OWNOBJ) $(TESTOBJ) $(VOBJ)
	$(CC) $(CFLAGS) -o $@ $(OWNOBJ) $(TESTOBJ) $(VOBJ) -lz $(NETLIBS)

run: zuh_ctest
	./zuh_ctest

strict: CFLAGS += -Werror
strict: clean zuh_ctest
	./zuh_ctest

asan: zuh_ctest_asan
	./zuh_ctest_asan

zuh_ctest_asan: $(OWN) $(TESTS) $(AVOBJ)
	$(CC) $(CFLAGS) $(ASANFLAGS) -o $@ $(OWN) $(TESTS) $(AVOBJ) -lz $(NETLIBS)

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

# ASan + UBSan for the live binaries (#231). A live backend is code the
# offline suite cannot reach, and #215 survived because none of them ran
# instrumented. -fno-sanitize-recover makes a UBSan report fail the run.
SANFLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined
SANENV   := ASAN_OPTIONS=detect_stack_use_after_return=1:detect_leaks=0:abort_on_error=1 \
            UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1

zuh_tlstest: $(TLSSRC) test_tls.c
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -o $@ $(TLSSRC) test_tls.c \
	      $(OPENSSL_LIBS) $(NETLIBS)

tls: zuh_tlstest
	./zuh_tlstest

zuh_tlstest_asan: $(TLSSRC) test_tls.c
	$(CC) $(CFLAGS) $(SANFLAGS) $(OPENSSL_CFLAGS) -o $@ $(TLSSRC) test_tls.c \
	      $(OPENSSL_LIBS) $(NETLIBS)

tls-asan: zuh_tlstest_asan
	$(SANENV) ./zuh_tlstest_asan

# --- 63.2 vertical slice ------------------------------------------------
# Also network-dependent, and also a separate binary for the same reason.
ENGSRC := $(SRC)/zuh_alloc.c $(SRC)/zuh_buffer.c $(SRC)/zuh_error.c \
          $(SRC)/zuh_time.c $(SRC)/zuh_stream.c $(SRC)/zuh_net.c \
          $(SRC)/zuh_headers.c $(SRC)/zuh_request.c $(SRC)/zuh_framing.c \
          $(SRC)/zuh_response.c $(SRC)/zuh_uri.c $(SRC)/zuh_redirect.c \
          $(SRC)/zuh_inflate.c $(SRC)/zuh_tls.c $(SRC)/zuh_tls_openssl.c \
          $(SRC)/zuh_engine.c $(SRC)/zuh_fork.c $(SRC)/zuh_pool.c \
          $(SRC)/zuh_sink.c $(SRC)/zuh_body.c $(SRC)/zuh_proxy.c $(SRC)/zuh_trace.c \
          $(SRC)/zuh_redact.c $(SRC)/zuh_h2.c \
          $(VENDOR)/picohttpparser.c $(NGSRC) \
          $(URIDIR)/UriParse.c $(URIDIR)/UriParseBase.c $(URIDIR)/UriResolve.c \
          $(URIDIR)/UriRecompose.c $(URIDIR)/UriCommon.c $(URIDIR)/UriMemory.c \
          $(URIDIR)/UriIp4.c $(URIDIR)/UriIp4Base.c

zuh_engtest: $(ENGSRC) test_engine.c
	$(CC) $(ENGBASE) $(URIFLAGS) $(OPENSSL_CFLAGS) -o $@ $(ENGSRC) test_engine.c \
	      $(OPENSSL_LIBS) -lz $(NETLIBS)

engine: zuh_engtest
	./zuh_engtest

zuh_engtest_asan: $(ENGSRC) test_engine.c
	$(CC) $(ENGBASE) $(SANFLAGS) $(URIFLAGS) $(OPENSSL_CFLAGS) -o $@ $(ENGSRC) test_engine.c \
	      $(OPENSSL_LIBS) -lz $(NETLIBS)

engine-asan: zuh_engtest_asan
	$(SANENV) ./zuh_engtest_asan

# The same slice on the macOS system TLS stack (§13.2, D-63): Network.framework
# for the protocol, SecTrust for trust, nothing bundled. The backend dials
# HTTPS itself (D-71), so this also runs the engine's dialled path.
# NW_FLAGS=-DZUH_NW_ASSUME_NO_PROXY_API=1 builds the macOS < 14 proxy refusal.
NWSRC := $(subst $(SRC)/zuh_tls_openssl.c,$(SRC)/zuh_tls_nw.c,$(ENGSRC))

zuh_engtest_nw: $(NWSRC) test_engine.c
	$(CC) $(ENGBASE) $(URIFLAGS) $(NW_FLAGS) -o $@ $(NWSRC) test_engine.c \
	      -framework Network -framework Security -framework CoreFoundation -lz $(NETLIBS)

engine-nw: zuh_engtest_nw
	./zuh_engtest_nw

zuh_engtest_nw_asan: $(NWSRC) test_engine.c
	$(CC) $(ENGBASE) $(SANFLAGS) $(URIFLAGS) $(NW_FLAGS) -o $@ $(NWSRC) test_engine.c \
	      -framework Network -framework Security -framework CoreFoundation -lz $(NETLIBS)

engine-nw-asan: zuh_engtest_nw_asan
	$(SANENV) ./zuh_engtest_nw_asan

# The same slice on the Windows system stack (§13.4, D-5). Exists so a crash
# in the Schannel backend reports a C location instead of taking an R process
# down with it — there is no Windows machine in the loop, so CI is the only
# debugger and it needs to say something useful.
SCHSRC := $(subst $(SRC)/zuh_tls_openssl.c,$(SRC)/zuh_tls_schannel.c,$(ENGSRC))

zuh_engtest_sch: $(SCHSRC) test_engine.c
	$(CC) $(ENGBASE) $(URIFLAGS) -o $@ $(SCHSRC) test_engine.c \
	      -lsecur32 -lcrypt32 -lz $(NETLIBS)

engine-sch: zuh_engtest_sch
	./zuh_engtest_sch

# #286: tls_eof's scripted servers over Schannel, on the Windows CI leg. The
# script puts the fixture CA in the machine's Root store for the run.
zuh_tlseof_sch: $(SCHSRC) tls_eof/drive.c
	$(CC) $(ENGBASE) $(URIFLAGS) -o $@ $(SCHSRC) tls_eof/drive.c \
	      -lsecur32 -lcrypt32 -lz $(NETLIBS)

tls-eof-sch: zuh_tlseof_sch
	DRIVE=$(CURDIR)/zuh_tlseof_sch tls_eof/run-sch.sh

# D-86: the engine over OpenSSL against a loopback TLS server that closes
# without close_notify, and one that sends close_notify behind the body. Needs
# python3 and the openssl CLI; no network.
zuh_tlseof: $(ENGSRC) tls_eof/drive.c
	$(CC) $(ENGBASE) $(URIFLAGS) $(OPENSSL_CFLAGS) -o $@ $(ENGSRC) tls_eof/drive.c \
	      $(OPENSSL_LIBS) -lz $(NETLIBS)

tls-eof: zuh_tlseof
	tls_eof/run.sh

# The same, under ASan + UBSan: #215 was a stack-use-after-return in the
# verify callback on renegotiation, which reads garbage silently without it.
zuh_tlseof_asan: $(ENGSRC) tls_eof/drive.c
	$(CC) $(ENGBASE) $(SANFLAGS) $(URIFLAGS) $(OPENSSL_CFLAGS) -o $@ $(ENGSRC) tls_eof/drive.c \
	      $(OPENSSL_LIBS) -lz $(NETLIBS)

tls-eof-asan: zuh_tlseof_asan
	$(SANENV) DRIVE=$(CURDIR)/zuh_tlseof_asan tls_eof/run.sh

# #249: the fork case of tls_eof (tls_eof/fork.sh) on Network.framework, so
# the drop of an inherited connection is tested on the macOS backend too.
# Needs the openssl CLI for the certificate; tls-eof runs it on OpenSSL.
zuh_tlseof_nw: $(NWSRC) tls_eof/drive.c
	$(CC) $(ENGBASE) $(URIFLAGS) -o $@ $(NWSRC) tls_eof/drive.c \
	      -framework Network -framework Security -framework CoreFoundation -lz $(NETLIBS)

tls-fork-nw: zuh_tlseof_nw
	DRIVE=$(CURDIR)/zuh_tlseof_nw tls_eof/fork.sh

# #311: the receive buffer stays bounded under a slow reader. nwrx.c
# includes the backend source to read its buffer, so it is not linked twice.
zuh_nwrx: $(NWSRC) tls_eof/nwrx.c
	$(CC) $(ENGBASE) $(URIFLAGS) -o $@ $(filter-out $(SRC)/zuh_tls_nw.c,$(NWSRC)) tls_eof/nwrx.c \
	      -framework Network -framework Security -framework CoreFoundation -lz $(NETLIBS)

tls-rx-nw: zuh_nwrx
	NWRX=$(CURDIR)/zuh_nwrx tls_eof/nwrx.sh

zuh_tlseof_nw_asan: $(NWSRC) tls_eof/drive.c
	$(CC) $(ENGBASE) $(SANFLAGS) $(URIFLAGS) -o $@ $(NWSRC) tls_eof/drive.c \
	      -framework Network -framework Security -framework CoreFoundation -lz $(NETLIBS)

tls-fork-nw-asan: zuh_tlseof_nw_asan
	$(SANENV) DRIVE=$(CURDIR)/zuh_tlseof_nw_asan tls_eof/fork.sh

clean:
	rm -rf zuh_ctest zuh_ctest_asan zuh_tlstest zuh_engtest zuh_engtest_nw zuh_engtest_sch zuh_tlseof zuh_tlseof_asan zuh_tlseof_nw zuh_tlseof_nw_asan zuh_nwrx \
	      zuh_tlstest_asan zuh_engtest_asan zuh_engtest_nw_asan *.dSYM build build-asan *.o

.PHONY: all run strict asan clean tls tls-asan tls-eof tls-eof-asan tls-fork-nw tls-fork-nw-asan tls-rx-nw engine engine-asan engine-nw-asan engine-nw engine-sch tls-eof-sch

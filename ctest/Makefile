# Standalone C tests for the zuhttp core.
#
# The point of this target is that it links NO R headers (design §11): the same
# objects the package builds also link into a bare binary and, later, a fuzz
# harness (§43). If this stops building, the R/C separation has been broken.
#
# Project-owned code is compiled with warnings as errors under `make strict`.
# Vendored code is compiled separately with warnings off, per §44 ("vendored
# code may use separate warning policy") — picohttpparser is deliberately
# unmodified (§48), so its warnings are not ours to fix.

CC      ?= cc
SRC     := ../src
VENDOR  := $(SRC)/vendor/picohttpparser
BUILD   := build

INC     := -I$(SRC) -I$(VENDOR) -I.
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
VCFLAGS := $(BASE) -w

OWN   := $(SRC)/zu_alloc.c $(SRC)/zu_buffer.c $(SRC)/zu_error.c \
         $(SRC)/zu_time.c $(SRC)/zu_stream.c $(SRC)/zu_mock_stream.c \
         $(SRC)/zu_headers.c $(SRC)/zu_request.c $(SRC)/zu_framing.c \
         $(SRC)/zu_response.c $(SRC)/zu_uri.c $(SRC)/zu_redirect.c \
         $(SRC)/zu_inflate.c $(SRC)/zu_net.c
TESTS := test_main.c test_alloc.c test_buffer.c test_error.c test_time.c \
         test_stream.c test_headers.c test_request.c test_framing.c \
         test_response.c test_redirect.c \
         test_inflate.c test_net.c
VOBJ  := $(BUILD)/picohttpparser.o

all: run

$(BUILD):
	mkdir -p $(BUILD)

$(VOBJ): $(VENDOR)/picohttpparser.c | $(BUILD)
	$(CC) $(VCFLAGS) -c -o $@ $<

zu_ctest: $(OWN) $(TESTS) $(VOBJ)
	$(CC) $(CFLAGS) -o $@ $(OWN) $(TESTS) $(VOBJ) -lz $(NETLIBS)

run: zu_ctest
	./zu_ctest

strict: CFLAGS += -Werror
strict: clean zu_ctest
	./zu_ctest

asan: CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer
asan: VCFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer
asan: clean zu_ctest
	./zu_ctest

clean:
	rm -rf zu_ctest zu_ctest.dSYM $(BUILD) *.o

.PHONY: all run strict asan clean

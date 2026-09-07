# Standalone C tests for the zuhttp core.
#
# The point of this target is that it links NO R headers (design §11): the same
# objects the package builds also link into a bare binary and, later, a fuzz
# harness (§43). If this stops building, the R/C separation has been broken.

CC      ?= cc
SRC     := ../src
CFLAGS  += -std=c99 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion \
           -Wstrict-prototypes -Wold-style-definition -Wvla -O1 -g -I$(SRC) -I.
CORE    := $(SRC)/zu_alloc.c $(SRC)/zu_buffer.c $(SRC)/zu_error.c \
           $(SRC)/zu_time.c $(SRC)/zu_stream.c $(SRC)/zu_mock_stream.c \
           $(SRC)/zu_headers.c $(SRC)/zu_request.c $(SRC)/zu_framing.c
TESTS   := test_main.c test_alloc.c test_buffer.c test_error.c test_time.c \
           test_stream.c test_headers.c test_request.c test_framing.c

all: run

zu_ctest: $(CORE) $(TESTS)
	$(CC) $(CFLAGS) -o $@ $(CORE) $(TESTS)

run: zu_ctest
	./zu_ctest

# Warnings are errors here; vendored code is exempt but this is all ours (§44).
strict: CFLAGS += -Werror
strict: clean zu_ctest
	./zu_ctest

asan: CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer
asan: clean zu_ctest
	./zu_ctest

clean:
	rm -rf zu_ctest zu_ctest.dSYM *.o

.PHONY: all run strict asan clean

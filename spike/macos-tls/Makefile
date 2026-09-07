# zuhttp Stage S0 — macOS TLS feasibility spike
#
# Requires: macOS, Xcode command line tools, OpenSSL 3.x
# OpenSSL is located via pkg-config; override with OPENSSL_PREFIX=... if needed.

OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS   := $(shell pkg-config --libs   openssl 2>/dev/null)

ifeq ($(strip $(OPENSSL_LIBS)),)
OPENSSL_PREFIX ?= /opt/homebrew/opt/openssl@3
OPENSSL_CFLAGS := -I$(OPENSSL_PREFIX)/include
OPENSSL_LIBS   := -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto
endif

CC      ?= clang
CFLAGS  += -std=c99 -Wall -Wextra -O1 -g $(OPENSSL_CFLAGS)
# Secure Transport is deprecated as of macOS 10.15. Silencing it here is
# itself a finding, not a fix — see FINDINGS.md.
CFLAGS  += -Wno-deprecated-declarations
LDFLAGS += $(OPENSSL_LIBS) -framework Security -framework CoreFoundation

all: tls_spike

tls_spike: tls_spike.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Show the deprecation warnings we normally silence.
warnings: tls_spike.c
	$(CC) -std=c99 -Wall -Wextra -O1 $(OPENSSL_CFLAGS) -fsyntax-only $< 2>&1 | \
	  grep -c 'is deprecated' | xargs -I{} echo "deprecated-API warnings: {}"

test: tls_spike
	./run.sh

clean:
	rm -rf tls_spike tls_spike.dSYM tmp

.PHONY: all test clean warnings

# F-5: does SecTrustEvaluateWithError survive fork()?  Needs a DER cert.
fork_trust_test: fork_trust_test.c
	$(CC) -std=c99 -Wall -O1 -o $@ $< -framework Security -framework CoreFoundation

forktest: fork_trust_test tmp/ca.der
	@echo "A. parent uses Security, then forks:"; -./fork_trust_test tmp/ca.der
	@echo "B. parent does not, then forks:";      -./fork_trust_test tmp/ca.der --no-parent-eval

tmp/ca.der: tmp/ca.pem
	$(OPENSSL_PREFIX)/bin/openssl x509 -in $< -outform DER -out $@ 2>/dev/null || \
	  openssl x509 -in $< -outform DER -out $@

.PHONY: forktest

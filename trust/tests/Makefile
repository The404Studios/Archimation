# Integration tests for the trust dispatcher wire-up.
#
# `make test-dispatch` builds and (attempts to) run the dispatch
# round-trip test.  The test requires:
#   - /dev/trust present (trust.ko loaded)
#   - libtrust.so.1 either installed or findable via LD_LIBRARY_PATH
#
# Most CI environments won't have /dev/trust; the test handles that
# by returning exit 77 (SKIP) so `make test-dispatch` doesn't flunk
# the build.

CC       ?= gcc
CFLAGS   ?= -Wall -Wextra -O2 -std=c11
CFLAGS   += -I$(CURDIR)/..

# Link against the in-tree libtrust build first so `make` picks up
# local changes without needing `make install`.  Fallback to the
# installed soname.
LIBTRUST_DIR := $(CURDIR)/../lib
LDFLAGS  += -L$(LIBTRUST_DIR) -Wl,-rpath,$(LIBTRUST_DIR)
LDLIBS   += -ltrust -lpthread

TESTS := test_dispatch_roundtrip

.PHONY: all clean test-dispatch

all: $(TESTS)

test_dispatch_roundtrip: test_dispatch_roundtrip.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

# Run target.  We tolerate exit 77 (SKIP) and exit 0 (PASS); anything
# else (non-zero non-77) counts as FAIL.
test-dispatch: test_dispatch_roundtrip
	@echo "== Running test_dispatch_roundtrip =="
	@LD_LIBRARY_PATH=$(LIBTRUST_DIR):$$LD_LIBRARY_PATH \
	  ./test_dispatch_roundtrip; rc=$$?; \
	  if [ "$$rc" = "77" ]; then \
	    echo "SKIP: trust.ko not loaded; see message above"; exit 0; \
	  else exit $$rc; fi

clean:
	rm -f $(TESTS)

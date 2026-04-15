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

TESTS := test_dispatch_roundtrip test_context_mask
BENCHES := bench_subject_pool

.PHONY: all clean test-dispatch test-context-mask bench-subject-pool

all: $(TESTS) $(BENCHES)

test_dispatch_roundtrip: test_dispatch_roundtrip.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

test_context_mask: test_context_mask.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

# bench-subject-pool: userland mirror of the trust.ko absent pool.
# R34 gate -- 1.5x speedup vs fresh-alloc or the concept is ripped out.
# Built with only libpthread + librt; does NOT require /dev/trust.
bench_subject_pool: bench_subject_pool.c
	$(CC) $(CFLAGS) -o $@ $< -lpthread -lrt

bench-subject-pool: bench_subject_pool
	@echo "== trust_subject_pool microbenchmark =="
	@./bench_subject_pool

# Run target.  We tolerate exit 77 (SKIP) and exit 0 (PASS); anything
# else (non-zero non-77) counts as FAIL.
test-dispatch: test_dispatch_roundtrip
	@echo "== Running test_dispatch_roundtrip =="
	@LD_LIBRARY_PATH=$(LIBTRUST_DIR):$$LD_LIBRARY_PATH \
	  ./test_dispatch_roundtrip; rc=$$?; \
	  if [ "$$rc" = "77" ]; then \
	    echo "SKIP: trust.ko not loaded; see message above"; exit 0; \
	  else exit $$rc; fi

# Session 34 R34: context-mask dispatch gate.
test-context-mask: test_context_mask
	@echo "== Running test_context_mask =="
	@LD_LIBRARY_PATH=$(LIBTRUST_DIR):$$LD_LIBRARY_PATH \
	  ./test_context_mask; rc=$$?; \
	  if [ "$$rc" = "77" ]; then \
	    echo "SKIP: trust.ko not loaded or pre-R34; see message above"; \
	    exit 0; \
	  else exit $$rc; fi

clean:
	rm -f $(TESTS) $(BENCHES)

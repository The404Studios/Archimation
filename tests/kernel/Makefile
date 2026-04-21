# tests/kernel/Makefile
#
# Userspace verification harness for the Root of Authority security
# theorem invariants exposed by trust.ko.
#
# Owner: Session 48 Agent 8.
#
# Build:   make
# Run:     sudo ./test_theorems        (root needed for /dev/trust ioctls)
# Clean:   make clean
#
# The harness intentionally has NO link-time dependency on libtrust so
# it builds even on a stripped CI image.  We open /sys nodes and
# /dev/trust directly.

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wno-unused-parameter -std=gnu11
LDFLAGS ?=

TARGETS := test_theorems

all: $(TARGETS)

test_theorems: test_theorems.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS) *.o

# Convenience target: load trust.ko (if not loaded) and run the suite.
# Requires sudo.
.PHONY: all clean check
check: test_theorems
	@if ! lsmod 2>/dev/null | grep -q '^trust '; then \
		echo "trust module not loaded; attempting modprobe..."; \
		sudo modprobe trust 2>/dev/null || \
		  { echo "WARN: could not load trust.ko; tests will SKIP"; }; \
	fi
	sudo ./test_theorems

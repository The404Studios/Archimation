# Makefile for tests/adversarial/
#
# Builds the `helpers` binary used by the Python theorem-violation
# suite to drive /dev/trust ioctls (subject create, proof capture/
# replay, entropy sample, TRC burn).
#
# Usage:
#   make -C tests/adversarial helpers        # default target
#   make -C tests/adversarial clean
#
# Requires:
#   - gcc
#   - trust/lib/libtrust.so and trust/lib/libtrust.h
#     (built by the top-level `make` or `make -C trust/lib`)
#
# If libtrust.so is absent the link step fails cleanly and the Python
# harness treats all live tests as skipped.

CC       ?= gcc
CFLAGS   ?= -Wall -Wextra -O2 -std=c11
ROOT     := $(CURDIR)/../..
TRUST_INC := $(ROOT)/trust/include
TRUST_LIB := $(ROOT)/trust/lib

.PHONY: all clean helpers

all: helpers

helpers: helpers.c
	$(CC) $(CFLAGS) -o $@ $< \
	    -I$(TRUST_INC) -I$(TRUST_LIB) \
	    -L$(TRUST_LIB) -ltrust \
	    -Wl,-rpath,$(TRUST_LIB)

clean:
	rm -f helpers

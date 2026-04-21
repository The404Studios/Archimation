# Makefile for libtrust_wine_shim.so
#
# Build locally:
#     make
# Clean:
#     make clean
#
# The PKGBUILD in this directory wraps this Makefile for Arch packaging.

CC      ?= gcc
# Use += so makepkg.conf's CFLAGS (which lack -fPIC) are PRESERVED and our
# flags are APPENDED.  `?=` would be skipped entirely when the environment
# already defines CFLAGS, silently losing -fPIC and breaking the .so link.
CFLAGS  += -O2 -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE
LDFLAGS +=
LDLIBS  += -ldl

TARGET  := libtrust_wine_shim.so
SRC     := libtrust_wine_shim.c

.PHONY: all clean

all: $(TARGET)

# -fPIC is placed on the compile line directly (not folded into CFLAGS) so
# it can never be overridden by an outer CFLAGS= invocation.  -shared implies
# -fPIC on most targets but being explicit is cheap insurance.
$(TARGET): $(SRC)
	$(CC) -fPIC -shared $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(TARGET)

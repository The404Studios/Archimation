# Makefile for libtrust_wine_shim.so
#
# Build locally:
#     make
# Clean:
#     make clean
#
# The PKGBUILD in this directory wraps this Makefile for Arch packaging.

CC      ?= gcc
CFLAGS  ?= -O2 -fPIC -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE
LDFLAGS ?=
LDLIBS  ?= -ldl

TARGET  := libtrust_wine_shim.so
SRC     := libtrust_wine_shim.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -shared -o $@ $< $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(TARGET)

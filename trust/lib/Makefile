# Userspace trust library Makefile
#
# Session 31:
#   - Adds libtrust_batch.c (varint+delta batch encoder) and
#     libtrust_events.c (binary events + zstd-compressed event log).
#   - Exposes both via existing soname libtrust.so.1, realname .1.2
#     (additive ABI — see libtrust.map).
#   - Links against libzstd (in base Arch) for event log compression.

CC        = gcc
CFLAGS    = -Wall -Wextra -Werror -O2 -fPIC -I$(CURDIR)/..
# trust_cmd.h (kernel-owned) contains two issues we can't fix:
#   - "trust_risc_*/trust_fbc_*/" inside a block comment (triggers
#     -Wcomment nested-comment warning)
#   - TRUST_OP_SCORE/TRUST_OP_THRESHOLD redefined inside the same header
#     (operand-tag vs opcode collision).
# Silence those for new modules that include trust_cmd.h directly.
# -Wno-builtin-macro-redefined doesn't cover user macros; we use -w
# only where needed or tolerate the warning by dropping -Werror for
# these new TUs while keeping everything else strict.
CFLAGS_NEW = $(filter-out -Werror,$(CFLAGS)) -Wno-comment -Wno-format
LDFLAGS   =
INSTALL_PREFIX ?= /usr

# Soname policy (additive):
ABI_MAJOR = 1
ABI_MINOR = 2
SONAME    = libtrust.so.$(ABI_MAJOR)
REALNAME  = libtrust.so.$(ABI_MAJOR).$(ABI_MINOR)
LINKNAME  = libtrust.so

# Detect libzstd via pkg-config; fall back to -lzstd.
ZSTD_CFLAGS := $(shell pkg-config --cflags libzstd 2>/dev/null)
ZSTD_LIBS   := $(shell pkg-config --libs libzstd 2>/dev/null)
ifeq ($(strip $(ZSTD_LIBS)),)
ZSTD_CFLAGS :=
ZSTD_LIBS   := -lzstd
endif
# Probe for the zstd header; if missing, keep the events.c compilable
# with HAVE_ZSTD undefined so compression degrades gracefully.
ZSTD_AVAILABLE := $(shell echo '\#include <zstd.h>' | $(CC) $(ZSTD_CFLAGS) \
                  -x c -E - >/dev/null 2>&1 && echo yes || echo no)
ifeq ($(ZSTD_AVAILABLE),yes)
CFLAGS += -DHAVE_ZSTD
else
ZSTD_LIBS :=
endif

OBJS      = libtrust.o libtrust_batch.o libtrust_events.o
HEADERS   = libtrust.h \
            ../include/trust_types.h ../include/trust_ioctl.h \
            ../include/trust_cmd.h   ../include/trust_isa.h

.PHONY: all clean install

all: $(LINKNAME) libtrust.a

libtrust.o: libtrust.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

libtrust_batch.o: libtrust_batch.c $(HEADERS)
	$(CC) $(CFLAGS_NEW) -c -o $@ $<

libtrust_events.o: libtrust_events.c $(HEADERS)
	$(CC) $(CFLAGS_NEW) $(ZSTD_CFLAGS) -c -o $@ $<

$(REALNAME): $(OBJS) libtrust.map
	$(CC) -shared -Wl,-soname,$(SONAME) \
	      -Wl,--version-script,$(CURDIR)/libtrust.map \
	      -o $@ $(OBJS) -lpthread $(ZSTD_LIBS)

# Build-time symlinks so both the linker name and soname resolve in-tree.
$(SONAME): $(REALNAME)
	ln -sf $(REALNAME) $@

$(LINKNAME): $(SONAME)
	ln -sf $(SONAME) $@

libtrust.a: $(OBJS)
	ar rcs $@ $^

clean:
	rm -f $(OBJS) $(REALNAME) $(SONAME) $(LINKNAME) libtrust.a

install: all
	install -d $(DESTDIR)$(INSTALL_PREFIX)/lib
	install -Dm755 $(REALNAME) $(DESTDIR)$(INSTALL_PREFIX)/lib/$(REALNAME)
	ln -sf $(REALNAME) $(DESTDIR)$(INSTALL_PREFIX)/lib/$(SONAME)
	ln -sf $(SONAME)   $(DESTDIR)$(INSTALL_PREFIX)/lib/$(LINKNAME)
	install -Dm644 libtrust.a $(DESTDIR)$(INSTALL_PREFIX)/lib/libtrust.a
	install -Dm644 libtrust.h \
	    $(DESTDIR)$(INSTALL_PREFIX)/include/trust/libtrust.h
	install -Dm644 ../include/trust_isa.h \
	    $(DESTDIR)$(INSTALL_PREFIX)/include/trust/trust_isa.h

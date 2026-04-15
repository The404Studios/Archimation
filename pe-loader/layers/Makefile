# pe-loader/layers/Makefile
#
# Builds the Coherence Vulkan implicit layer (libcoherence_present_layer.so).
#
# SOFT-FAIL: if <vulkan/vulkan.h> is not available on the build host we
# still produce an object (compiled without HAVE_VULKAN) so the project's
# top-level build never breaks -- the resulting .so is non-functional
# and install will skip it.
#
# Normal Arch builds have vulkan-headers in base-devel-adjacent packages
# or via the vulkan-icd-loader pull-in; we probe with cpp -E.

CC      ?= gcc
CFLAGS  ?= -O2 -fPIC -pipe -Wall -Wextra -fvisibility=hidden \
           -fno-strict-aliasing -pthread
LDFLAGS ?= -shared -ldl -lrt -pthread -Wl,-z,noexecstack

# Probe for vulkan headers at configure time.  We compile-check a trivial
# TU that pulls in <vulkan/vulkan.h>; if that succeeds the SDK headers are
# visible and we enable the real layer path.  A plain `-E` probe is not
# sufficient -- with many gcc versions a missing include does not return
# non-zero, so the test must actually try to compile.
#
# Make escapes '#' inside $(shell ...) as '\#', but the shell then sees
# literal '\#' which breaks `printf`.  We sidestep by emitting the probe
# TU as two `echo` lines with single-quoted comments Make recognizes as
# literal text (no '#' char actually passed to echo).
HAVE_VULKAN := $(shell TMPSRC=$$(mktemp --suffix=.c) && \
    { echo 'extern int main_probe(void);'; \
      echo 'int main_probe(void){return 0;}'; \
    } > $$TMPSRC && \
    $(CC) -include vulkan/vulkan.h -include vulkan/vk_layer.h \
        -xc -c -o /dev/null $$TMPSRC >/dev/null 2>&1 \
        && { rm -f $$TMPSRC; echo yes; } \
        || { rm -f $$TMPSRC; echo no; })

ifeq ($(HAVE_VULKAN),yes)
  CFLAGS += -DHAVE_VULKAN=1
else
  # Without Vulkan headers we compile only the stub branch; lots of helpers
  # become dead code so suppress -Wunused-function specifically.
  CFLAGS += -Wno-unused-function
  $(warning coherence_present_layer: Vulkan headers not found; building stub .so. \
    Install vulkan-headers to enable present-mode interception.)
endif

LAYER_SO   := libcoherence_present_layer.so
LAYER_SRCS := coherence_present_layer.c
LAYER_OBJS := $(LAYER_SRCS:.c=.o)
LAYER_MANIFEST := coherence_present_layer.json

# Install destinations:
#   .so       -> /usr/lib/vulkan/layers/
#   manifest  -> /etc/vulkan/implicit_layer.d/   (system-wide implicit)
INSTALL_PREFIX ?= /usr
LAYER_LIB_DIR  ?= $(INSTALL_PREFIX)/lib/vulkan/layers
IMPLICIT_DIR   ?= /etc/vulkan/implicit_layer.d
INSTALL        ?= install

.PHONY: all install clean syntax-check

all: $(LAYER_SO)

$(LAYER_SO): $(LAYER_OBJS)
	$(CC) $(LAYER_OBJS) $(LDFLAGS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Compile-check only (used by CI without linking).
syntax-check:
	$(CC) $(CFLAGS) -fsyntax-only $(LAYER_SRCS)

install: $(LAYER_SO)
	$(INSTALL) -d $(DESTDIR)$(LAYER_LIB_DIR)
	$(INSTALL) -m 0755 $(LAYER_SO) $(DESTDIR)$(LAYER_LIB_DIR)/
	$(INSTALL) -d $(DESTDIR)$(IMPLICIT_DIR)
	$(INSTALL) -m 0644 $(LAYER_MANIFEST) $(DESTDIR)$(IMPLICIT_DIR)/

clean:
	rm -f $(LAYER_OBJS) $(LAYER_SO)

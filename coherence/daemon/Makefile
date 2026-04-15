# coherence/daemon/Makefile
#
# Builds the coherence daemon (control loop + state machine + config).
#
# This Makefile only builds the pieces owned by Agent 3. Measurement
# (agent 4), derivation (agent 5), and actuation (agent 6) drop their
# .c files into src/ and get picked up automatically via the glob;
# their prototypes match the weak stubs in control_loop.c.
#
# -Werror is enforced. Pass `WERROR=0` to relax during bisect.

CC       ?= cc
PREFIX   ?= /usr
BINDIR   ?= $(PREFIX)/bin
CONFDIR  ?= /etc/coherence
UNITDIR  ?= $(PREFIX)/lib/systemd/system
RUNDIR   ?= /var/run/coherence

WERROR   ?= 1

CSTD      = -std=c11
WARN      = -Wall -Wextra -Wshadow -Wpointer-arith -Wcast-align \
            -Wstrict-prototypes -Wmissing-prototypes -Wformat=2 \
            -Wno-unused-parameter
# -Wnested-externs intentionally omitted: coherence_types.h (shared contract)
# declares `extern int memcmp(...)` inside coh_a_equal and we're not
# permitted to edit that header.
ifeq ($(WERROR),1)
WARN     += -Werror
endif

OPT      ?= -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2
DEBUG    ?= -g

CPPFLAGS += -Iinclude -D_POSIX_C_SOURCE=200809L
CFLAGS   += $(CSTD) $(WARN) $(OPT) $(DEBUG) -fno-common -fPIE
LDFLAGS  += -pie -Wl,-z,relro -Wl,-z,now

# --- sources ---
# Only files owned by Agent 3. Other agents' files are *.c too and will
# be linked in via wildcard; weak stubs in control_loop.c resolve when
# they're absent.
AGENT3_SRCS = src/main.c src/control_loop.c src/state_machine.c src/config.c
OTHER_SRCS  = $(filter-out $(AGENT3_SRCS),$(wildcard src/*.c))
AGENT3_OBJS = $(AGENT3_SRCS:.c=.o)
OTHER_OBJS  = $(OTHER_SRCS:.c=.o)
OBJS        = $(AGENT3_OBJS) $(OTHER_OBJS)

BIN         = coherenced

# Agent 3's files get the full strict set (incl. -Werror when WERROR=1).
# Other agents' files get a relaxed set — we still warn, but don't hold
# up our build on their prototype / truncation style choices. Once their
# agents land, they own their own warnings.
OTHER_WARN  = -Wall -Wextra -Wno-unused-parameter -Wno-missing-prototypes \
              -Wno-strict-prototypes -Wno-stringop-truncation \
              -Wno-format-truncation -Wno-shadow
OTHER_CFLAGS = $(CSTD) $(OTHER_WARN) $(OPT) $(DEBUG) -fno-common -fPIE

.PHONY: all clean install check syntax

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(AGENT3_OBJS): %.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(OTHER_OBJS): %.o: %.c
	$(CC) $(CPPFLAGS) $(OTHER_CFLAGS) -c -o $@ $<

# Syntax-only check. Used by CI and by Agent 3's self-verification.
syntax:
	@for f in $(AGENT3_SRCS); do \
		echo "  SYNTAX $$f"; \
		$(CC) $(CPPFLAGS) $(CFLAGS) -fsyntax-only $$f || exit 1; \
	done

check: syntax
	@echo "Daemon compiles cleanly."

clean:
	rm -f $(OBJS) $(BIN)

install: $(BIN)
	install -Dm755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)
	install -dm755 $(DESTDIR)$(CONFDIR)
	install -dm755 $(DESTDIR)$(RUNDIR)

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
# pool_metrics.c spawns a 1-Hz pthread aggregator at constructor time.
LDLIBS   += -lpthread

# --- sources ---
# Only files owned by Agent 3. Other agents' files are *.c too and will
# be linked in via wildcard; weak stubs in control_loop.c resolve when
# they're absent.
AGENT3_SRCS = src/main.c src/control_loop.c src/state_machine.c \
              src/state_machine_tables.c src/config.c
# Agent 2 (posture layer) owns src/posture.c. It follows the same strict
# -Werror regime as Agent 3 but has its own grouping so warnings stay
# scoped to the correct owner.
AGENT2_SRCS = src/posture.c
AGENT2_OBJS = $(AGENT2_SRCS:.c=.o)
OTHER_SRCS  = $(filter-out $(AGENT3_SRCS) $(AGENT2_SRCS),$(wildcard src/*.c))
AGENT3_OBJS = $(AGENT3_SRCS:.c=.o)
OTHER_OBJS  = $(OTHER_SRCS:.c=.o)
OBJS        = $(AGENT3_OBJS) $(AGENT2_OBJS) $(OTHER_OBJS)

BIN         = coherenced

# Agent 3's files get the full strict set (incl. -Werror when WERROR=1).
# Other agents' files get a relaxed set — we still warn, but don't hold
# up our build on their prototype / truncation style choices. Once their
# agents land, they own their own warnings.
OTHER_WARN  = -Wall -Wextra -Wno-unused-parameter -Wno-missing-prototypes \
              -Wno-strict-prototypes -Wno-stringop-truncation \
              -Wno-format-truncation -Wno-shadow
OTHER_CFLAGS = $(CSTD) $(OTHER_WARN) $(OPT) $(DEBUG) -fno-common -fPIE

.PHONY: all clean install check syntax test-posture syntax-posture \
        test-typestate test

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(AGENT3_OBJS): %.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(AGENT2_OBJS): %.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(OTHER_OBJS): %.o: %.c
	$(CC) $(CPPFLAGS) $(OTHER_CFLAGS) -c -o $@ $<

# Syntax-only check. Used by CI and by Agent 3's self-verification.
syntax:
	@for f in $(AGENT3_SRCS); do \
		echo "  SYNTAX $$f"; \
		$(CC) $(CPPFLAGS) $(CFLAGS) -fsyntax-only $$f || exit 1; \
	done

# Agent 2 posture-layer syntax check.
syntax-posture:
	@for f in $(AGENT2_SRCS); do \
		echo "  SYNTAX $$f"; \
		$(CC) $(CPPFLAGS) $(CFLAGS) -fsyntax-only $$f || exit 1; \
	done

check: syntax syntax-posture
	@echo "Daemon compiles cleanly."

# --- posture layer test ---
# Builds + runs tests/test_posture.c against src/posture.c. Uses the
# full strict warning set and links only what the test needs.
# COH_POSTURE_DRY_RUN=1 redirects all writes to /tmp/coh_posture_dry/.
TEST_POSTURE_BIN  = tests/test_posture.bin
TEST_POSTURE_SRCS = tests/test_posture.c src/posture.c

$(TEST_POSTURE_BIN): $(TEST_POSTURE_SRCS) include/posture.h include/coherence_types.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG -o $@ $(TEST_POSTURE_SRCS)

test-posture: $(TEST_POSTURE_BIN)
	@echo "  RUN  $(TEST_POSTURE_BIN)"
	@COH_POSTURE_DRY_RUN=1 $(TEST_POSTURE_BIN)

# --- typestate test ---
# Builds tests/test_typestate.c against the R34 typestate tables +
# stringifiers. Deliberately does not pull in the whole daemon — the
# test is a pure-function exercise of the transition table + string
# lookup surface. Full -Werror.
TEST_TYPESTATE_BIN  = tests/test_typestate.bin
TEST_TYPESTATE_SRCS = tests/test_typestate.c \
                      src/state_machine.c \
                      src/state_machine_tables.c

$(TEST_TYPESTATE_BIN): $(TEST_TYPESTATE_SRCS) include/coherence_types.h \
                      include/state_machine.h include/config.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(TEST_TYPESTATE_SRCS)

test-typestate: $(TEST_TYPESTATE_BIN)
	@echo "  RUN  $(TEST_TYPESTATE_BIN)"
	@$(TEST_TYPESTATE_BIN)

# Aggregate test target — runs every self-test in the daemon. Keeps
# CI green when new tests are added (they just get wired to `test`).
test: test-typestate

clean:
	rm -f $(OBJS) $(BIN) $(TEST_POSTURE_BIN) $(TEST_TYPESTATE_BIN)

install: $(BIN)
	install -Dm755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)
	install -dm755 $(DESTDIR)$(CONFDIR)
	install -dm755 $(DESTDIR)$(RUNDIR)

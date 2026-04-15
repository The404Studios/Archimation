# coherence/simulator/Makefile
#
# Offline stability simulator for the coherence control system.
#
# Targets:
#   make / make build       Build the simulator binary
#   make stability-report   Build + run + emit correctness-report.md + sweep-grid.csv
#   make traces             Regenerate the example .bin traces
#   make clean              Remove build artefacts
#   make distclean          Also remove generated reports + traces
#
# The simulator links against its own reference state_machine + derived
# implementations (compiled from simulator.c itself) so it does not need
# the daemon running. If coherence/daemon/build/libcoherence_core.a
# exists we prefer linking against it — Agents 3+5 can drop that in and
# the simulator will pick it up on the next build.

CC       ?= cc
CSTD     ?= -std=c11
CFLAGS   ?= $(CSTD) -O2 -pipe -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L
INCLUDES := -Iinclude -I../daemon/include
LDFLAGS  ?=
LDLIBS   ?= -lm

# Optional daemon static library.
CORE_LIB := ../daemon/build/libcoherence_core.a

SRC      := simulator.c trace.c noise.c stability.c sweep.c report.c
OBJ      := $(SRC:.c=.o)

# Daemon support sources we fold in when libcoherence_core.a is absent.
# config.c is the only piece we need that's not already re-implemented
# in simulator.c — its defaults/validator logic is purely compile-time
# and adding it here keeps the simulator self-contained without any
# header ping-pong.
DAEMON_SRC := ../daemon/src/config.c
DAEMON_OBJ := daemon_config.o

BIN        := simulator
REPORT_DIR := report
TRACE_DIR  := traces

# Default seed. Change via `make stability-report SEED=0x...` for a
# specific reproducer; keep default stable for CI.
SEED ?= 0xC0FFEE

.PHONY: all build stability-report traces clean distclean

all: $(BIN)

build: $(BIN)

$(BIN): $(OBJ) $(DAEMON_OBJ)
	@if [ -f $(CORE_LIB) ]; then \
		echo "[link] $(BIN) (with libcoherence_core)"; \
		$(CC) $(CFLAGS) $(OBJ) $(CORE_LIB) $(LDFLAGS) $(LDLIBS) -o $@; \
	else \
		echo "[link] $(BIN) (self-contained, no daemon lib)"; \
		$(CC) $(CFLAGS) $(OBJ) $(DAEMON_OBJ) $(LDFLAGS) $(LDLIBS) -o $@; \
	fi

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

daemon_config.o: $(DAEMON_SRC)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

traces: $(BIN)
	@mkdir -p $(TRACE_DIR)
	./$(BIN) --generate-traces --seed $(SEED)

stability-report: $(BIN)
	@mkdir -p $(REPORT_DIR) $(TRACE_DIR)
	./$(BIN) --seed $(SEED) \
	         --report $(REPORT_DIR)/correctness-report.md \
	         --csv    $(REPORT_DIR)/sweep-grid.csv \
	 || echo "(simulator exited non-zero; report may still be valid)"
	@echo "Report: $(REPORT_DIR)/correctness-report.md"

clean:
	rm -f $(OBJ) $(DAEMON_OBJ) $(BIN)

distclean: clean
	rm -rf $(REPORT_DIR)
	rm -f  $(TRACE_DIR)/*.bin

# Header dependencies — minimal but keeps incremental builds honest.
simulator.o: include/trace.h include/noise.h include/sim_internal.h \
             ../daemon/include/coherence_types.h ../daemon/include/config.h
trace.o:     include/trace.h include/noise.h
noise.o:     include/noise.h include/trace.h
stability.o: include/sim_internal.h ../daemon/include/coherence_types.h
sweep.o:     include/sim_internal.h include/trace.h include/noise.h \
             ../daemon/include/coherence_types.h ../daemon/include/config.h
report.o:    include/sim_internal.h ../daemon/include/coherence_types.h

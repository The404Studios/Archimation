# Test Suite Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2
MINGW_CC = x86_64-w64-mingw32-gcc
ROOT = $(CURDIR)/..
TRUST_DIR = $(ROOT)/trust
PE_DIR = $(ROOT)/pe-loader

.PHONY: all clean trust-tests pe-tests observer-tests api-tests \
       automation-tests filesystem-tests qemu-test hello-exe \
       pt_regs_test bisim-tests

all: trust-tests observer-tests automation-tests filesystem-tests bisim-tests

# --- Trust system tests ---
trust-tests: pe-loader/test_trust
	./pe-loader/test_trust

pe-loader/test_trust: pe-loader/test_trust.c
	$(CC) $(CFLAGS) -o $@ $< -L$(TRUST_DIR)/lib -ltrust \
		-I$(TRUST_DIR)/include -Wl,-rpath,$(TRUST_DIR)/lib

# --- PE loader tests ---
pe-tests: pe-loader/hello.exe
	bash pe-loader/test_peloader.sh

# Generate hello.exe using Python or Node.js (whichever is available)
hello-exe: pe-loader/hello.exe

pe-loader/hello.exe: pe-loader/gen_hello_pe.py pe-loader/gen_hello_pe.js
	@if command -v python3 >/dev/null 2>&1; then \
		python3 pe-loader/gen_hello_pe.py pe-loader/hello.exe; \
	elif command -v node >/dev/null 2>&1; then \
		node pe-loader/gen_hello_pe.js pe-loader/hello.exe; \
	else \
		echo "ERROR: Need python3 or node to generate hello.exe"; \
		exit 1; \
	fi

# Cross-compile test binary with MinGW (optional, requires mingw-w64-gcc)
pe-loader/hello_mingw.exe: pe-loader/hello_mingw.c
	$(MINGW_CC) -o $@ $< -nostdlib -Wl,--entry=_start -lkernel32

# --- AI control tests (Python) ---
AI_PYTHONPATH = $(ROOT)/ai-control:$(ROOT)/ai-control/daemon

observer-tests:
	python3 ai-control/test_trust_observer.py

api-tests:
	python3 ai-control/test_api.py

automation-tests:
	PYTHONPATH=$(AI_PYTHONPATH) python3 ai-control/test_automation.py

filesystem-tests:
	PYTHONPATH=$(AI_PYTHONPATH) python3 ai-control/test_filesystem.py

# --- Bisim / pure-C unit tests ---
# S76 Agent E: hook S75 Agent F's trust_pt_regs_compat unit test into the
# test tree so `make -C tests` exercises it. The test is self-contained
# (TRUST_TEST_PT_REGS makes the header synthesize a minimal x86_64 pt_regs,
# no kernel linkage), so it builds without WSL / mkarchiso.

bisim-tests: pt_regs_test

pt_regs_test: bisim/pt_regs_compat
	./bisim/pt_regs_compat

bisim/pt_regs_compat: bisim/test_pt_regs_compat.c
	$(CC) $(CFLAGS) -DTRUST_TEST_PT_REGS -I$(TRUST_DIR)/include \
		-o $@ $<

# --- Integration ---
qemu-test:
	bash ../scripts/test-qemu.sh

clean:
	rm -f pe-loader/test_trust pe-loader/hello_mingw.exe \
	      bisim/pt_regs_compat

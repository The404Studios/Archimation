# Test Suite Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2
MINGW_CC = x86_64-w64-mingw32-gcc
ROOT = $(CURDIR)/..
TRUST_DIR = $(ROOT)/trust
PE_DIR = $(ROOT)/pe-loader

.PHONY: all clean trust-tests pe-tests observer-tests api-tests \
       automation-tests filesystem-tests qemu-test hello-exe

all: trust-tests observer-tests automation-tests filesystem-tests

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

# --- Integration ---
qemu-test:
	bash ../scripts/test-qemu.sh

clean:
	rm -f pe-loader/test_trust pe-loader/hello_mingw.exe

# Top-level Makefile for AI Arch Linux
# Parallel builds: run with `make -jN` or set `JOBS=N make`.
# Auto-detects cores; propagates MAKEFLAGS to sub-makes (pe-loader, trust, services, tests).

.PHONY: all trust-lib trust-kernel pe-loader services ai-control firewall packages iso clean test test-qemu help

# Auto-detect core count. Respect pre-set JOBS env var.
# nproc exists on Linux/WSL; fall back to 4 on exotic hosts.
JOBS ?= $(shell nproc 2>/dev/null || echo 4)

# Propagate parallel-job flag to every sub-make. The conditional guards
# against infinite recursion when the parent already set -jN.
ifeq (,$(findstring -j,$(MAKEFLAGS)))
MAKEFLAGS += -j$(JOBS)
endif

# Export JOBS so scripts/build-packages.sh and scripts/build-iso.sh pick it up.
export JOBS
export MAKEFLAGS

# ccache wrapper — huge win on iterative C rebuilds (5-20x faster second compile).
# Skip gracefully when ccache isn't installed.
CCACHE := $(shell command -v ccache 2>/dev/null)
ifneq (,$(CCACHE))
export CC  := ccache $(or $(CC),gcc)
export CXX := ccache $(or $(CXX),g++)
# Keep ccache in a project-local dir so WSL/NTFS doesn't blow away the root cache
# between runs when /tmp is tmpfs-backed (it's not on WSL2, but belt-and-braces).
export CCACHE_DIR ?= $(HOME)/.cache/ccache-ai-arch
# 5 GB is plenty for this project's C+ASM footprint; prevents unbounded growth.
export CCACHE_MAXSIZE ?= 5G
endif

all: trust-lib pe-loader services

help:
	@echo "AI Arch Linux Build"
	@echo "  make all         — build trust-lib + pe-loader + services (default)"
	@echo "  make packages    — build all .pkg.tar.zst (incremental)"
	@echo "  make iso         — build pe-loader + services + packages + ISO"
	@echo "  make test        — run pe-loader test suite"
	@echo "  make test-qemu   — boot the ISO in QEMU and smoke-test"
	@echo "  make clean       — remove all build artifacts"
	@echo ""
	@echo "  Parallel jobs: $(JOBS) (override: JOBS=N make …)"
	@echo "  ccache:        $(if $(CCACHE),enabled ($(CCACHE)),not installed)"

trust-lib:
	$(MAKE) -C trust/lib

trust-kernel:
	$(MAKE) -C trust/kernel

pe-loader: trust-lib
	$(MAKE) -C pe-loader

services:
	$(MAKE) -C services

packages:
	bash scripts/build-packages.sh

iso: pe-loader services packages
	bash scripts/build-iso.sh

ai-control:
	@echo "AI control daemon is Python-based, no compilation needed."

firewall:
	@echo "Firewall is Python-based, no compilation needed."

clean:
	$(MAKE) -C trust/kernel clean 2>/dev/null || true
	$(MAKE) -C pe-loader clean
	$(MAKE) -C services clean
	bash scripts/clean.sh

test: pe-loader
	$(MAKE) -C pe-loader tests
	$(MAKE) -C tests

test-qemu: iso
	bash scripts/test-qemu.sh

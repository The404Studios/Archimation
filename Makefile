.PHONY: all trust-lib trust-kernel pe-loader services ai-control firewall packages iso clean test test-qemu

all: trust-lib trust-kernel pe-loader services

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

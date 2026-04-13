# Root of Trust - Top-level Makefile

KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build

.PHONY: all kernel lib clean install

all: kernel lib

# Kernel module
kernel:
	$(MAKE) -C $(KERNEL_SRC) M=$(CURDIR)/kernel modules

# Userspace library
lib:
	$(MAKE) -C lib

clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(CURDIR)/kernel clean 2>/dev/null || true
	$(MAKE) -C lib clean

install: all
	install -Dm644 kernel/trust.ko $(DESTDIR)/lib/modules/$(shell uname -r)/extra/trust.ko
	$(MAKE) -C lib install DESTDIR=$(DESTDIR)
	install -Dm644 include/trust_types.h $(DESTDIR)/usr/include/trust/trust_types.h
	install -Dm644 include/trust_ioctl.h $(DESTDIR)/usr/include/trust/trust_ioctl.h

# Userspace trust library Makefile

CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2 -fPIC -I$(CURDIR)/..
INSTALL_PREFIX ?= /usr

.PHONY: all clean install

all: libtrust.so libtrust.a

libtrust.o: libtrust.c libtrust.h ../include/trust_types.h ../include/trust_ioctl.h
	$(CC) $(CFLAGS) -c -o $@ $<

libtrust.so: libtrust.o
	$(CC) -shared -o $@ $^ -lpthread

libtrust.a: libtrust.o
	ar rcs $@ $^

clean:
	rm -f libtrust.o libtrust.so libtrust.a

install: all
	install -Dm755 libtrust.so $(DESTDIR)$(INSTALL_PREFIX)/lib/libtrust.so
	install -Dm644 libtrust.a $(DESTDIR)$(INSTALL_PREFIX)/lib/libtrust.a
	install -Dm644 libtrust.h $(DESTDIR)$(INSTALL_PREFIX)/include/trust/libtrust.h

# Object Broker Daemon (pe-objectd) Makefile

CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2 \
         -I../../pe-loader/include \
         -I../../pe-loader/dlls \
         -I../../pe-loader/registry
LDFLAGS = -lpthread -lrt

SRCS = objectd_main.c \
       objectd_objects.c \
       objectd_registry.c \
       objectd_namespace.c \
       objectd_shm.c \
       objectd_handles.c \
       ../../pe-loader/registry/registry.c \
       ../../pe-loader/registry/registry_defaults.c

OBJS = $(SRCS:.c=.o)

.PHONY: all clean

all: pe-objectd

pe-objectd: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o pe-objectd
	rm -f ../../pe-loader/registry/registry.o
	rm -f ../../pe-loader/registry/registry_defaults.o

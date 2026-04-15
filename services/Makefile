# Windows Services / Drivers / Anti-Cheat Layer

.PHONY: all scm drivers anticheat async objectd clean

CC = gcc
CFLAGS = -Wall -Wextra -O2 -I../pe-loader/include -I../pe-loader/dlls -I../pe-loader/registry
LDFLAGS = -lpthread -ldl

all: async scm drivers-stubs drivers-userspace anticheat objectd

# Service Control Manager
SCM_SRCS = scm/scm_daemon.c scm/scm_database.c scm/scm_api.c \
           scm/scm_dependency.c scm/scm_event.c
SCM_OBJS = $(SCM_SRCS:.c=.o)

scm: scm/scm_daemon scm/sc

scm/scm_daemon: $(SCM_OBJS) $(ASYNC_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

scm/sc: scm/sc.c
	$(CC) $(CFLAGS) -Iscm -o $@ $< $(LDFLAGS)

scm/%.o: scm/%.c
	$(CC) $(CFLAGS) -Iscm -c -o $@ $<

# Async service queue (optional, links with SCM objects)
ASYNC_SRCS = async/service_queue.c async/dependency_graph.c
ASYNC_OBJS = $(ASYNC_SRCS:.c=.o)

async: $(ASYNC_OBJS)

async/%.o: async/%.c
	$(CC) $(CFLAGS) -Iscm -c -o $@ $<

# Driver stubs library (linked into driver-related tools)
DRIVER_STUB_SRCS = drivers/stubs/wdm_stubs.c \
                   drivers/stubs/wdf_stubs.c \
                   drivers/stubs/ndis_stubs.c
DRIVER_STUB_OBJS = $(DRIVER_STUB_SRCS:.c=.o)

drivers/stubs/%.o: drivers/stubs/%.c
	$(CC) $(CFLAGS) -I drivers/stubs -c -o $@ $<

# Driver userspace tools
DRIVER_USER_SRCS = drivers/userspace/inf_parser.c \
                   drivers/userspace/device_namespace.c \
                   drivers/userspace/ioctl_bridge.c \
                   drivers/userspace/driver_install.c
DRIVER_USER_OBJS = $(DRIVER_USER_SRCS:.c=.o)

drivers/userspace/%.o: drivers/userspace/%.c
	$(CC) $(CFLAGS) -I drivers/stubs -c -o $@ $<

drivers-stubs: drivers/stubs/libwdm_stubs.so drivers/stubs/libwdf_stubs.so drivers/stubs/libndis_stubs.so

drivers/stubs/libwdm_stubs.so: drivers/stubs/wdm_stubs.c
	$(CC) $(CFLAGS) -fPIC -shared -I drivers/stubs -o $@ $<

drivers/stubs/libwdf_stubs.so: drivers/stubs/wdf_stubs.c
	$(CC) $(CFLAGS) -fPIC -shared -I drivers/stubs -o $@ $<

drivers/stubs/libndis_stubs.so: drivers/stubs/ndis_stubs.c
	$(CC) $(CFLAGS) -fPIC -shared -I drivers/stubs -o $@ $<

drivers-userspace: $(DRIVER_STUB_OBJS) $(DRIVER_USER_OBJS) drivers/userspace/devcon drivers-stubs

drivers/userspace/devcon: drivers/userspace/devcon.c $(DRIVER_USER_OBJS) $(DRIVER_STUB_OBJS)
	$(CC) $(CFLAGS) -I drivers/stubs -o $@ $^ $(LDFLAGS)

# Anti-cheat compatibility
ANTICHEAT_SRCS = anticheat/ac_compat.c \
                 anticheat/eac_shim.c \
                 anticheat/battleye_shim.c \
                 anticheat/blackshield_shim.c \
                 anticheat/vanguard_shim.c \
                 anticheat/anticheat_guard.c \
                 anticheat/process_integrity.c \
                 anticheat/kernel_callbacks.c
ANTICHEAT_OBJS = $(ANTICHEAT_SRCS:.c=.o)

anticheat: anticheat/libpe_anticheat.so

anticheat/%.o: anticheat/%.c
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

anticheat/libpe_anticheat.so: $(ANTICHEAT_OBJS)
	$(CC) $(CFLAGS) -shared -o $@ $^ $(LDFLAGS)

# Object Broker daemon
objectd:
	$(MAKE) -C objectd

# Kernel driver host module (requires kernel headers)
drivers-kernel:
	$(MAKE) -C drivers/kernel

clean:
	rm -f scm/*.o scm/scm_daemon scm/sc
	rm -f async/*.o
	rm -f drivers/stubs/*.o drivers/stubs/*.so
	rm -f drivers/userspace/*.o drivers/userspace/devcon
	rm -f anticheat/*.o anticheat/*.so
	$(MAKE) -C objectd clean

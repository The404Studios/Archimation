# PE Loader - Top-level Makefile
#
# Builds: peloader binary, stub DLL shared libraries, kernel module
# Supports parallel builds via `make -jN`. Header dep tracking via -MMD -MP
# avoids spurious recompiles when an unrelated header's timestamp changes.

.PHONY: all loader dlls kernel tests tools clean install trust_lib

# Allow the caller (top-level Makefile or scripts) to pass CC=ccache gcc.
# Otherwise default to gcc.
CC ?= gcc
NASM ?= nasm
# x86_64 baseline — do NOT use -march=native. The ISO targets both old
# (Westmere-era) and new hardware; the loader must run on any x86_64 CPU.
# -pipe: assemble via pipes not temp files (~5-10% faster on WSL/NTFS).
# -MMD -MP: emit .d dep files so changed headers trigger only affected .o rebuilds.
CFLAGS = -Wall -Wextra -Werror -Wno-stringop-truncation -Wno-format-truncation \
         -O2 -fPIC -pipe -MMD -MP \
         -I$(CURDIR)/include -I$(TRUST_DIR)/include
TRUST_DIR = $(CURDIR)/../trust
LDFLAGS = -ldl -lpthread
LOADER_LDFLAGS = $(LDFLAGS) -rdynamic -L$(TRUST_DIR)/lib -ltrust -lm -lrt -Wl,-rpath,/usr/lib

INSTALL_PREFIX ?= /usr
BIN_DIR ?= $(INSTALL_PREFIX)/bin
LIB_DIR ?= $(INSTALL_PREFIX)/lib/pe-compat
KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build

all: trust_lib loader dlls

# --- Trust library (must be built first) ---
trust_lib:
	$(MAKE) -C $(TRUST_DIR)/lib

# --- Loader binary ---
LOADER_SRCS = loader/main.c \
              loader/loader_init.c \
              loader/abi_thunk_create.c \
              loader/pe_parser.c \
              loader/pe_mapper.c \
              loader/pe_relocator.c \
              loader/pe_import.c \
              loader/preloader.c \
              loader/memory_manager.c \
              loader/env_setup.c \
              loader/pe_tls.c \
              loader/pe_exception.c \
              loader/windrv_manager.c \
              loader/windrv_host.c \
              loader/pe_diag.c \
              loader/anticheat_bridge.c \
              loader/trust_gate.c \
              loader/pe_event.c \
              loader/cortex_cmd.c \
              loader/objectd_client.c \
              dlls/common/wchar_util.c \
              loader/abi_thunk.S
LOADER_OBJS = $(LOADER_SRCS:.c=.o)
LOADER_OBJS := $(LOADER_OBJS:.S=.o)

loader: loader/peloader

# Explicit order-only dep on trust_lib — safe under `make -j` (loader/peloader
# linker step needs ../trust/lib/libtrust.so; without this, parallel make can
# race trust_lib against loader compile/link and fail with "cannot find -ltrust")
loader/peloader: $(LOADER_OBJS) | trust_lib
	$(CC) $(CFLAGS) -o $@ $(LOADER_OBJS) $(LOADER_LDFLAGS)

loader/%.o: loader/%.c
	$(CC) $(CFLAGS) -I$(CURDIR)/dlls -c -o $@ $<

loader/%.o: loader/%.S
	$(CC) $(CFLAGS) -c -o $@ $<

dlls/common/wchar_util.o: dlls/common/wchar_util.c
	$(CC) $(CFLAGS) -I$(CURDIR)/dlls -c -o $@ $<

# Registry files compiled into loader need both include paths
registry/registry.o: registry/registry.c
	$(CC) $(CFLAGS) -I$(CURDIR)/dlls -I$(CURDIR)/registry -c -o $@ $<

registry/registry_defaults.o: registry/registry_defaults.c
	$(CC) $(CFLAGS) -I$(CURDIR)/dlls -I$(CURDIR)/registry -c -o $@ $<

# --- Stub DLL shared libraries ---
DLL_CFLAGS = $(CFLAGS) -I$(CURDIR)/dlls -I$(CURDIR)/registry

# Common library (statically linked into each DLL)
COMMON_SRCS = dlls/common/dll_common.c \
              dlls/common/wchar_util.c \
              dlls/common/casefold.c
COMMON_OBJS = $(COMMON_SRCS:.c=.o)

dlls/common/%.o: dlls/common/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

# Registry library (linked into advapi32)
REGISTRY_SRCS = registry/registry.c \
                registry/registry_defaults.c
REGISTRY_OBJS = $(REGISTRY_SRCS:.c=.o)

registry/%.o: registry/%.c
	$(CC) $(DLL_CFLAGS) -I$(CURDIR)/dlls -c -o $@ $<

# kernel32.dll stub
K32_SRCS = dlls/kernel32/kernel32_console.c \
           dlls/kernel32/kernel32_process.c \
           dlls/kernel32/kernel32_error.c \
           dlls/kernel32/kernel32_memory.c \
           dlls/kernel32/kernel32_file.c \
           dlls/kernel32/kernel32_find.c \
           dlls/kernel32/kernel32_thread.c \
           dlls/kernel32/kernel32_sync.c \
           dlls/kernel32/kernel32_string.c \
           dlls/kernel32/kernel32_time.c \
           dlls/kernel32/kernel32_module.c \
           dlls/kernel32/kernel32_module_pe.c \
           dlls/kernel32/kernel32_path.c \
           dlls/kernel32/kernel32_environ.c \
           dlls/kernel32/kernel32_resource.c \
           dlls/kernel32/kernel32_pipe.c \
           dlls/kernel32/kernel32_iocp.c \
           dlls/kernel32/kernel32_fiber.c \
           dlls/kernel32/kernel32_srwlock.c \
           dlls/kernel32/kernel32_threadpool.c \
           dlls/kernel32/kernel32_debug.c \
           dlls/kernel32/kernel32_notify.c \
           dlls/kernel32/kernel32_async.c \
           dlls/kernel32/kernel32_locale.c \
           dlls/kernel32/kernel32_toolhelp.c \
           dlls/kernel32/kernel32_job.c
K32_OBJS = $(K32_SRCS:.c=.o)

dlls/kernel32/%.o: dlls/kernel32/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_kernel32.so: $(K32_OBJS) $(EXTRA_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS) -lrt

# ntdll.dll stub
NTDLL_SRCS = dlls/ntdll/ntdll_main.c \
             dlls/ntdll/ntdll_file.c \
             dlls/ntdll/ntdll_memory.c \
             dlls/ntdll/ntdll_thread.c \
             dlls/ntdll/ntdll_sync.c \
             dlls/ntdll/ntdll_exception.c \
             dlls/ntdll/ntdll_process.c
NTDLL_OBJS = $(NTDLL_SRCS:.c=.o)

dlls/ntdll/%.o: dlls/ntdll/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_ntdll.so: $(NTDLL_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# msvcrt.dll stub
MSVCRT_SRCS = dlls/msvcrt/msvcrt_stdio.c \
              dlls/msvcrt/msvcrt_heap.c \
              dlls/msvcrt/msvcrt_math.c \
              dlls/msvcrt/msvcrt_except.c \
              dlls/msvcrt/msvcrt_string.c
MSVCRT_OBJS = $(MSVCRT_SRCS:.c=.o)

dlls/msvcrt/%.o: dlls/msvcrt/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_msvcrt.so: $(MSVCRT_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS) -lm

# advapi32.dll stub
ADVAPI32_SRCS = dlls/advapi32/advapi32_registry.c \
                dlls/advapi32/advapi32_service.c \
                dlls/advapi32/advapi32_security.c \
                dlls/advapi32/advapi32_crypto.c \
                dlls/advapi32/advapi32_credman.c
ADVAPI32_OBJS = $(ADVAPI32_SRCS:.c=.o)

dlls/advapi32/%.o: dlls/advapi32/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_advapi32.so: $(ADVAPI32_OBJS) $(REGISTRY_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# Graphics backend (linked into user32 and gdi32)
GFX_SRCS = graphics/gfx_x11.c \
           graphics/gfx_drawing.c \
           graphics/gfx_wayland.c
GFX_OBJS = $(GFX_SRCS:.c=.o)
GFX_CFLAGS = $(CFLAGS) -I$(CURDIR)/graphics -I$(CURDIR)/dlls

graphics/%.o: graphics/%.c
	$(CC) $(GFX_CFLAGS) -c -o $@ $<

# user32.dll stub
USER32_SRCS = dlls/user32/user32_window.c \
              dlls/user32/user32_message.c \
              dlls/user32/user32_input.c \
              dlls/user32/user32_dialog.c \
              dlls/user32/user32_menu.c \
              dlls/user32/user32_display.c
USER32_OBJS = $(USER32_SRCS:.c=.o)

dlls/user32/%.o: dlls/user32/%.c
	$(CC) $(DLL_CFLAGS) -I$(CURDIR)/graphics -c -o $@ $<

dlls/libpe_user32.so: $(USER32_OBJS) $(GFX_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS) -lX11

# gdi32.dll stub
GDI32_SRCS = dlls/gdi32/gdi32_dc.c \
             dlls/gdi32/gdi32_bitmap.c \
             dlls/gdi32/gdi32_text.c \
             dlls/gdi32/gdi32_font.c
GDI32_OBJS = $(GDI32_SRCS:.c=.o)

dlls/gdi32/%.o: dlls/gdi32/%.c
	$(CC) $(DLL_CFLAGS) -I$(CURDIR)/graphics -c -o $@ $<

dlls/libpe_gdi32.so: $(GDI32_OBJS) $(GFX_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS) -lX11

# ws2_32.dll stub (Winsock2)
WS2_SRCS = dlls/ws2_32/ws2_32_socket.c
WS2_OBJS = $(WS2_SRCS:.c=.o)

dlls/ws2_32/%.o: dlls/ws2_32/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_ws2_32.so: $(WS2_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# ole32.dll stub (COM)
OLE32_SRCS = dlls/ole32/ole32_com.c \
             dlls/ole32/ole32_classregistry.c \
             dlls/ole32/ole32_shell.c
OLE32_OBJS = $(OLE32_SRCS:.c=.o)

dlls/ole32/%.o: dlls/ole32/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_ole32.so: $(OLE32_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# shell32.dll stub (Shell API)
SHELL32_SRCS = dlls/shell32/shell32_shell.c
SHELL32_OBJS = $(SHELL32_SRCS:.c=.o)

dlls/shell32/%.o: dlls/shell32/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_shell32.so: $(SHELL32_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# version.dll stub
VERSION_SRCS = dlls/version/version_info.c
VERSION_OBJS = $(VERSION_SRCS:.c=.o)

dlls/version/%.o: dlls/version/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_version.so: $(VERSION_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# shlwapi.dll stub (Shell Lightweight Utility)
SHLWAPI_SRCS = dlls/shlwapi/shlwapi_path.c
SHLWAPI_OBJS = $(SHLWAPI_SRCS:.c=.o)

dlls/shlwapi/%.o: dlls/shlwapi/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_shlwapi.so: $(SHLWAPI_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# crypt32.dll stub (Certificate/Crypto)
CRYPT32_SRCS = dlls/crypt32/crypt32_cert.c
CRYPT32_OBJS = $(CRYPT32_SRCS:.c=.o)

dlls/crypt32/%.o: dlls/crypt32/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_crypt32.so: $(CRYPT32_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# winmm.dll stub (Multimedia)
WINMM_SRCS = dlls/winmm/winmm_time.c
WINMM_OBJS = $(WINMM_SRCS:.c=.o)

dlls/winmm/%.o: dlls/winmm/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_winmm.so: $(WINMM_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# iphlpapi.dll stub (IP Helper)
IPHLPAPI_SRCS = dlls/iphlpapi/iphlpapi_net.c
IPHLPAPI_OBJS = $(IPHLPAPI_SRCS:.c=.o)

dlls/iphlpapi/%.o: dlls/iphlpapi/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_iphlpapi.so: $(IPHLPAPI_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# winhttp.dll stub (HTTP client + WinINet)
WINHTTP_SRCS = dlls/winhttp/winhttp_session.c
WINHTTP_OBJS = $(WINHTTP_SRCS:.c=.o)

dlls/winhttp/%.o: dlls/winhttp/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_winhttp.so: $(WINHTTP_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# setupapi.dll stub (Device Setup)
SETUPAPI_SRCS = dlls/setupapi/setupapi_device.c
SETUPAPI_OBJS = $(SETUPAPI_SRCS:.c=.o)

dlls/setupapi/%.o: dlls/setupapi/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_setupapi.so: $(SETUPAPI_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# comctl32.dll stub (Common Controls)
COMCTL32_SRCS = dlls/comctl32/comctl32_controls.c
COMCTL32_OBJS = $(COMCTL32_SRCS:.c=.o)

dlls/comctl32/%.o: dlls/comctl32/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_comctl32.so: $(COMCTL32_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# comdlg32.dll stub (Common Dialog Box Library)
COMDLG32_SRCS = dlls/comdlg32/comdlg32_dialogs.c
COMDLG32_OBJS = $(COMDLG32_SRCS:.c=.o)

dlls/comdlg32/%.o: dlls/comdlg32/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_comdlg32.so: $(COMDLG32_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# d3d stubs (DirectX/Direct3D/XInput/D3D12/DirectInput/D3DX)
D3D_SRCS = dlls/d3d/d3d_stubs.c \
           dlls/d3d/d3d9_device.c \
           dlls/d3d/dxgi_factory.c \
           dlls/d3d/d3dcompiler_stubs.c \
           dlls/d3d/dxvk_bridge.c \
           dlls/d3d/d3dx_stubs.c \
           dlls/d3d/dinput_stubs.c
D3D_OBJS = $(D3D_SRCS:.c=.o)

dlls/d3d/%.o: dlls/d3d/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_d3d.so: $(D3D_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS) -lm

# ntoskrnl.exe stub (Windows kernel API)
NTOSKRNL_SRCS = dlls/ntoskrnl/ntoskrnl_io.c \
                dlls/ntoskrnl/ntoskrnl_mm.c \
                dlls/ntoskrnl/ntoskrnl_sync.c \
                dlls/ntoskrnl/ntoskrnl_rtl.c \
                dlls/ntoskrnl/ntoskrnl_ps.c \
                dlls/ntoskrnl/ntoskrnl_registry.c
NTOSKRNL_OBJS = $(NTOSKRNL_SRCS:.c=.o)

dlls/ntoskrnl/%.o: dlls/ntoskrnl/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_ntoskrnl.so: $(NTOSKRNL_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# hal.dll stub (Hardware Abstraction Layer)
HAL_SRCS = dlls/hal/hal_stubs.c
HAL_OBJS = $(HAL_SRCS:.c=.o)

dlls/hal/%.o: dlls/hal/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_hal.so: $(HAL_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# ndis.sys stub (Network Driver Interface)
NDIS_SRCS = dlls/ndis/ndis_stubs.c
NDIS_OBJS = $(NDIS_SRCS:.c=.o)

dlls/ndis/%.o: dlls/ndis/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_ndis.so: $(NDIS_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# mscoree.dll stub (.NET CLR hosting)
MSCOREE_SRCS = dlls/mscoree/mscoree_host.c
MSCOREE_OBJS = $(MSCOREE_SRCS:.c=.o)

dlls/mscoree/%.o: dlls/mscoree/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_mscoree.so: $(MSCOREE_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# oleaut32.dll stub (OLE Automation - BSTR, VARIANT, SafeArray)
OLEAUT32_SRCS = dlls/oleaut32/oleaut32_variant.c
OLEAUT32_OBJS = $(OLEAUT32_SRCS:.c=.o)

dlls/oleaut32/%.o: dlls/oleaut32/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_oleaut32.so: $(OLEAUT32_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# bcrypt.dll stub (Modern Crypto API)
BCRYPT_SRCS = dlls/bcrypt/bcrypt_crypto.c
BCRYPT_OBJS = $(BCRYPT_SRCS:.c=.o)

dlls/bcrypt/%.o: dlls/bcrypt/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_bcrypt.so: $(BCRYPT_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# psapi.dll stub (Process Status API)
PSAPI_SRCS = dlls/psapi/psapi_process.c
PSAPI_OBJS = $(PSAPI_SRCS:.c=.o)

dlls/psapi/%.o: dlls/psapi/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_psapi.so: $(PSAPI_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# dbghelp.dll stub (Debug/Symbol Helper)
DBGHELP_SRCS = dlls/dbghelp/dbghelp_sym.c
DBGHELP_OBJS = $(DBGHELP_SRCS:.c=.o)

dlls/dbghelp/%.o: dlls/dbghelp/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_dbghelp.so: $(DBGHELP_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# userenv.dll stub (User Profile)
USERENV_SRCS = dlls/userenv/userenv_profile.c
USERENV_OBJS = $(USERENV_SRCS:.c=.o)

dlls/userenv/%.o: dlls/userenv/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_userenv.so: $(USERENV_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# secur32.dll stub (SSPI Authentication)
SECUR32_SRCS = dlls/secur32/secur32_sspi.c
SECUR32_OBJS = $(SECUR32_SRCS:.c=.o)

dlls/secur32/%.o: dlls/secur32/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_secur32.so: $(SECUR32_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# dsound.dll stub (DirectSound + XAudio2)
DSOUND_SRCS = dlls/dsound/dsound_audio.c \
              dlls/dsound/xaudio2_stubs.c
DSOUND_OBJS = $(DSOUND_SRCS:.c=.o)

dlls/dsound/%.o: dlls/dsound/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_dsound.so: $(DSOUND_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS) -lm

# dwmapi.dll stub (Desktop Window Manager)
DWMAPI_SRCS = dlls/dwmapi/dwmapi_stubs.c
DWMAPI_OBJS = $(DWMAPI_SRCS:.c=.o)

dlls/dwmapi/%.o: dlls/dwmapi/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_dwmapi.so: $(DWMAPI_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# steamclient (steam_api64.dll stubs)
STEAMCLIENT_SRCS = dlls/steamclient/steam_api_stub.c
STEAMCLIENT_OBJS = $(STEAMCLIENT_SRCS:.c=.o)

dlls/steamclient/%.o: dlls/steamclient/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_steamclient.so: $(STEAMCLIENT_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# msi.dll stub (Windows Installer + VC++ Redistributable handler)
MSI_SRCS = dlls/msi/msi_installer.c \
           dlls/msi/vcredist_handler.c
MSI_OBJS = $(MSI_SRCS:.c=.o)

dlls/msi/%.o: dlls/msi/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_msi.so: $(MSI_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# extra stubs (wevtapi, powrprof, cabinet, wintrust)
EXTRA_SRCS = dlls/extra/extra_stubs.c
EXTRA_OBJS = $(EXTRA_SRCS:.c=.o)

dlls/extra/%.o: dlls/extra/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

# imm32.dll stub
IMM32_SRCS = dlls/imm32/imm32_input.c
IMM32_OBJS = $(IMM32_SRCS:.c=.o)

dlls/imm32/%.o: dlls/imm32/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_imm32.so: $(IMM32_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# shcore.dll stub (DPI awareness)
SHCORE_SRCS = dlls/shcore/shcore_stubs.c
SHCORE_OBJS = $(SHCORE_SRCS:.c=.o)

dlls/shcore/%.o: dlls/shcore/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_shcore.so: $(SHCORE_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# combase.dll stub (WinRT foundation)
COMBASE_SRCS = dlls/combase/combase_winrt.c
COMBASE_OBJS = $(COMBASE_SRCS:.c=.o)

dlls/combase/%.o: dlls/combase/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_combase.so: $(COMBASE_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# WinPixEventRuntime.dll stub (UE5 GPU profiling)
WINPIX_SRCS = dlls/winpix/winpix_stubs.c
WINPIX_OBJS = $(WINPIX_SRCS:.c=.o)

dlls/winpix/%.o: dlls/winpix/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_winpix.so: $(WINPIX_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# wer.dll stub (Windows Error Reporting)
WER_SRCS = dlls/wer/wer_stubs.c
WER_OBJS = $(WER_SRCS:.c=.o)

dlls/wer/%.o: dlls/wer/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_wer.so: $(WER_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# dstorage.dll stub (DirectStorage for UE5 asset streaming)
DSTORAGE_SRCS = dlls/dstorage/dstorage_stubs.c
DSTORAGE_OBJS = $(DSTORAGE_SRCS:.c=.o)

dlls/dstorage/%.o: dlls/dstorage/%.c
	$(CC) $(DLL_CFLAGS) -c -o $@ $<

dlls/libpe_dstorage.so: $(DSTORAGE_OBJS) $(COMMON_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

dlls: dlls/libpe_kernel32.so dlls/libpe_ntdll.so dlls/libpe_msvcrt.so \
      dlls/libpe_advapi32.so dlls/libpe_user32.so dlls/libpe_gdi32.so \
      dlls/libpe_ws2_32.so dlls/libpe_ole32.so dlls/libpe_shell32.so \
      dlls/libpe_version.so dlls/libpe_shlwapi.so dlls/libpe_crypt32.so \
      dlls/libpe_winmm.so dlls/libpe_iphlpapi.so dlls/libpe_winhttp.so \
      dlls/libpe_setupapi.so dlls/libpe_comctl32.so dlls/libpe_comdlg32.so dlls/libpe_d3d.so \
      dlls/libpe_ntoskrnl.so dlls/libpe_hal.so dlls/libpe_ndis.so \
      dlls/libpe_mscoree.so \
      dlls/libpe_oleaut32.so dlls/libpe_bcrypt.so dlls/libpe_psapi.so \
      dlls/libpe_dbghelp.so dlls/libpe_userenv.so dlls/libpe_secur32.so \
      dlls/libpe_dsound.so \
      dlls/libpe_dwmapi.so dlls/libpe_steamclient.so \
      dlls/libpe_msi.so dlls/libpe_imm32.so \
      dlls/libpe_shcore.so \
      dlls/libpe_combase.so dlls/libpe_winpix.so \
      dlls/libpe_wer.so dlls/libpe_dstorage.so

# --- Kernel module ---
kernel:
	$(MAKE) -C $(KERNEL_SRC) M=$(CURDIR)/kernel modules

# --- Tests ---
tests: loader dlls
	@echo "Running PE parser tests..."
	@if [ -x ../tests/pe-loader/test_peloader.sh ]; then \
		bash ../tests/pe-loader/test_peloader.sh; \
	else \
		echo "  (no test script found - skipping)"; \
	fi

# --- Tools ---
tools:
	$(CC) $(CFLAGS) -o tools/pe_dump tools/pe_dump.c $(LDFLAGS)

# --- Install ---
install: all
	install -Dm755 loader/peloader $(DESTDIR)$(BIN_DIR)/peloader
	install -d $(DESTDIR)$(LIB_DIR)
	install -m755 dlls/libpe_*.so $(DESTDIR)$(LIB_DIR)/

# --- Clean ---
clean:
	rm -f loader/peloader loader/*.o loader/*.d
	rm -f dlls/*/*.o dlls/*/*.d dlls/*.so
	rm -f graphics/*.o graphics/*.d
	rm -f registry/*.o registry/*.d
	rm -f tools/pe_dump tools/*.o tools/*.d
	rm -f kernel/*.o kernel/*.ko kernel/*.mod* kernel/.*.cmd
	rm -rf kernel/.tmp_versions kernel/Module.symvers kernel/modules.order

# --- Auto-generated header dependencies (from -MMD -MP) ---
# -include silences the error when .d files don't exist yet on a fresh checkout.
# Correct incremental rebuilds: changing a single header only recompiles TUs
# that actually include it, NOT the whole tree.
-include $(shell find loader dlls graphics registry tools -name '*.d' 2>/dev/null)

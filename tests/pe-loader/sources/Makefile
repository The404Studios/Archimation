# Makefile -- Cross-compile PE corpus binaries via MinGW.
#
# Each target is a hand-written .c file we OWN (BSD-style permissive).
# Build is tolerant: if MinGW is absent, `make` exits with a friendly
# message and skip-status (77).  Each binary is independent; one failed
# compile does not block the others (handled by run_corpus.sh).
#
# Usage:
#   make              # build all binaries that compile
#   make clean        # remove all .exe outputs
#   make BIN.exe      # build one specific binary

# NB: use 'override' on CC because make's built-in 'CC = cc' shadows ?= and
# would otherwise pick the host gcc, which can't link Win32 import libs.
override CC := x86_64-w64-mingw32-gcc
CFLAGS      ?= -O0 -g -Wall -Wextra -Wno-unused-parameter
LDFLAGS     ?= -static-libgcc

# Per-target link libraries.  Each target overrides LIBS.
LIBS_console_hello    = -lmsvcrt
LIBS_console_files    = -lkernel32 -lmsvcrt
LIBS_console_threads  = -lkernel32 -lmsvcrt
LIBS_console_socket   = -lws2_32 -lmsvcrt
LIBS_console_registry = -ladvapi32 -lmsvcrt
LIBS_gui_window       = -luser32 -lkernel32 -lmsvcrt
LIBS_gui_text         = -lgdi32 -luser32 -lkernel32 -lmsvcrt
LIBS_gui_resource     = -luser32 -lkernel32 -lmsvcrt
LIBS_com_inproc       = -lole32 -loleaut32 -luuid -lkernel32 -lmsvcrt
LIBS_service_hello    = -ladvapi32 -lkernel32 -lmsvcrt

# Session 67 corpus extension -- exercises Sessions 65-66 surface area.
LIBS_wmi_query        = -lole32 -loleaut32 -luuid -lkernel32 -lmsvcrt
LIBS_com_dispatch     = -lole32 -loleaut32 -luuid -lkernel32 -lmsvcrt
LIBS_cross_handle     = -lkernel32 -lmsvcrt

# Session 68 corpus extension -- exercises S67/S68 regression fixes.
LIBS_registry_signext = -ladvapi32 -lmsvcrt
LIBS_font_render      = -lgdi32 -luser32 -lkernel32 -lmsvcrt
LIBS_listview_columns = -lcomctl32 -luser32 -lgdi32 -lkernel32 -lmsvcrt

BINS = \
    console_hello.exe \
    console_files.exe \
    console_threads.exe \
    console_socket.exe \
    console_registry.exe \
    gui_window.exe \
    gui_text.exe \
    gui_resource.exe \
    com_inproc.exe \
    service_hello.exe

# Session 67 binaries (built with the same MinGW toolchain as BINS).
NEW_BINS = \
    wmi_query.exe \
    com_dispatch.exe \
    cross_handle.exe

# Session 68 binaries -- regression guards for S67/S68 fixes.
S68_BINS = \
    registry_signext.exe \
    font_render.exe \
    listview_columns.exe

# .NET PE -- requires Mono mcs.  Optional; gracefully skipped if absent.
DOTNET_BINS = dotnet_hello.exe

# .ps1 is not a PE -- it's a static source that ships as-is and is
# invoked by run_corpus.sh via `pwsh -File`.  Listed for `make list`.
SCRIPT_BINS = powershell_hello.ps1

.PHONY: all clean check-toolchain dotnet ps1

all: check-toolchain $(BINS) $(NEW_BINS) $(S68_BINS) dotnet ps1

check-toolchain:
	@command -v $(CC) >/dev/null 2>&1 || { \
	    echo "Makefile: $(CC) not on PATH; corpus build SKIPPED"; \
	    echo "  Install with: pacman -S mingw-w64-gcc (Arch)"; \
	    exit 77; \
	}

# Pattern rule: each .exe links against its category-specific LIBS_xxx.
%.exe: %.c
	@printf "  CC    %s\n" "$@"
	@$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS_$*) || \
	    echo "  FAIL  $@ (continuing)"

# gui_window is GUI-subsystem so it doesn't pop a console on Windows.
# Under our PE loader on Linux it's irrelevant, but we set it anyway
# to match production binaries.
gui_window.exe: gui_window.c
	@printf "  CC    %s (GUI subsystem)\n" "$@"
	@$(CC) $(CFLAGS) -mwindows -o $@ $< $(LDFLAGS) $(LIBS_gui_window) || \
	    echo "  FAIL  $@ (continuing)"

# --- .NET target (Session 67) -------------------------------------------
# Build dotnet_hello.exe via the Mono compiler.  If mcs is absent we
# print a friendly message and exit 0 so the rest of the corpus still
# builds; run_corpus.sh will report the binary as SKIP.
dotnet: dotnet_hello.exe

dotnet_hello.exe: dotnet_hello.cs
	@if command -v mcs >/dev/null 2>&1; then \
	    printf "  MCS   %s\n" "$@"; \
	    mcs -platform:x64 -out:$@ $< || echo "  FAIL  $@ (continuing)"; \
	elif command -v csc >/dev/null 2>&1; then \
	    printf "  CSC   %s\n" "$@"; \
	    csc -platform:x64 -out:$@ $< || echo "  FAIL  $@ (continuing)"; \
	else \
	    echo "  SKIP  $@ (mcs/csc absent — install mono or dotnet-sdk)"; \
	fi

# --- PowerShell passthrough (Session 67) --------------------------------
# .ps1 has no compile step; this target only exists so `make` doesn't
# complain and so `make list` shows it.
ps1:
	@printf "  KEEP  powershell_hello.ps1 (no build step)\n"

clean:
	rm -f $(BINS) $(NEW_BINS) $(S68_BINS) $(DOTNET_BINS)

# Diagnostic helpers
list:
	@echo "C targets:      $(BINS) $(NEW_BINS) $(S68_BINS)"
	@echo "DOTNET targets: $(DOTNET_BINS)"
	@echo "Script files:   $(SCRIPT_BINS)"

info:
	@echo "CC      = $(CC)"
	@echo "CFLAGS  = $(CFLAGS)"
	@echo "LDFLAGS = $(LDFLAGS)"
	@$(CC) --version 2>/dev/null | head -1 || echo "(no $(CC))"

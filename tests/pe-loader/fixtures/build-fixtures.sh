#!/bin/bash
#
# build-fixtures.sh -- Cross-compile tiny_* PE32+ test fixtures.
#
# Produces three .exe binaries next to this script:
#   tiny_exit42.exe       -- simplest PE; ExitProcess(42)
#   tiny_console.exe      -- kernel32 WriteFile + msvcrt printf
#   tiny_messagebox.exe   -- user32 MessageBoxA (GUI subsystem)
#
# Deterministic flags:
#   -O2 -s            strip symbols for reproducible size
#   -nostdlib         no CRT link for tiny_exit42 / tiny_messagebox
#   -nostartfiles     CRT linked but entry point is _start (tiny_console)
#   -Wl,--entry=_start  explicit entry so mainCRTStartup isn't pulled in
#   -Wl,--build-id=none suppress random build-id so rebuilds are byte-identical
#
# Usage:
#   ./build-fixtures.sh            # build all three
#   ./build-fixtures.sh clean      # remove .exe outputs
#
# Requirements:
#   x86_64-w64-mingw32-gcc  (Arch: mingw-w64-gcc; Debian: gcc-mingw-w64-x86-64)
#
# If mingw is not installed, exits with status 77 (automake "skip") and a
# single-line error, so callers/CI can treat this as "not tested" rather
# than a hard failure.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CC="${CC:-x86_64-w64-mingw32-gcc}"

# Common deterministic flags. -Wl,--no-insert-timestamp zeroes the PE
# timestamp field so two builds of the same source produce byte-identical
# output (critical because the .exe files are checked in).
COMMON_CFLAGS="-O2 -s -Wl,--build-id=none -Wl,--no-insert-timestamp"

if [[ "${1:-}" == "clean" ]]; then
    rm -f "$HERE"/tiny_exit42.exe "$HERE"/tiny_console.exe "$HERE"/tiny_messagebox.exe
    echo "cleaned fixture .exe outputs"
    exit 0
fi

# Detect toolchain.
if ! command -v "$CC" >/dev/null 2>&1; then
    echo "build-fixtures.sh: $CC not found; skipping fixture build." >&2
    echo "  Install with:  pacman -S mingw-w64-gcc   (Arch)" >&2
    echo "  or:            apt install gcc-mingw-w64-x86-64   (Debian)" >&2
    exit 77  # automake "skip" exit code
fi

cd "$HERE"

build() {
    local src="$1"
    local out="$2"
    shift 2
    local extra_flags=("$@")

    echo "  CC    $out"
    # shellcheck disable=SC2086
    "$CC" $COMMON_CFLAGS "${extra_flags[@]}" -o "$out" "$src"

    # Sanity check: must be PE32+ (0x8664 = AMD64).
    # hexdump of offset 4 of the PE header gives the machine type.
    if ! file "$out" | grep -q "PE32+"; then
        echo "ERROR: $out is not PE32+!" >&2
        file "$out" >&2
        exit 1
    fi
}

echo "=== Building PE test fixtures ==="

# NOTE on -nostartfiles vs -nostdlib:
#   -nostdlib drops both startup files AND default library search paths,
#   which means kernel32/user32 import libs can't be found. We use
#   -nostartfiles so the mingw lib search paths are preserved but the
#   CRT startup wrapper (mainCRTStartup) isn't pulled in.

# tiny_exit42.exe: no CRT, single kernel32 import.
build tiny_exit42.c tiny_exit42.exe \
    -nostartfiles -Wl,--entry=_start -lkernel32

# tiny_console.exe: uses both kernel32 and msvcrt.
build tiny_console.c tiny_console.exe \
    -nostartfiles -Wl,--entry=_start -lkernel32 -lmsvcrt

# tiny_messagebox.exe: GUI subsystem, user32 import.
# -mwindows sets IMAGE_SUBSYSTEM_WINDOWS_GUI (subsystem=2) in the PE header.
build tiny_messagebox.c tiny_messagebox.exe \
    -nostartfiles -mwindows -Wl,--entry=_start -lkernel32 -luser32

echo ""
echo "=== Fixture sizes ==="
ls -l "$HERE"/*.exe

echo ""
echo "=== File types ==="
for f in "$HERE"/*.exe; do
    printf "  %-28s %s\n" "$(basename "$f")" "$(file -b "$f")"
done

echo ""
echo "Done. Fixtures in: $HERE"

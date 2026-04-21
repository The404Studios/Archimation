#!/bin/bash
#
# test_fixtures.sh -- Run the tiny_* PE fixtures through peloader and
#                     assert exit codes / stdout markers.
#
# Ran directly on a system where peloader is installed (typically in the
# QEMU test VM via run-pe-tests.sh). Exit 0 iff all required tests pass.
#
# Reports pass/fail counts on stdout. Returns the count of failed tests
# as the process exit code (capped at 125).

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES_DIR="$HERE/fixtures"

PELOADER="${PELOADER:-peloader}"
PASS=0
FAIL=0
SKIP=0

if ! command -v "$PELOADER" >/dev/null 2>&1; then
    echo "test_fixtures.sh: $PELOADER not found on PATH" >&2
    exit 2
fi

have_fixture() {
    local f="$FIXTURES_DIR/$1"
    if [[ ! -f "$f" ]]; then
        echo "  [SKIP] $1 (fixture missing; run build-fixtures.sh)"
        SKIP=$((SKIP + 1))
        return 1
    fi
    return 0
}

# --- Test 1: tiny_exit42.exe --- must exit 42. ---------------------------
echo "=== tiny_exit42.exe (ExitProcess(42)) ==="
if have_fixture tiny_exit42.exe; then
    set +e
    "$PELOADER" "$FIXTURES_DIR/tiny_exit42.exe" >/dev/null 2>&1
    rc=$?
    set -e
    if [[ $rc -eq 42 ]]; then
        echo "  [PASS] exit code = 42"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] expected 42, got $rc"
        FAIL=$((FAIL + 1))
    fi
fi

# --- Test 2: tiny_console.exe --- must print marker + exit 0. -----------
echo "=== tiny_console.exe (kernel32+msvcrt stdio) ==="
if have_fixture tiny_console.exe; then
    set +e
    out=$("$PELOADER" "$FIXTURES_DIR/tiny_console.exe" 2>&1)
    rc=$?
    set -e
    if [[ $rc -eq 0 ]]; then
        echo "  [PASS] exit code = 0"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] expected exit 0, got $rc"
        FAIL=$((FAIL + 1))
    fi
    # Marker check is independent of exit-code check.
    if grep -q "Hello from PE!" <<< "$out"; then
        echo "  [PASS] stdout contains 'Hello from PE!'"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] marker 'Hello from PE!' not in output"
        echo "  --- captured output ---"
        printf '%s\n' "$out" | sed 's/^/    /'
        echo "  -----------------------"
        FAIL=$((FAIL + 1))
    fi
fi

# --- Test 3: tiny_messagebox.exe --- GUI path. --------------------------
# Two acceptable outcomes:
#   a) DISPLAY set or headless-stub works:   exit 0 (or 1 if stub returned 0)
#   b) user32 stub missing MessageBoxA:      loader prints "unresolved
#      import"; exit != 0 but the error is structured.
# We pass if EITHER (a) the exe ran to ExitProcess OR (b) the loader
# reported a specific unresolved-import error.
echo "=== tiny_messagebox.exe (user32 GUI path) ==="
if have_fixture tiny_messagebox.exe; then
    set +e
    out=$("$PELOADER" "$FIXTURES_DIR/tiny_messagebox.exe" 2>&1)
    rc=$?
    set -e
    if [[ $rc -eq 0 || $rc -eq 1 ]]; then
        echo "  [PASS] MessageBoxA returned (exit $rc)"
        PASS=$((PASS + 1))
    elif grep -qiE "unresolved import.*messagebox|messagebox.*unresolved" <<< "$out"; then
        echo "  [PASS] reported specific unresolved-import error (structured failure)"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] unexpected exit $rc and no unresolved-import message"
        echo "  --- captured output ---"
        printf '%s\n' "$out" | sed 's/^/    /'
        echo "  -----------------------"
        FAIL=$((FAIL + 1))
    fi
fi

# --- Summary ------------------------------------------------------------
echo ""
echo "=== Fixture test summary: $PASS passed, $FAIL failed, $SKIP skipped ==="

if [[ $FAIL -gt 125 ]]; then
    exit 125
fi
exit $FAIL

#!/bin/bash
# test_peloader.sh - Test the PE loader with hello.exe
#
# Runs inside the Arch Linux environment (VM or native).
# Requires: peloader binary in PATH or ../../pe-loader/peloader
#
# Usage: bash test_peloader.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HELLO_EXE="${SCRIPT_DIR}/hello.exe"
PE_LOADER="${SCRIPT_DIR}/../../pe-loader/loader/peloader"

# Find peloader
if [ ! -f "$PE_LOADER" ]; then
    PE_LOADER=$(which peloader 2>/dev/null || echo "")
fi

if [ -z "$PE_LOADER" ] || [ ! -f "$PE_LOADER" ]; then
    echo "ERROR: peloader not found"
    echo "  Expected at: ${SCRIPT_DIR}/../../pe-loader/loader/peloader"
    echo "  Or install it to PATH"
    exit 1
fi

if [ ! -f "$HELLO_EXE" ]; then
    echo "ERROR: hello.exe not found at ${HELLO_EXE}"
    exit 1
fi

echo "=== PE Loader Integration Test ==="
echo ""
echo "PE Loader: ${PE_LOADER}"
echo "Test binary: ${HELLO_EXE}"
echo "Binary size: $(stat -c %s "$HELLO_EXE" 2>/dev/null || stat -f %z "$HELLO_EXE" 2>/dev/null) bytes"
echo ""

PASS=0
FAIL=0

# Test 1: peloader --help should work
echo -n "  [1] peloader --help: "
if "${PE_LOADER}" --help 2>&1 | grep -q "PE Loader"; then
    echo "PASS"
    PASS=$((PASS + 1))
else
    echo "FAIL"
    FAIL=$((FAIL + 1))
fi

# Test 2: peloader --version should work
echo -n "  [2] peloader --version: "
if "${PE_LOADER}" --version 2>&1 | grep -q "peloader"; then
    echo "PASS"
    PASS=$((PASS + 1))
else
    echo "FAIL"
    FAIL=$((FAIL + 1))
fi

# Test 3: Load and run hello.exe
echo -n "  [3] Run hello.exe: "
OUTPUT=$("${PE_LOADER}" -v "${HELLO_EXE}" 2>&1 || true)
if echo "$OUTPUT" | grep -q "Hello from PE!"; then
    echo "PASS"
    PASS=$((PASS + 1))
else
    echo "FAIL"
    FAIL=$((FAIL + 1))
    echo "    Output was:"
    echo "$OUTPUT" | head -20 | sed 's/^/    /'
fi

# Test 4: Exit code is 0
echo -n "  [4] Exit code 0: "
"${PE_LOADER}" "${HELLO_EXE}" > /dev/null 2>&1
EXIT_CODE=$?
if [ "$EXIT_CODE" -eq 0 ]; then
    echo "PASS"
    PASS=$((PASS + 1))
else
    echo "FAIL (exit code: ${EXIT_CODE})"
    FAIL=$((FAIL + 1))
fi

# Test 5: Verbose mode shows PE loading steps
echo -n "  [5] Verbose output shows steps: "
VERBOSE_OUT=$("${PE_LOADER}" -v "${HELLO_EXE}" 2>&1 || true)
STEPS_OK=1
for step in "Parsing PE headers" "Mapping sections" "Resolving imports"; do
    if ! echo "$VERBOSE_OUT" | grep -q "$step"; then
        STEPS_OK=0
        echo "FAIL (missing: $step)"
        FAIL=$((FAIL + 1))
        break
    fi
done
if [ "$STEPS_OK" -eq 1 ]; then
    echo "PASS"
    PASS=$((PASS + 1))
fi

# Test 6: Trust integration (if /dev/trust exists)
echo -n "  [6] Trust registration: "
if [ -c /dev/trust ]; then
    TRUST_OUT=$("${PE_LOADER}" -v "${HELLO_EXE}" 2>&1 || true)
    if echo "$TRUST_OUT" | grep -q "Trust:"; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL (no Trust output with /dev/trust present)"
        FAIL=$((FAIL + 1))
    fi
else
    echo "SKIP (no /dev/trust)"
fi

echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="

exit $FAIL

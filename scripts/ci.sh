#!/bin/bash
# ci.sh - Full validation pipeline for ai-arch-linux.
#
# Runs six steps in sequence. Each step:
#   - Writes to logs/ci-<step>-<timestamp>.log
#   - Emits one PASS / FAIL / SKIP line to stdout
#   - Contributes to pass/fail/skip counts
#
# Exit codes:
#   0   - all steps PASS (or PASS+SKIP)
#   1   - at least one step FAILED
#   77  - POSIX "skip all" (only if every runnable step was skipped)
#
# Environment:
#   CI_QUICK=1     - Skip the ISO build and QEMU steps (short CI run).
#   CI_SKIP_QEMU=1 - Skip only the QEMU smoke test (e.g. on GitHub free tier).
#   CI_SKIP_ISO=1  - Skip the ISO build (implies CI_SKIP_QEMU).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_DIR="$PROJECT_DIR/logs"
TS="$(date -u +%Y%m%dT%H%M%SZ)"

mkdir -p "$LOG_DIR"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
FAILED_STEPS=()

# CI_QUICK implies both ISO and QEMU skip.
if [ "${CI_QUICK:-0}" = "1" ]; then
    CI_SKIP_ISO=1
    CI_SKIP_QEMU=1
fi
# Skipping ISO forces QEMU to also skip (nothing to boot).
if [ "${CI_SKIP_ISO:-0}" = "1" ]; then
    CI_SKIP_QEMU=1
fi

_log_path() {
    printf '%s/ci-%s-%s.log' "$LOG_DIR" "$1" "$TS"
}

# run_step NAME SKIP_VAR CMD [ARGS...]
# SKIP_VAR is the name of an env var; if set to "1" the step is skipped.
# Pass empty string "" to disable skip-gating.
run_step() {
    local name="$1"; shift
    local skip_var="$1"; shift
    local log_file
    log_file="$(_log_path "$name")"

    if [ -n "$skip_var" ]; then
        local skip_val="${!skip_var:-0}"
        if [ "$skip_val" = "1" ]; then
            echo "SKIP: $name (${skip_var}=1)" | tee -a "$log_file"
            SKIP_COUNT=$((SKIP_COUNT + 1))
            return 0
        fi
    fi

    local t0 t1 rc
    t0=$(date +%s)
    echo "=== [$(date -u +%H:%M:%SZ)] BEGIN $name ===" | tee -a "$log_file"
    # Use a subshell so per-step failures don't abort the whole pipeline.
    (
        cd "$PROJECT_DIR"
        "$@"
    ) >>"$log_file" 2>&1
    rc=$?
    t1=$(date +%s)

    if [ $rc -eq 77 ]; then
        echo "SKIP: $name (preconditions not met, exit 77) — log: $log_file"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        return 0
    fi

    if [ $rc -eq 0 ]; then
        echo "PASS: $name (${t1}s - ${t0}s = $((t1 - t0))s) — log: $log_file"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "FAIL: $name (rc=$rc, $((t1 - t0))s) — log: $log_file"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_STEPS+=("$name")
    fi
    return 0
}

# ── Step implementations ────────────────────────────────────────────────────

step_pysyntax() {
    # Compile every .py under ai-control/ and tests/. Fails on any SyntaxError.
    local py
    if ! command -v python3 >/dev/null 2>&1; then
        echo "python3 not found"
        return 77
    fi
    local files=()
    while IFS= read -r -d '' py; do
        files+=("$py")
    done < <(find ai-control tests -type f -name '*.py' -print0 2>/dev/null)
    if [ ${#files[@]} -eq 0 ]; then
        echo "no .py files found under ai-control/ or tests/"
        return 77
    fi
    echo "Checking ${#files[@]} Python files..."
    python3 -m py_compile "${files[@]}"
}

step_shellsyntax() {
    # bash -n every scripts/*.sh — catches typos without executing.
    local sh
    local failed=0
    local total=0
    for sh in scripts/*.sh; do
        [ -f "$sh" ] || continue
        total=$((total + 1))
        if ! bash -n "$sh"; then
            echo "FAIL $sh"
            failed=$((failed + 1))
        fi
    done
    echo "Checked $total scripts, $failed failed."
    [ $failed -eq 0 ]
}

step_cbuild() {
    # All C modules. Each sub-build logs inline; we rely on exit code.
    if ! command -v make >/dev/null 2>&1 || ! command -v gcc >/dev/null 2>&1; then
        echo "make or gcc not available — cannot build C sources"
        return 77
    fi
    local any_built=0
    local rc=0

    if [ -f trust/lib/Makefile ]; then
        echo "--- trust/lib ---"
        make -C trust/lib || rc=$?
        any_built=1
    fi
    if [ -f coherence/daemon/Makefile ]; then
        echo "--- coherence/daemon ---"
        make -C coherence/daemon || rc=$?
        any_built=1
    fi
    if [ -f services/Makefile ]; then
        echo "--- services ---"
        make -C services || rc=$?
        any_built=1
    fi
    if [ -f pe-loader/Makefile ]; then
        echo "--- pe-loader ---"
        make -C pe-loader || rc=$?
        any_built=1
    fi

    if [ $any_built -eq 0 ]; then
        echo "No C Makefiles found"
        return 77
    fi
    return $rc
}

step_packages() {
    if ! command -v makepkg >/dev/null 2>&1; then
        echo "makepkg not available (not on Arch)"
        return 77
    fi
    bash scripts/build-packages.sh
}

step_iso() {
    if ! command -v mkarchiso >/dev/null 2>&1; then
        echo "mkarchiso not available"
        return 77
    fi
    if [ "$(id -u)" != "0" ] && ! sudo -n true 2>/dev/null; then
        echo "mkarchiso requires root or passwordless sudo"
        return 77
    fi
    bash scripts/build-iso.sh
}

step_qemu() {
    if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
        echo "qemu-system-x86_64 not available"
        return 77
    fi
    # Bail if no ISO was produced.
    if ! ls output/*.iso >/dev/null 2>&1; then
        echo "No ISO present in output/ — cannot smoke test"
        return 77
    fi
    bash scripts/test-qemu.sh
}

# ── Driver ──────────────────────────────────────────────────────────────────

echo "========================================"
echo " ai-arch-linux CI pipeline"
echo " project : $PROJECT_DIR"
echo " logs    : $LOG_DIR"
echo " ts      : $TS"
echo " flags   : CI_QUICK=${CI_QUICK:-0} CI_SKIP_ISO=${CI_SKIP_ISO:-0} CI_SKIP_QEMU=${CI_SKIP_QEMU:-0}"
echo "========================================"

run_step pysyntax     ""              step_pysyntax
run_step shellsyntax  ""              step_shellsyntax
run_step cbuild       ""              step_cbuild
run_step packages     ""              step_packages
run_step iso          CI_SKIP_ISO     step_iso
run_step qemu         CI_SKIP_QEMU    step_qemu

echo "========================================"
echo " SUMMARY: PASS=$PASS_COUNT FAIL=$FAIL_COUNT SKIP=$SKIP_COUNT"
if [ $FAIL_COUNT -gt 0 ]; then
    echo " Failed steps: ${FAILED_STEPS[*]}"
fi
echo "========================================"

if [ $FAIL_COUNT -gt 0 ]; then
    exit 1
fi
# All runnable steps skipped — POSIX-style "nothing ran" signal.
if [ $PASS_COUNT -eq 0 ] && [ $SKIP_COUNT -gt 0 ]; then
    exit 77
fi
exit 0

#!/bin/bash
#
# run-real-pe-tests.sh -- Exercise the PE loader against real-world
# open-source Windows binaries fetched by fetch-real-pe-binaries.sh.
#
# Session 41 / Agent 3: the prior in-tree fixtures were synthetic
# (one hello.exe + three MinGW stubs). This harness complements them
# by loading real binaries compiled by real toolchains (MinGW-w64,
# MSVC) with real import tables. We care about LOADING, not about
# correctness of business logic; a binary that gets far enough to
# print a usage message, --version string, or a specific runtime
# error has exercised the full PE parse + section map + reloc +
# import-resolve pipeline.
#
# Usage:
#   bash scripts/run-real-pe-tests.sh [--peloader=<path>]
#                                     [--bin-dir=<path>]
#                                     [--remote]
#                                     [--no-fetch]
#
# --peloader       Path to peloader binary (default: look up PATH, then
#                  pe-loader/loader/peloader relative to repo).
# --bin-dir        Where the real binaries live (default:
#                  tests/pe-loader/real-binaries/ at repo root).
# --remote         Run the tests in the QEMU VM via SSH on port 2222
#                  (mirrors run-pe-tests.sh's model).
# --no-fetch       Assume binaries are already present; skip the fetch
#                  step.
#
# Exit codes:
#   0   all binaries PASSED or PARTIAL
#   1   at least one binary FAILED (PE format / unresolved imports)
#   2   peloader not found
#   77  binaries not present and offline (propagated from fetch script)
#
# Result classes:
#   PASS     -- peloader loaded the binary AND it ran long enough to
#               produce stdout/stderr (or to exit non-crashily on a
#               benign arg). Import resolution succeeded.
#   PARTIAL  -- Import resolution succeeded, binary started executing,
#               but crashed / hit SEH / got killed by signal during run.
#               Still means the loader did its job; runtime shim is
#               what's incomplete.
#   FAIL     -- Loader bailed: PE format error, unresolved imports,
#               mapping failure, etc. The loader itself did not accept
#               the binary.

set -uo pipefail

# -----------------------------------------------------------------------
# Paths + args
# -----------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DEFAULT_BIN_DIR="$PROJECT_DIR/tests/pe-loader/real-binaries"

PELOADER=""
BIN_DIR="$DEFAULT_BIN_DIR"
REMOTE=0
NO_FETCH=0

for arg in "$@"; do
    case "$arg" in
        --peloader=*)   PELOADER="${arg#*=}" ;;
        --bin-dir=*)    BIN_DIR="${arg#*=}" ;;
        --remote)       REMOTE=1 ;;
        --no-fetch)     NO_FETCH=1 ;;
        -h|--help)
            sed -n '3,40p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "run-real-pe-tests.sh: unknown arg '$arg'" >&2
            exit 2
            ;;
    esac
done

# -----------------------------------------------------------------------
# Fetch step (local mode only -- remote VM caller does its own copy)
# -----------------------------------------------------------------------
if [[ "$NO_FETCH" -eq 0 && "$REMOTE" -eq 0 ]]; then
    if [[ -x "$SCRIPT_DIR/fetch-real-pe-binaries.sh" ]]; then
        set +e
        bash "$SCRIPT_DIR/fetch-real-pe-binaries.sh"
        fetch_rc=$?
        set -e
        if [[ $fetch_rc -eq 77 ]]; then
            echo "[run-real-pe] offline; SKIP entire real-binary suite"
            exit 77
        fi
        if [[ $fetch_rc -ne 0 ]]; then
            echo "[run-real-pe] fetch returned $fetch_rc -- some binaries may be missing"
            # Don't abort; we still want to run whatever IS present.
        fi
    fi
fi

# -----------------------------------------------------------------------
# Locate peloader
# -----------------------------------------------------------------------
if [[ "$REMOTE" -eq 0 ]]; then
    if [[ -z "$PELOADER" ]]; then
        if command -v peloader >/dev/null 2>&1; then
            PELOADER="$(command -v peloader)"
        elif [[ -x "$PROJECT_DIR/pe-loader/loader/peloader" ]]; then
            PELOADER="$PROJECT_DIR/pe-loader/loader/peloader"
        fi
    fi
    if [[ -z "$PELOADER" || ! -x "$PELOADER" ]]; then
        echo "[run-real-pe] ERROR: peloader not found" >&2
        exit 2
    fi
fi

# -----------------------------------------------------------------------
# Test matrix
# -----------------------------------------------------------------------
# Each entry: <binary>|<args>|<note>
# <args> is what we pass after the exe name. Keep it side-effect free
# (--help / --version / no I/O).
TESTS=(
    "busybox64.exe|--help|Single-exe Unix tools (kernel32+msvcrt)"
    "curl.exe|--version|HTTP client (kernel32+ws2_32+crypt32+advapi32)"
    "rg.exe|--version|ripgrep (kernel32+ntdll+advapi32+userenv+bcrypt)"
    "7zr.exe||7-Zip decompressor usage dump (kernel32+user32+ole32)"
    "nasm.exe|-v|NASM assembler (kernel32+msvcrt only)"
)

# -----------------------------------------------------------------------
# Result accumulators
# -----------------------------------------------------------------------
RESULTS=()   # "<name>|<verdict>|<unresolved>|<stdout200>|<stderr200>"
PASS=0
PARTIAL=0
FAIL=0
SKIP=0

# -----------------------------------------------------------------------
# Runner
# -----------------------------------------------------------------------
# Capture first 200 chars of stdout/stderr so that big help dumps don't
# explode the report. Newlines in the captured text are replaced with
# \n literals in the matrix row (so the row stays one line).
truncate_stream() {
    # stdin -> up-to-200-char sanitized single-line
    head -c 200 | tr '\n\r\t' '   ' | sed 's/  */ /g'
}

# Extract the first "unresolved import" diagnostic from stderr, if any.
# peloader phrases it a couple of ways; match generously.
first_unresolved() {
    local errtxt="$1"
    # Try ordered patterns; stop on first hit.
    local line
    line=$(printf '%s\n' "$errtxt" | grep -m1 -iE 'unresolved import|import not found|missing export|undefined symbol' || true)
    if [[ -z "$line" ]]; then
        echo ""
        return
    fi
    # Trim leading whitespace + truncate.
    printf '%s' "$line" | sed 's/^[[:space:]]*//' | head -c 120
}

run_one() {
    local exe="$1" args="$2" note="$3"
    local path="$BIN_DIR/$exe"
    local verdict unresolved stdout_trim stderr_trim

    if [[ ! -f "$path" ]]; then
        RESULTS+=("$exe|SKIP|missing||$note")
        SKIP=$((SKIP + 1))
        echo "  [SKIP] $exe ($note) -- not present"
        return
    fi

    echo "  [RUN ] $exe $args  ($note)"

    # Run with a hard timeout so runaway binaries don't hang CI.
    local tmpout tmperr rc
    tmpout=$(mktemp); tmperr=$(mktemp)

    # shellcheck disable=SC2086
    # We want word-splitting of $args here.
    set +e
    if [[ -n "$args" ]]; then
        timeout --signal=KILL 20 "$PELOADER" "$path" $args \
            >"$tmpout" 2>"$tmperr"
    else
        timeout --signal=KILL 20 "$PELOADER" "$path" \
            >"$tmpout" 2>"$tmperr"
    fi
    rc=$?
    set -e

    local errtxt; errtxt=$(cat "$tmperr")
    unresolved=$(first_unresolved "$errtxt")
    stdout_trim=$(truncate_stream < "$tmpout")
    stderr_trim=$(truncate_stream < "$tmperr")

    # --- Classification ----------------------------------------------
    # FAIL if loader bailed before running: unresolved imports, PE
    # parse errors, mapping failures. These produce loader-side stderr
    # with specific keywords and typically rc=1 or rc=2.
    if [[ -n "$unresolved" ]] \
       || grep -qiE 'PE format|invalid PE|magic mismatch|not a PE|DOS header|mapping failed|reloc failed' <<< "$errtxt"; then
        verdict="FAIL"
        FAIL=$((FAIL + 1))
    elif [[ $rc -eq 124 || $rc -eq 137 ]]; then
        # SIGKILL/timeout -- loader got the binary running but it
        # hung (probably waiting on input, networking, or a shim
        # that never returns). That's PARTIAL.
        verdict="PARTIAL"
        PARTIAL=$((PARTIAL + 1))
    elif [[ $rc -eq 139 || $rc -eq 134 || $rc -eq 136 || $rc -eq 135 ]]; then
        # SEGV / ABRT / FPE / BUS -- import tables resolved but a
        # runtime shim lied about its semantics and the guest tripped.
        verdict="PARTIAL"
        PARTIAL=$((PARTIAL + 1))
    else
        # Anything else -- including rc != 0 from the guest's own
        # error handling (e.g. curl --version returns 0, but a guest
        # that exits 1 on an unknown arg still loaded fine).
        verdict="PASS"
        PASS=$((PASS + 1))
    fi

    RESULTS+=("$exe|$verdict|$unresolved|$stdout_trim|$stderr_trim")
    echo "         -> $verdict (rc=$rc)"

    rm -f "$tmpout" "$tmperr"
}

# -----------------------------------------------------------------------
# Local-run loop
# -----------------------------------------------------------------------
if [[ "$REMOTE" -eq 0 ]]; then
    echo "=== Real-world PE binary suite ==="
    echo "peloader: $PELOADER"
    echo "bin-dir:  $BIN_DIR"
    echo ""

    for entry in "${TESTS[@]}"; do
        IFS='|' read -r exe args note <<< "$entry"
        run_one "$exe" "$args" "$note"
    done
else
    # -------------------------------------------------------------------
    # Remote (QEMU) path: copy binaries + this script + run from there.
    # Caller in run-pe-tests.sh already has SSH set up; we just wrap.
    # -------------------------------------------------------------------
    SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
    SSH_CMD="sshpass -p root ssh $SSH_OPTS root@127.0.0.1 -p 2222"
    SCP_CMD="sshpass -p root scp $SSH_OPTS -P 2222"

    echo "=== Real-world PE binary suite (remote QEMU) ==="
    $SSH_CMD "mkdir -p /tmp/pe-test/real-binaries"

    # Copy only the .exe files (not SHA256SUMS; not .gitignore).
    shopt -s nullglob
    copied=0
    for f in "$BIN_DIR"/*.exe; do
        name=$(basename "$f")
        echo "  Copying real-binaries/$name..."
        $SCP_CMD "$f" "root@127.0.0.1:/tmp/pe-test/real-binaries/$name"
        copied=$((copied + 1))
    done
    shopt -u nullglob

    if [[ $copied -eq 0 ]]; then
        echo "  (no binaries in $BIN_DIR -- skipping remote run)"
        exit 77
    fi

    # Copy this script over and re-invoke in local mode inside the VM.
    $SCP_CMD "$0" root@127.0.0.1:/tmp/pe-test/run-real-pe-tests.sh
    $SSH_CMD "chmod +x /tmp/pe-test/run-real-pe-tests.sh"
    $SSH_CMD "PE_COMPAT_DLL_PATH=/usr/lib/pe-compat \
              bash /tmp/pe-test/run-real-pe-tests.sh \
              --peloader=\$(command -v peloader) \
              --bin-dir=/tmp/pe-test/real-binaries \
              --no-fetch"
    exit $?
fi

# -----------------------------------------------------------------------
# Matrix report
# -----------------------------------------------------------------------
echo ""
echo "=== Real-world PE binary results ==="
printf '  %-16s  %-8s  %-40s  %s\n' "BINARY" "VERDICT" "FIRST-UNRESOLVED" "STDOUT (first 200 chars)"
printf '  %-16s  %-8s  %-40s  %s\n' "----------------" "--------" "----------------------------------------" "----------------------------------------"
for row in "${RESULTS[@]}"; do
    IFS='|' read -r name verdict unresolved stdout_trim _ <<< "$row"
    # Pad / clip the columns.
    u="${unresolved:-—}"
    [[ ${#u} -gt 40 ]] && u="${u:0:37}..."
    o="${stdout_trim:-—}"
    [[ ${#o} -gt 60 ]] && o="${o:0:57}..."
    printf '  %-16s  %-8s  %-40s  %s\n' "$name" "$verdict" "$u" "$o"
done
echo ""
echo "  Totals: PASS=$PASS  PARTIAL=$PARTIAL  FAIL=$FAIL  SKIP=$SKIP"
echo ""

# Exit code: nonzero iff any FAIL.
if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
exit 0

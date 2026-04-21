#!/bin/bash
# run_corpus.sh -- Exercise every test binary through the PE loader.
#
# Output: PASS / FAIL / SKIP per binary + summary tally + JSON file.
#
# Exit codes:
#   0 -- all built binaries passed
#   1 -- one or more FAILed
#   2 -- no binaries available (toolchain absent or never built)
#
# Result JSON written to ${RESULT:-/tmp/pe_corpus_result.json}.
#
# Usage:
#   bash run_corpus.sh                # build (if needed) and run all
#   bash run_corpus.sh --no-build     # run-only; do not invoke make
#   bash run_corpus.sh --build-only   # build only; do not run

set +e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="${SCRIPT_DIR}/sources"
RESULT="${RESULT:-/tmp/pe_corpus_result.json}"

# Locate peloader.  Order: $PE_LOADER -> /usr/bin/peloader -> repo build.
LOADER="${PE_LOADER:-}"
if [ -z "$LOADER" ] || [ ! -x "$LOADER" ]; then
    LOADER=/usr/bin/peloader
fi
if [ ! -x "$LOADER" ]; then
    LOADER="${SCRIPT_DIR}/../../pe-loader/loader/peloader"
fi

DO_BUILD=1
DO_RUN=1
for arg in "$@"; do
    case "$arg" in
        --no-build) DO_BUILD=0 ;;
        --build-only) DO_RUN=0 ;;
        --help|-h)
            sed -n '2,16p' "$0"
            exit 0
            ;;
    esac
done

echo "=== PE Loader Corpus Runner ==="
echo "  loader:      $LOADER"
echo "  source dir:  $SRC_DIR"
echo "  result json: $RESULT"
echo ""

# --- Build phase ---------------------------------------------------------
if [ "$DO_BUILD" = "1" ]; then
    if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
        echo "--- Building corpus (make -C sources) ---"
        ( cd "$SRC_DIR" && make -k all 2>&1 ) | sed 's/^/  /'
        echo ""
    else
        echo "--- MinGW NOT FOUND; skipping build, will run pre-built binaries ---"
        echo ""
    fi
fi

if [ "$DO_RUN" = "0" ]; then
    echo "build-only mode; exit"
    exit 0
fi

# --- Loader presence check ----------------------------------------------
if [ ! -x "$LOADER" ]; then
    echo "ERROR: peloader binary not found at any of:"
    echo "  \$PE_LOADER (env)"
    echo "  /usr/bin/peloader"
    echo "  $SCRIPT_DIR/../../pe-loader/loader/peloader"
    echo ""
    echo "Will report all binaries as SKIP."
    LOADER=""
fi

# --- Per-binary spec ----------------------------------------------------
# Format:  binary_name|expectation|category
# expectation:
#   exit-zero       -- only validates rc == 0
#   outputs:STR     -- stdout/stderr must contain STR
#   outputs-any:A,B -- stdout/stderr must contain at least one of A or B
#   creates:PATH    -- file at PATH must exist after run (and is removed)
TESTS=(
    "console_hello.exe|outputs:CONSOLE_HELLO_OK|console-msvcrt"
    "console_files.exe|outputs:CONSOLE_FILES_OK|console-fileio"
    "console_threads.exe|outputs:CONSOLE_THREADS_OK|console-threading"
    "console_socket.exe|outputs:CONSOLE_SOCKET_OK|console-network"
    "console_registry.exe|outputs:CONSOLE_REGISTRY_OK|console-registry"
    "gui_window.exe|outputs-any:GUI_WINDOW_OK,GUI_WINDOW_STUB|gui-window"
    "gui_text.exe|outputs-any:GUI_TEXT_OK,GUI_TEXT_STUB|gui-gdi-freetype"
    "gui_resource.exe|outputs:GUI_RESOURCE_OK|gui-resource"
    "com_inproc.exe|outputs-any:COM_INPROC_OK,COM_INPROC_STUB|com-inproc"
    "service_hello.exe|outputs-any:SERVICE_HELLO_OK,SERVICE_HELLO_NOSCM|service-scm"
    # --- Session 67 corpus extension (S65/S66 surface area) ---
    "dotnet_hello.exe|outputs-any:DOTNET_HELLO_OK,DOTNET_HELLO_STUB|dotnet-mono-bridge"
    "wmi_query.exe|outputs-any:WMI_QUERY_OK,WMI_QUERY_STUB|wmi-provider"
    "com_dispatch.exe|outputs-any:COM_DISPATCH_OK,COM_DISPATCH_STUB|clr-metahost"
    "cross_handle.exe|outputs-any:CROSS_HANDLE_OK_PARENT,CROSS_HANDLE_STUB|handle-inheritance"
    "powershell_hello.ps1|outputs:POWERSHELL_HELLO_OK|powershell-passthrough"
    # --- Session 68 regression guards (S67/S68 fix surface) ---
    "registry_signext.exe|outputs-any:REGISTRY_SIGNEXT_OK,REGISTRY_SIGNEXT_STUB|registry-signext"
    "font_render.exe|outputs-any:FONT_RENDER_OK,FONT_RENDER_STUB|gdi-freetype-uaf"
    "listview_columns.exe|outputs-any:LISTVIEW_COLUMNS_OK,LISTVIEW_COLUMNS_STUB|comctl-listview-oob"
)

PASS=0
FAIL=0
SKIP=0
ERROR=0

# JSON accumulator (manual to avoid jq dependency).
JSON_RESULTS=""

run_test() {
    local name="$1"
    local expect="$2"
    local category="$3"
    local bin="$SRC_DIR/$name"

    if [ ! -f "$bin" ]; then
        echo "  [SKIP] $name (binary absent; build it with: make -C sources)"
        SKIP=$((SKIP + 1))
        JSON_RESULTS="$JSON_RESULTS{\"name\":\"$name\",\"category\":\"$category\",\"status\":\"SKIP\",\"reason\":\"binary-absent\"},"
        return
    fi

    # --- Special-case: .ps1 PowerShell scripts (Session 67 A9) -----------
    # Routed through pwsh directly; the loader is bypassed.  This mirrors
    # binfmt_misc behaviour on the live ISO where .ps1 is associated
    # with /usr/bin/pwsh.  If pwsh is absent on the host we SKIP cleanly.
    case "$name" in
        *.ps1)
            local pwsh_bin
            pwsh_bin="$(command -v pwsh 2>/dev/null)"
            if [ -z "$pwsh_bin" ]; then
                echo "  [SKIP] $name (pwsh absent on host)"
                SKIP=$((SKIP + 1))
                JSON_RESULTS="$JSON_RESULTS{\"name\":\"$name\",\"category\":\"$category\",\"status\":\"SKIP\",\"reason\":\"pwsh-absent\"},"
                return
            fi
            local out rc
            out=$(timeout 15 "$pwsh_bin" -NoProfile -File "$bin" 2>&1)
            rc=$?
            # Fall through to expectation matching with $out and $rc set.
            ;;
        *)
            if [ -z "$LOADER" ]; then
                echo "  [SKIP] $name (loader absent)"
                SKIP=$((SKIP + 1))
                JSON_RESULTS="$JSON_RESULTS{\"name\":\"$name\",\"category\":\"$category\",\"status\":\"SKIP\",\"reason\":\"loader-absent\"},"
                return
            fi

            local out rc
            out=$(timeout 15 "$LOADER" "$bin" 2>&1)
            rc=$?
            ;;
    esac

    case "$expect" in
        exit-zero)
            if [ $rc -eq 0 ]; then
                echo "  [PASS] $name (rc=0)"
                PASS=$((PASS + 1))
                JSON_RESULTS="$JSON_RESULTS{\"name\":\"$name\",\"category\":\"$category\",\"status\":\"PASS\",\"rc\":$rc},"
            else
                echo "  [FAIL] $name (rc=$rc)"
                FAIL=$((FAIL + 1))
                JSON_RESULTS="$JSON_RESULTS{\"name\":\"$name\",\"category\":\"$category\",\"status\":\"FAIL\",\"rc\":$rc,\"reason\":\"nonzero-exit\"},"
            fi
            ;;
        outputs:*)
            local needle="${expect#outputs:}"
            if echo "$out" | grep -qF "$needle"; then
                echo "  [PASS] $name (saw '$needle')"
                PASS=$((PASS + 1))
                JSON_RESULTS="$JSON_RESULTS{\"name\":\"$name\",\"category\":\"$category\",\"status\":\"PASS\",\"rc\":$rc,\"matched\":\"$needle\"},"
            else
                echo "  [FAIL] $name (rc=$rc; no '$needle' in output)"
                echo "$out" | head -5 | sed 's/^/         /'
                FAIL=$((FAIL + 1))
                JSON_RESULTS="$JSON_RESULTS{\"name\":\"$name\",\"category\":\"$category\",\"status\":\"FAIL\",\"rc\":$rc,\"reason\":\"missing-marker\",\"expected\":\"$needle\"},"
            fi
            ;;
        outputs-any:*)
            local list="${expect#outputs-any:}"
            local IFS_OLD="$IFS"
            IFS=','
            local matched=""
            for needle in $list; do
                if echo "$out" | grep -qF "$needle"; then
                    matched="$needle"
                    break
                fi
            done
            IFS="$IFS_OLD"
            if [ -n "$matched" ]; then
                echo "  [PASS] $name (saw '$matched')"
                PASS=$((PASS + 1))
                JSON_RESULTS="$JSON_RESULTS{\"name\":\"$name\",\"category\":\"$category\",\"status\":\"PASS\",\"rc\":$rc,\"matched\":\"$matched\"},"
            else
                echo "  [FAIL] $name (rc=$rc; none of '$list' in output)"
                echo "$out" | head -5 | sed 's/^/         /'
                FAIL=$((FAIL + 1))
                JSON_RESULTS="$JSON_RESULTS{\"name\":\"$name\",\"category\":\"$category\",\"status\":\"FAIL\",\"rc\":$rc,\"reason\":\"missing-any-marker\",\"expected\":\"$list\"},"
            fi
            ;;
        creates:*)
            local path="${expect#creates:}"
            if [ -e "$path" ]; then
                echo "  [PASS] $name (file '$path' created)"
                PASS=$((PASS + 1))
                rm -f "$path"
                JSON_RESULTS="$JSON_RESULTS{\"name\":\"$name\",\"category\":\"$category\",\"status\":\"PASS\",\"rc\":$rc,\"created\":\"$path\"},"
            else
                echo "  [FAIL] $name (rc=$rc; '$path' missing)"
                FAIL=$((FAIL + 1))
                JSON_RESULTS="$JSON_RESULTS{\"name\":\"$name\",\"category\":\"$category\",\"status\":\"FAIL\",\"rc\":$rc,\"reason\":\"missing-file\",\"expected\":\"$path\"},"
            fi
            ;;
        *)
            echo "  [ERROR] $name (unknown expectation '$expect')"
            ERROR=$((ERROR + 1))
            JSON_RESULTS="$JSON_RESULTS{\"name\":\"$name\",\"category\":\"$category\",\"status\":\"ERROR\",\"reason\":\"bad-expectation\"},"
            ;;
    esac
}

# --- Run phase ----------------------------------------------------------
echo "--- Running corpus ---"
for spec in "${TESTS[@]}"; do
    IFS='|' read -r bin_name expect category <<< "$spec"
    run_test "$bin_name" "$expect" "$category"
done
echo ""

# --- Summary ------------------------------------------------------------
TOTAL=${#TESTS[@]}
echo "=== Corpus summary: PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP  ERROR=$ERROR  (of $TOTAL) ==="

# --- Emit JSON ----------------------------------------------------------
JSON_RESULTS="${JSON_RESULTS%,}"  # strip trailing comma
cat > "$RESULT" <<EOF
{
  "loader": "${LOADER:-}",
  "source_dir": "$SRC_DIR",
  "totals": {
    "pass": $PASS,
    "fail": $FAIL,
    "skip": $SKIP,
    "error": $ERROR,
    "total": $TOTAL
  },
  "results": [$JSON_RESULTS]
}
EOF
echo "  -> $RESULT"

# --- Exit code ----------------------------------------------------------
if [ $ERROR -gt 0 ]; then
    exit 2
elif [ $FAIL -gt 0 ]; then
    exit 1
elif [ $PASS -eq 0 ] && [ $SKIP -eq $TOTAL ]; then
    # Everything skipped -- treat as "no corpus available" not failure
    echo "  (everything skipped; toolchain or loader absent)"
    exit 2
else
    exit 0
fi

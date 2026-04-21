#!/bin/bash
# diag-roa.sh — Root of Authority conformance diagnostic.
#
# Prints PASS/FAIL for every architectural element named in the RoA paper
# (Zenodo 18710335, DOI 10.5281/zenodo.18710335 — Roberts/Eli/Leelee).
#
# Runs cleanly on a system where trust.ko is NOT loaded: missing kernel
# nodes are reported as SKIP (not FAIL) so the script still exits 0 if
# every reachable element is healthy.
#
# Style mirrors scripts/diag-coherence.sh / scripts/diag-contusion.sh.
#
# Exit codes: 0 = all reachable elements PASS; 1 = at least one FAIL.

set -uo pipefail

# ----- colour scheme (matches diag-coherence.sh / diag-contusion.sh prose) -----
if [ -t 1 ]; then
    C_RESET=$'\033[0m'
    C_PASS=$'\033[1;32m'   # bold green
    C_FAIL=$'\033[1;31m'   # bold red
    C_SKIP=$'\033[1;33m'   # bold yellow
    C_HEAD=$'\033[1;36m'   # bold cyan
    C_DIM=$'\033[2m'
else
    C_RESET=""; C_PASS=""; C_FAIL=""; C_SKIP=""; C_HEAD=""; C_DIM=""
fi

PASS=0
FAIL=0
SKIP=0
TOTAL=0

banner() {
    echo ""
    echo "${C_HEAD}^^^^ $1 ^^^^${C_RESET}"
}

check_pass() {
    local name="$1"; local detail="${2:-}"
    PASS=$((PASS+1)); TOTAL=$((TOTAL+1))
    printf "  %s[PASS]%s %-48s %s%s%s\n" \
        "$C_PASS" "$C_RESET" "$name" "$C_DIM" "$detail" "$C_RESET"
}

check_fail() {
    local name="$1"; local detail="${2:-}"
    FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1))
    printf "  %s[FAIL]%s %-48s %s%s%s\n" \
        "$C_FAIL" "$C_RESET" "$name" "$C_DIM" "$detail" "$C_RESET"
}

check_skip() {
    local name="$1"; local detail="${2:-}"
    SKIP=$((SKIP+1)); TOTAL=$((TOTAL+1))
    printf "  %s[SKIP]%s %-48s %s%s%s\n" \
        "$C_SKIP" "$C_RESET" "$name" "$C_DIM" "$detail" "$C_RESET"
}

# ----------------------------------------------------------------------
echo "${C_HEAD}========================================================${C_RESET}"
echo "${C_HEAD} Root of Authority — runtime conformance diagnostic${C_RESET}"
echo "${C_HEAD} Paper:  Zenodo 18710335 (Roberts / Eli / Leelee)${C_RESET}"
echo "${C_HEAD} DOI:    10.5281/zenodo.18710335${C_RESET}"
echo "${C_HEAD}========================================================${C_RESET}"

# ----------------------------------------------------------------------
banner "Section 10 — Theorem invariants (sysfs counters)"

TRUST_SYSFS="/sys/kernel/trust"

if [ ! -d "$TRUST_SYSFS" ]; then
    KERNEL_LOADED=0
    echo "  ${C_DIM}(trust.ko not loaded — kernel-side checks will SKIP)${C_RESET}"
else
    KERNEL_LOADED=1
fi

check_sysfs_counter() {
    local label="$1"; local node="$2"
    local path="${TRUST_SYSFS}/${node}"
    if [ "$KERNEL_LOADED" -eq 0 ]; then
        check_skip "$label" "trust.ko not loaded"
        return
    fi
    if [ ! -e "$path" ]; then
        check_fail "$label" "missing: $path"
        return
    fi
    local val
    val=$(cat "$path" 2>/dev/null || echo "?")
    # Counter exists; for theorem violation counters we want value == 0
    case "$node" in
        theorem*_violations)
            if [ "$val" = "0" ]; then
                check_pass "$label" "violations=$val"
            else
                check_fail "$label" "violations=$val (expected 0)"
            fi
            ;;
        *)
            check_pass "$label" "value=$val"
            ;;
    esac
}

check_sysfs_counter "Theorem 1 (proof self-consume)"      "theorem1_violations"
check_sysfs_counter "Theorem 2 (generational decay)"      "theorem2_violations"
check_sysfs_counter "Theorem 4 (auth conservativity)"     "theorem4_violations"
check_sysfs_counter "Theorem 5 (cancer detect terminate)" "theorem5_violations"
check_sysfs_counter "Theorem 6 (meiosis entropy)"         "theorem6_violations"

# ----------------------------------------------------------------------
banner "Section 7 — Cancer detection counters"

check_sysfs_counter "cancer_detections (counter readable)"  "cancer_detections"
check_sysfs_counter "cancer_threshold_ms (tunable)"         "cancer_threshold_ms"

# ----------------------------------------------------------------------
banner "Section 6 — Meiosis bond table"

check_sysfs_counter "meiosis_active_bonds (gauge)"          "meiosis_active_bonds"
check_sysfs_counter "meiosis_count (cumulative)"            "meiosis_count"

# ----------------------------------------------------------------------
banner "Section 4 — Sex determination threshold"

check_sysfs_counter "sex_threshold (conf(E,t) cutoff)"      "sex_threshold"

# ----------------------------------------------------------------------
banner "libtrust ioctl reachability"

LIBTRUST_SO=""
for cand in \
    /usr/lib/libtrust.so.1 \
    /usr/lib/libtrust.so \
    /usr/lib/x86_64-linux-gnu/libtrust.so.1 \
    /usr/local/lib/libtrust.so.1 ; do
    if [ -e "$cand" ]; then
        LIBTRUST_SO="$cand"; break
    fi
done

if [ -z "$LIBTRUST_SO" ]; then
    check_skip "libtrust.so present"                      "no libtrust.so on linker path"
    check_skip "classify_subject symbol"                  "libtrust not present"
    check_skip "set_subject_class symbol"                 "libtrust not present"
    check_skip "meiosis_request symbol"                   "libtrust not present"
else
    check_pass "libtrust.so present"                      "$LIBTRUST_SO"
    # nm or readelf may not be installed everywhere; tolerate either.
    SYM_TOOL=""
    if command -v nm      >/dev/null 2>&1; then SYM_TOOL="nm -D --defined-only"; fi
    if [ -z "$SYM_TOOL" ] && command -v readelf >/dev/null 2>&1; then SYM_TOOL="readelf -Ws"; fi
    if [ -z "$SYM_TOOL" ] && command -v objdump >/dev/null 2>&1; then SYM_TOOL="objdump -T"; fi
    if [ -z "$SYM_TOOL" ]; then
        check_skip "classify_subject symbol"              "no nm/readelf/objdump available"
        check_skip "set_subject_class symbol"             "no nm/readelf/objdump available"
        check_skip "meiosis_request symbol"               "no nm/readelf/objdump available"
    else
        SYMS=$($SYM_TOOL "$LIBTRUST_SO" 2>/dev/null || true)
        for sym in classify_subject set_subject_class meiosis_request ; do
            if printf '%s\n' "$SYMS" | grep -q "\\b${sym}\\b"; then
                check_pass "${sym} symbol"                "exported by libtrust"
            else
                check_fail "${sym} symbol"                "not found in $LIBTRUST_SO"
            fi
        done
    fi
fi

# ----------------------------------------------------------------------
banner "AI Cortex — Dynamic Hyperlation surface"

CORTEX_BASE="${CORTEX_BASE:-http://127.0.0.1:8420}"

if ! command -v curl >/dev/null 2>&1; then
    check_skip "curl available"                           "install curl to test cortex"
    check_skip "GET /cortex/hyperlation/state"            "curl missing"
    check_skip "GET /cortex/hyperlation/theorems"         "curl missing"
else
    check_pass "curl available"                           "$(curl --version | head -1)"
    # Ping cortex base — a 200/401/404 all mean the daemon is reachable.
    PING_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "${CORTEX_BASE}/" 2>/dev/null || echo "000")
    if [ "$PING_CODE" = "000" ]; then
        check_skip "cortex daemon reachable"              "no listener at ${CORTEX_BASE}"
        check_skip "GET /cortex/hyperlation/state"        "cortex down"
        check_skip "GET /cortex/hyperlation/theorems"     "cortex down"
    else
        check_pass "cortex daemon reachable"              "HTTP ${PING_CODE} from ${CORTEX_BASE}/"
        for ep in "/cortex/hyperlation/state" "/cortex/hyperlation/theorems" ; do
            CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "${CORTEX_BASE}${ep}" 2>/dev/null || echo "000")
            if [ "$CODE" = "200" ]; then
                check_pass "GET ${ep}"                    "HTTP 200"
            elif [ "$CODE" = "401" ] || [ "$CODE" = "403" ]; then
                # Endpoint exists but requires auth — still reachable.
                check_pass "GET ${ep}"                    "HTTP ${CODE} (auth-gated, endpoint exists)"
            elif [ "$CODE" = "000" ]; then
                check_fail "GET ${ep}"                    "no response"
            else
                check_fail "GET ${ep}"                    "HTTP ${CODE}"
            fi
        done
    fi
fi

# ----------------------------------------------------------------------
banner "Userspace artefacts — files on disk"

# These should always be present in this repo / installed package.
check_path() {
    local label="$1"; local path="$2"
    if [ -e "$path" ]; then
        check_pass "$label" "$path"
    else
        check_fail "$label" "missing: $path"
    fi
}

# Try repo layout first, then installed prefixes.
ROA_DOC=""
for cand in \
    "$(dirname "$(dirname "$(readlink -f "$0")")")/docs/roa-conformance.md" \
    /usr/share/doc/ai-control/roa-conformance.md \
    /usr/share/doc/roa-conformance.md ; do
    if [ -e "$cand" ]; then ROA_DOC="$cand"; break; fi
done
if [ -n "$ROA_DOC" ]; then
    check_pass "docs/roa-conformance.md"                 "$ROA_DOC"
else
    check_fail "docs/roa-conformance.md"                 "not found"
fi

# ----------------------------------------------------------------------
echo ""
echo "${C_HEAD}========================================================${C_RESET}"
PCT=0
if [ "$TOTAL" -gt 0 ]; then
    PCT=$(( (PASS * 100) / TOTAL ))
fi
SUMMARY=$(printf "PASS %d/%d (%d%%)  FAIL %d  SKIP %d" "$PASS" "$TOTAL" "$PCT" "$FAIL" "$SKIP")
if [ "$FAIL" -eq 0 ]; then
    echo "  ${C_PASS}${SUMMARY}${C_RESET}"
    echo "${C_HEAD}========================================================${C_RESET}"
    exit 0
else
    echo "  ${C_FAIL}${SUMMARY}${C_RESET}"
    echo "${C_HEAD}========================================================${C_RESET}"
    exit 1
fi

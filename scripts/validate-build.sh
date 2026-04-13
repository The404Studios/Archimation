#!/bin/bash
# validate-build.sh - CI-like validation of the build output
#
# Checks compilation, Python syntax, package integrity, CRLF issues,
# file conflicts between packages, and repo consistency.
#
# Usage:
#   bash scripts/validate-build.sh          # run all checks
#   bash scripts/validate-build.sh --quick  # skip slow checks (C compilation, package build)
#
# Exit code = number of errors (0 = all passed)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
REPO_DIR="$PROJECT_DIR/repo/x86_64"

ERRORS=0
WARNINGS=0
QUICK=0

[[ "${1:-}" = "--quick" ]] && QUICK=1

_pass() { echo "OK"; }
_fail() { echo "FAIL"; ((ERRORS++)) || true; }
_warn() { echo "WARN${1:+ ($1)}"; ((WARNINGS++)) || true; }

echo "========================================"
echo "  Build Validation"
echo "========================================"
echo ""

# ── 1. C compilation ─────────────────────────────────────────────────────────
if [ "$QUICK" -eq 0 ]; then
    echo -n "[1/8] C compilation (pe-loader + services)... "
    if make -C "$PROJECT_DIR" all 2>/dev/null; then
        _pass
    else
        _fail
    fi
else
    echo "[1/8] C compilation... SKIPPED (--quick)"
fi

# ── 2. Python syntax check ──────────────────────────────────────────────────
echo -n "[2/8] Python syntax... "
PY_FAIL=0
PY_TOTAL=0
PY_ERRORS=""
for py_dir in ai-control/daemon ai-control/cortex firewall; do
    full_dir="$PROJECT_DIR/$py_dir"
    [ -d "$full_dir" ] || continue
    for f in "$full_dir"/*.py; do
        [ -f "$f" ] || continue
        ((PY_TOTAL++)) || true
        if ! python3 -c "
import ast, sys
try:
    ast.parse(open(sys.argv[1]).read())
except SyntaxError as e:
    print(f'{sys.argv[1]}:{e.lineno}: {e.msg}', file=sys.stderr)
    sys.exit(1)
" "$f" 2>/dev/null; then
            ((PY_FAIL++)) || true
            PY_ERRORS="${PY_ERRORS}    $(basename "$f")\n"
        fi
    done
done
if [ "$PY_FAIL" -eq 0 ]; then
    echo "OK ($PY_TOTAL files)"
else
    echo "FAIL ($PY_FAIL/$PY_TOTAL files with syntax errors)"
    echo -e "$PY_ERRORS"
    ERRORS=$((ERRORS + PY_FAIL))
fi

# ── 3. CRLF check in shell scripts and PKGBUILDs ────────────────────────────
echo -n "[3/8] CRLF line endings... "
CRLF_COUNT=0
CRLF_FILES=""
for check_dir in packages scripts profile/airootfs; do
    full_dir="$PROJECT_DIR/$check_dir"
    [ -d "$full_dir" ] || continue
    while IFS= read -r -d '' f; do
        if grep -Pql '\r\n' "$f" 2>/dev/null; then
            ((CRLF_COUNT++)) || true
            CRLF_FILES="${CRLF_FILES}    ${f#$PROJECT_DIR/}\n"
        fi
    done < <(find "$full_dir" -type f \( -name "*.sh" -o -name "PKGBUILD" -o -name "*.install" -o -name "*.hook" \) -print0 2>/dev/null)
done
if [ "$CRLF_COUNT" -eq 0 ]; then
    _pass
else
    _warn "$CRLF_COUNT files with CRLF"
    echo -e "$CRLF_FILES"
fi

# ── 4. PKGBUILD lint: all packages have required fields ─────────────────────
echo -n "[4/8] PKGBUILD required fields... "
PB_FAIL=0
PB_ERRORS=""
for pkgbuild in "$PROJECT_DIR"/packages/*/PKGBUILD; do
    [ -f "$pkgbuild" ] || continue
    pkg=$(basename "$(dirname "$pkgbuild")")
    for field in pkgname pkgver pkgrel pkgdesc arch; do
        if ! grep -q "^${field}=" "$pkgbuild" 2>/dev/null; then
            ((PB_FAIL++)) || true
            PB_ERRORS="${PB_ERRORS}    $pkg: missing '$field'\n"
        fi
    done
    # Check for single-quoted $pkgdir (common bug)
    if grep -q "'\$pkgdir" "$pkgbuild" 2>/dev/null; then
        ((PB_FAIL++)) || true
        PB_ERRORS="${PB_ERRORS}    $pkg: single-quoted \$pkgdir (won't expand)\n"
    fi
done
if [ "$PB_FAIL" -eq 0 ]; then
    _pass
else
    echo "FAIL ($PB_FAIL issues)"
    echo -e "$PB_ERRORS"
    ERRORS=$((ERRORS + PB_FAIL))
fi

# ── 5. File conflict check between packages ──────────────────────────────────
echo -n "[5/8] Inter-package file conflicts... "
# Scan package() functions for install -D destinations and check for overlaps.
# This is a best-effort static check -- it greps for install destinations.
CONFLICT_COUNT=0
CONFLICT_DETAILS=""
declare -A FILE_OWNERS 2>/dev/null || true
# Simpler approach: scan for install -Dm* "$pkgdir/<path>" patterns
for pkgbuild in "$PROJECT_DIR"/packages/*/PKGBUILD; do
    [ -f "$pkgbuild" ] || continue
    pkg=$(basename "$(dirname "$pkgbuild")")
    # Extract paths after $pkgdir or "$pkgdir
    while IFS= read -r dest_path; do
        # Normalize: strip leading quotes and $pkgdir prefix
        dest_path=$(echo "$dest_path" | sed 's|.*\$pkgdir||; s|.*\${pkgdir}||; s|^"||; s|"$||; s|^ *||')
        [ -z "$dest_path" ] && continue
        # Skip directories (install -d)
        [[ "$dest_path" = */ ]] && continue

        if [ -n "${FILE_OWNERS[$dest_path]+x}" ]; then
            other="${FILE_OWNERS[$dest_path]}"
            if [ "$other" != "$pkg" ]; then
                ((CONFLICT_COUNT++)) || true
                CONFLICT_DETAILS="${CONFLICT_DETAILS}    $dest_path: $other vs $pkg\n"
            fi
        else
            FILE_OWNERS["$dest_path"]="$pkg"
        fi
    done < <(grep -oP '(?:"\$pkgdir|\$pkgdir|\$\{pkgdir\})[^"]*' "$pkgbuild" 2>/dev/null | grep -v 'install -d' || true)
done
if [ "$CONFLICT_COUNT" -eq 0 ]; then
    _pass
else
    _warn "$CONFLICT_COUNT potential conflicts"
    echo -e "$CONFLICT_DETAILS"
fi

# ── 6. Repo consistency: each .pkg.tar.zst appears exactly once ──────────────
echo -n "[6/8] Repo version uniqueness... "
if [ -d "$REPO_DIR" ]; then
    DUPE_COUNT=0
    DUPE_DETAILS=""
    declare -A REPO_PKGS 2>/dev/null || true
    for pkg_file in "$REPO_DIR"/*.pkg.tar.zst; do
        [ -f "$pkg_file" ] || continue
        base=$(basename "$pkg_file")
        # Extract package name (everything before version)
        name=$(echo "$base" | sed 's/-[0-9][^-]*-[0-9][^-]*-[a-z_][a-z0-9_]*.pkg.tar.zst$//')
        if [ -n "${REPO_PKGS[$name]+x}" ]; then
            ((DUPE_COUNT++)) || true
            DUPE_DETAILS="${DUPE_DETAILS}    $name: $(basename "${REPO_PKGS[$name]}") AND $base\n"
        else
            REPO_PKGS["$name"]="$pkg_file"
        fi
    done
    if [ "$DUPE_COUNT" -eq 0 ]; then
        _pass
    else
        echo "FAIL ($DUPE_COUNT packages with duplicate versions)"
        echo -e "$DUPE_DETAILS"
        ERRORS=$((ERRORS + DUPE_COUNT))
    fi
else
    _warn "repo dir not found"
fi

# ── 7. Package build (full) ─────────────────────────────────────────────────
if [ "$QUICK" -eq 0 ]; then
    echo -n "[7/8] Package build (all PKGBUILDs)... "
    if bash "$SCRIPT_DIR/build-packages.sh" >/dev/null 2>&1; then
        _pass
    else
        _fail
    fi
else
    echo "[7/8] Package build... SKIPPED (--quick)"
fi

# ── 8. Systemd service files syntax ─────────────────────────────────────────
echo -n "[8/8] Systemd service files... "
SVC_FAIL=0
SVC_ERRORS=""
while IFS= read -r -d '' svc_file; do
    # Basic check: must have [Unit] and [Service] or [Install] sections
    if ! grep -q '^\[Unit\]' "$svc_file" 2>/dev/null; then
        ((SVC_FAIL++)) || true
        SVC_ERRORS="${SVC_ERRORS}    ${svc_file#$PROJECT_DIR/}: missing [Unit] section\n"
    fi
done < <(find "$PROJECT_DIR" -type f -name "*.service" -print0 2>/dev/null)
if [ "$SVC_FAIL" -eq 0 ]; then
    _pass
else
    _warn "$SVC_FAIL issues"
    echo -e "$SVC_ERRORS"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "========================================"
echo "  Results: $ERRORS error(s), $WARNINGS warning(s)"
echo "========================================"
if [ "$ERRORS" -gt 0 ]; then
    echo "  VALIDATION FAILED"
else
    echo "  ALL CHECKS PASSED"
fi

exit "$ERRORS"

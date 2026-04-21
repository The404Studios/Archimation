#!/bin/bash
# Test harness for verify_trust_dkms_manifest in build-packages.sh.
# Used to validate the guard during S67 development; safe to keep around.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Pull only the function definition out of build-packages.sh.
# awk is more reliable than sed across body content (handles `}` inside).
fn_def=$(awk '/^verify_trust_dkms_manifest\(\)/,/^}$/' "$SCRIPT_DIR/build-packages.sh")
eval "$fn_def"

# ── Test 1: positive (real package, all sources present) ──────────────────
real_pkg=$(ls -t "$PROJECT_DIR/repo/x86_64/trust-dkms-"[0-9]*.pkg.tar.zst 2>/dev/null | head -1)
if [ -z "$real_pkg" ]; then
    echo "[SKIP] no trust-dkms package built yet — run scripts/build-packages.sh first"
    exit 77
fi

if verify_trust_dkms_manifest "$real_pkg" >/dev/null 2>&1; then
    echo "[PASS] complete package -> guard returns 0"
else
    echo "[FAIL] complete package -> guard returned non-zero"
    exit 1
fi

# ── Test 2: negative (fake package missing every source) ──────────────────
tmp=$(mktemp -d)
mkdir -p "$tmp/usr/src/trust-0.1.0"
touch "$tmp/usr/src/trust-0.1.0/trust_core.c"
( cd "$tmp" && tar -I zstd -cf "$tmp/fake.pkg.tar.zst" . ) >/dev/null 2>&1

if ! verify_trust_dkms_manifest "$tmp/fake.pkg.tar.zst" >/dev/null 2>&1; then
    echo "[PASS] fake package missing sources -> guard returns 1"
else
    echo "[FAIL] fake package missing sources -> guard returned 0 (should fail)"
    rm -rf "$tmp"
    exit 1
fi

rm -rf "$tmp"
echo "[OK] verify_trust_dkms_manifest behaves correctly in both cases"

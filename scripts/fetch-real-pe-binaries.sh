#!/bin/bash
#
# fetch-real-pe-binaries.sh -- Download real-world open-source Windows PE
# binaries for the PE loader integration test suite.
#
# Session 41 / Agent 3: the existing in-tree fixtures are a single
# hand-built hello.exe and three MinGW stubs (exit42, console, msgbox).
# That's enough to exercise ExitProcess + kernel32 stdio, but nothing
# else. This script pulls ~5 real binaries off known-stable URLs so the
# loader gets tested against code compiled by actual compilers
# (MinGW-w64, MSVC) shipping real import tables.
#
# The binaries stay in tests/pe-loader/real-binaries/ and are NOT
# committed to the tree. Checksums ARE committed (see SHA256SUMS in
# the same dir).
#
# Usage:
#   bash scripts/fetch-real-pe-binaries.sh [--dry-run] [--force]
#
# Exit codes:
#   0   all binaries present and verified (or dry-run succeeded)
#   1   checksum mismatch or extraction failure
#   2   bad arguments
#   77  network unreachable / offline (autoconf "skip" convention)
#
# Ground rules:
#   - curl -LfsS --retry 3 --connect-timeout 10 --max-time 60
#   - Idempotent: re-running after a successful fetch is a no-op.
#   - --dry-run prints URLs + expected paths without touching the net.
#   - Offline detection: a single HEAD to a cheap endpoint; on failure
#     we exit 77 and the caller treats the whole suite as SKIP.

set -uo pipefail

# -----------------------------------------------------------------------
# Paths
# -----------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="$PROJECT_DIR/tests/pe-loader/real-binaries"
SUMS_FILE="$BIN_DIR/SHA256SUMS"
WORK_DIR="${TMPDIR:-/tmp}/pe-real-binaries-$$"

mkdir -p "$BIN_DIR"

# -----------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------
DRY_RUN=0
FORCE=0
for arg in "$@"; do
    case "$arg" in
        --dry-run)          DRY_RUN=1 ;;
        --force)            FORCE=1 ;;
        -h|--help)
            sed -n '3,30p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "fetch-real-pe-binaries.sh: unknown arg '$arg'" >&2
            exit 2
            ;;
    esac
done

# -----------------------------------------------------------------------
# Binary manifest
# -----------------------------------------------------------------------
# Each entry is <local_name>|<url>|<kind>|<inner_path>
#   kind = raw       -- download URL is the final .exe
#   kind = zip:<rel> -- download URL is a .zip; extract <rel> into <local_name>
#
# Update both URL and the SHA in SHA256SUMS together if an upstream
# vendor rotates a release in place.
MANIFEST=(
    # busybox-w32 -- frippery.org, 64-bit single-exe Unix tools.
    # Imports: kernel32, msvcrt. Tiny, bulletproof, --help shows usage.
    "busybox64.exe|https://frippery.org/files/busybox/busybox-w64-FRP-5034-g15892753a.exe|raw|"

    # curl 8.5.0 Windows mingw build -- curl.se official build.
    # Imports: kernel32, ws2_32, advapi32, crypt32, wldap32, normaliz,
    # msvcrt. Good exercise of ws2_32 + SEH + SSL libraries (even if
    # --version does no I/O, the IAT still has to resolve).
    "curl.exe|https://curl.se/windows/dl-8.5.0_1/curl-8.5.0_1-win64-mingw.zip|zip:curl-8.5.0_1-win64-mingw/bin/curl.exe|"

    # ripgrep 14.1.0 x86_64-pc-windows-gnu -- GitHub release.
    # Imports: kernel32, advapi32, ntdll, ws2_32, userenv, bcrypt,
    # msvcrt. Uses real Win32 file APIs, env vars, locale, console I/O.
    "rg.exe|https://github.com/BurntSushi/ripgrep/releases/download/14.1.0/ripgrep-14.1.0-x86_64-pc-windows-gnu.zip|zip:ripgrep-14.1.0-x86_64-pc-windows-gnu/rg.exe|"

    # 7zr.exe 23.01 -- 7-zip.org, standalone 7-Zip console decompressor.
    # Imports: kernel32, advapi32, user32, shell32, oleaut32, ole32,
    # uxtheme, comctl32. Pure MSVC build (no msvcrt dep -- statically
    # linked). Tests the vcredist register path in peloader's main.
    "7zr.exe|https://7-zip.org/a/7zr.exe|raw|"

    # nasm 2.16.03 -- nasm.us, pure-C console assembler.
    # Imports: kernel32, msvcrt. Small, does --version without I/O
    # side effects. A "clean baseline" sample.
    "nasm.exe|https://www.nasm.us/pub/nasm/releasebuilds/2.16.03/win64/nasm-2.16.03-win64.zip|zip:nasm-2.16.03/nasm.exe|"
)

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------
log() { printf '[fetch-real-pe] %s\n' "$*"; }
err() { printf '[fetch-real-pe] ERROR: %s\n' "$*" >&2; }

curl_safe() {
    # curl with hardened flags: retry 3, short connect + total timeout,
    # no silent-on-error, follow redirects.
    curl -LfsS --retry 3 --connect-timeout 10 --max-time 60 "$@"
}

check_online() {
    # One HEAD to a cheap, redundant endpoint. If even this fails, we
    # treat the whole run as offline and exit 77.
    if curl -fsS --connect-timeout 5 --max-time 8 -o /dev/null \
        -I https://github.com/ 2>/dev/null; then
        return 0
    fi
    return 1
}

expected_sha_for() {
    # Print the expected SHA-256 for filename $1 from SHA256SUMS, or
    # empty string if the file isn't listed.
    local name="$1"
    [[ -f "$SUMS_FILE" ]] || { echo ""; return; }
    awk -v f="$name" '
        $0 !~ /^#/ && $0 !~ /^$/ && $2 == f { print $1; exit }
    ' "$SUMS_FILE"
}

actual_sha_for() {
    # Print the hex SHA-256 of file $1. Uses sha256sum (coreutils) if
    # available, else shasum -a 256 (BSD), else openssl.
    local f="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$f" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$f" | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$f" | awk '{print $NF}'
    else
        err "no sha256sum/shasum/openssl available"
        return 1
    fi
}

already_ok() {
    # True if $1 exists AND matches the expected SHA from SHA256SUMS.
    local name="$1"
    local path="$BIN_DIR/$name"
    [[ -f "$path" ]] || return 1
    local expected; expected=$(expected_sha_for "$name")
    [[ -n "$expected" ]] || return 1
    local actual; actual=$(actual_sha_for "$path") || return 1
    [[ "$actual" == "$expected" ]]
}

fetch_raw() {
    # Download a raw .exe to the final location.
    local name="$1" url="$2"
    local dest="$BIN_DIR/$name"
    log "  fetching $name <- $url"
    mkdir -p "$(dirname "$dest")"
    if ! curl_safe -o "$dest.part" "$url"; then
        err "  download failed for $name"
        rm -f "$dest.part"
        return 1
    fi
    mv "$dest.part" "$dest"
    return 0
}

fetch_zip() {
    # Download a zip and extract a single inner file.
    local name="$1" url="$2" inner="$3"
    local dest="$BIN_DIR/$name"
    log "  fetching $name <- $url (zip, inner=$inner)"
    mkdir -p "$WORK_DIR"
    local archive="$WORK_DIR/$name.zip"
    if ! curl_safe -o "$archive" "$url"; then
        err "  download failed for $name"
        return 1
    fi
    if ! command -v unzip >/dev/null 2>&1; then
        err "  unzip not on PATH; cannot extract $name"
        return 1
    fi
    # Extract just the one inner file. -j flattens paths, -o overwrites.
    if ! unzip -p "$archive" "$inner" > "$dest.part" 2>/dev/null; then
        # -p may succeed and emit nothing if the path is wrong, so also
        # check for empty output.
        err "  extraction failed for $name (inner=$inner)"
        rm -f "$dest.part"
        return 1
    fi
    if [[ ! -s "$dest.part" ]]; then
        err "  extracted zero bytes for $name (inner=$inner); wrong path?"
        rm -f "$dest.part"
        return 1
    fi
    mv "$dest.part" "$dest"
    return 0
}

verify_sha() {
    # Verify $1 against SHA256SUMS. Returns 0 on match, 1 on mismatch,
    # 2 if the file isn't listed in SHA256SUMS at all (which is also a
    # failure for a real fetch -- caller decides).
    local name="$1"
    local path="$BIN_DIR/$name"
    local expected; expected=$(expected_sha_for "$name")
    if [[ -z "$expected" ]]; then
        err "  $name: no entry in $SUMS_FILE"
        return 2
    fi
    local actual; actual=$(actual_sha_for "$path") || return 1
    if [[ "$actual" != "$expected" ]]; then
        err "  $name: SHA mismatch"
        err "    expected: $expected"
        err "    actual:   $actual"
        return 1
    fi
    return 0
}

cleanup() {
    [[ -d "$WORK_DIR" ]] && rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# -----------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------
log "Real PE binary fetch -- dest $BIN_DIR"

if [[ "$DRY_RUN" -eq 1 ]]; then
    log "--dry-run: would fetch:"
    for entry in "${MANIFEST[@]}"; do
        IFS='|' read -r name url kind _ <<< "$entry"
        printf '  %-20s  <- %s  (%s)\n' "$name" "$url" "$kind"
    done
    exit 0
fi

if ! check_online; then
    log "offline (github.com HEAD failed); exiting 77 (SKIP)"
    exit 77
fi

TOTAL=0
FETCHED=0
SKIPPED=0
FAILED=0

for entry in "${MANIFEST[@]}"; do
    IFS='|' read -r name url kind _ <<< "$entry"
    TOTAL=$((TOTAL + 1))

    if [[ "$FORCE" -eq 0 ]] && already_ok "$name"; then
        log "[skip] $name already present + verified"
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    case "$kind" in
        raw)
            if ! fetch_raw "$name" "$url"; then
                FAILED=$((FAILED + 1))
                continue
            fi
            ;;
        zip:*)
            inner="${kind#zip:}"
            if ! fetch_zip "$name" "$url" "$inner"; then
                FAILED=$((FAILED + 1))
                continue
            fi
            ;;
        *)
            err "unknown kind '$kind' for $name"
            FAILED=$((FAILED + 1))
            continue
            ;;
    esac

    # Verify the freshly-downloaded file against SHA256SUMS.
    rc=0
    verify_sha "$name" || rc=$?
    case "$rc" in
        0)
            log "[ok]   $name verified"
            FETCHED=$((FETCHED + 1))
            ;;
        2)
            # Not listed in SHA256SUMS. The checked-in placeholder sums
            # in this repo are known to be stale -- the first real
            # fetch populates them. Record the observed sum so the
            # next run succeeds and warn loudly.
            actual=$(actual_sha_for "$BIN_DIR/$name") || actual="(unknown)"
            err "  $name: not in SHA256SUMS (observed $actual) -- update SHA256SUMS + commit"
            FAILED=$((FAILED + 1))
            ;;
        *)
            # Mismatch -- treat as failure, leave file for debugging.
            FAILED=$((FAILED + 1))
            ;;
    esac
done

log "summary: total=$TOTAL fetched=$FETCHED skipped=$SKIPPED failed=$FAILED"

if [[ "$FAILED" -gt 0 ]]; then
    exit 1
fi
exit 0

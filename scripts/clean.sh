#!/bin/bash
# Clean build artifacts
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Cleaning build artifacts..."

rm -rf "$PROJECT_DIR/work"
rm -rf "$PROJECT_DIR/output"
rm -f "$PROJECT_DIR/repo/x86_64"/*.pkg.tar.zst
rm -f "$PROJECT_DIR/repo/x86_64"/*.db*
rm -f "$PROJECT_DIR/repo/x86_64"/*.files*
rm -rf "$PROJECT_DIR/repo/x86_64/.build-hashes"

echo "Done."

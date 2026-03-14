#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="$ROOT_DIR/artifacts/packages"
VERSION="${1:-}"
if [ -z "$VERSION" ]; then echo "Usage: ./eng/pack.sh <version>"; exit 1; fi

echo "=== AgentGuard Pack (v$VERSION) ==="
cd "$ROOT_DIR"
rm -rf "$OUTPUT_DIR"
dotnet pack AgentGuard.slnx --configuration Release --output "$OUTPUT_DIR" -p:PackageVersion="$VERSION"
echo "Packages:"
ls -la "$OUTPUT_DIR"/*.nupkg

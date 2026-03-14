#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIGURATION="${1:-Debug}"

echo "=== AgentGuard Build ($CONFIGURATION) ==="
cd "$ROOT_DIR"

echo "-- Restore --"
dotnet restore AgentGuard.slnx

echo "-- Build --"
dotnet build AgentGuard.slnx --no-restore --configuration "$CONFIGURATION"

echo "-- Test --"
dotnet test AgentGuard.slnx --no-build --configuration "$CONFIGURATION" --verbosity normal

echo "Build complete."

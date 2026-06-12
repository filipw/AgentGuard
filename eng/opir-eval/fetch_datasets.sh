#!/usr/bin/env bash
# Downloads PIGuard's bundled evaluation datasets into .cache/piguard-datasets.
# Reused verbatim from eng/piguard-eval so Opir is measured on the same rows.
set -euo pipefail
cd "$(dirname "$0")"
DEST=.cache/piguard-datasets
mkdir -p "$DEST"
BASE=https://raw.githubusercontent.com/leolee99/PIGuard/main/datasets
for f in NotInject_one.json NotInject_two.json NotInject_three.json \
         wildguard.json BIPIA_text.json BIPIA_code.json; do
  curl -fsSL "$BASE/$f" -o "$DEST/$f"
  echo "ok $f"
done
echo "datasets ready in $DEST"

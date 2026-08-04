#!/usr/bin/env bash
# Remove every module's virtualenv, caches, and build output.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for t in backend/.venv ai.engine/.venv mcpserver/.venv \
         frontend/node_modules frontend/.next frontend/out; do
  if [ -e "$root/$t" ]; then
    echo "removing $t"
    rm -rf "$root/$t"
  fi
done

find "$root" \
  -path '*/node_modules' -prune -o \
  \( -name __pycache__ -o -name .pytest_cache -o -name .mypy_cache \
     -o -name .ruff_cache -o -name '*.egg-info' \) -print0 |
  while IFS= read -r -d '' p; do
    echo "removing ${p#"$root"/}"
    rm -rf "$p"
  done

echo 'clean: done'

#!/usr/bin/env bash
# Create .env from .env.example when it does not already exist.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ -f "$root/.env" ]; then
  echo '.env already exists - leaving it untouched'
else
  cp "$root/.env.example" "$root/.env"
  echo 'created .env from .env.example - fill in OPENAI_API_KEY before using the ai.engine LLM'
fi

#!/usr/bin/env bash
# Phase 1 acceptance smoke test. Probes every module's health surface.
# Requires the stack to be running (make up, or the individual make dev-* targets).
set -uo pipefail

failures=0
analyze='{"source":"verify","asset":"example.internal","raw_input":"placeholder"}'
initialize='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"verify","version":"1"}}}'

probe() {
  local name="$1" method="$2" url="$3" body="${4:-$analyze}"
  local code
  if [ "$method" = 'POST' ]; then
    code=$(curl -s -o /dev/null -w '%{http_code}' -m 15 -X POST \
      -H 'Content-Type: application/json' \
      -H 'Accept: application/json, text/event-stream' \
      -d "$body" "$url" || echo 000)
  else
    code=$(curl -s -o /dev/null -w '%{http_code}' -m 15 "$url" || echo 000)
  fi
  if [ "$code" -ge 200 ] && [ "$code" -lt 300 ]; then
    printf 'PASS  %-34s %s %s\n' "$name" "$code" "$url"
  else
    printf 'FAIL  %-34s %s %s\n' "$name" "$code" "$url"
    failures=$((failures + 1))
  fi
}

echo 'backend (:8000)'
probe 'GET /health'               GET http://localhost:8000/health
probe 'GET /health/db [needs db]' GET http://localhost:8000/health/db
probe 'GET /findings [needs db]'  GET http://localhost:8000/findings

echo
echo 'ai.engine (:8003)'
probe 'GET /health' GET http://localhost:8003/health
for a in vulnerability phishing network webapp; do
  probe "POST /agents/$a/analyze" POST "http://localhost:8003/agents/$a/analyze"
done

echo
echo 'frontend (:3000)'
probe 'GET /' GET http://localhost:3000/

echo
echo 'mcpserver (:8004)'
probe 'GET /health' GET http://localhost:8004/health
probe 'POST /mcp initialize' POST http://localhost:8004/mcp "$initialize"

echo
if [ "$failures" -eq 0 ]; then
  echo 'verify: all checks passed'
  exit 0
fi
echo "verify: $failures check(s) failed"
echo 'Probes marked [needs db] fail when PostgreSQL is not running.'
exit 1

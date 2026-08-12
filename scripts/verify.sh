#!/usr/bin/env bash
# Acceptance smoke test. Probes every module's health surface.
# Requires the stack to be running (make up, or the individual make *-dev targets).
#
# INTERNAL_KEY is read from the environment (or .env) and sent on every probe: the
# agent routes and the MCP endpoint require it whenever one is configured, so
# without it this script would report 401s as failures.
set -uo pipefail

if [ -z "${INTERNAL_KEY:-}" ] && [ -f .env ]; then
  INTERNAL_KEY=$(sed -n 's/^INTERNAL_KEY=//p' .env | head -1)
fi

failures=0
# A real Nmap banner, not a placeholder: the vulnerability agent now runs a rule
# engine, and "placeholder" exercises only the unparseable-source path.
analyze='{"source":"nmap","asset":"10.0.0.5","raw_input":"Nmap scan report for 10.0.0.5\n22/tcp open ssh OpenSSH 7.2 (protocol 2.0)\n"}'
initialize='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"verify","version":"1"}}}'

probe() {
  local name="$1" method="$2" url="$3" body="${4:-$analyze}"
  local code
  if [ "$method" = 'POST' ]; then
    code=$(curl -s -o /dev/null -w '%{http_code}' -m 15 -X POST \
      -H 'Content-Type: application/json' \
      -H 'Accept: application/json, text/event-stream' \
      -H "X-Internal-Key: ${INTERNAL_KEY:-}" \
      -d "$body" "$url" || echo 000)
  else
    code=$(curl -s -o /dev/null -w '%{http_code}' -m 15 \
      -H "X-Internal-Key: ${INTERNAL_KEY:-}" "$url" || echo 000)
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
probe 'POST /agents/vulnerability/assess' POST http://localhost:8003/agents/vulnerability/assess \
  '{"scan_id":"00000000-0000-0000-0000-000000000000","source":"nmap","asset":"10.0.0.5","scan":{"format":"nmap_xml","scanner":"nmap","hosts":[{"address":"10.0.0.5","status":"up","ports":[{"port":22,"protocol":"tcp","state":"open","service":"ssh","product":"OpenSSH","version":"7.2"}]}]},"context":{}}'

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

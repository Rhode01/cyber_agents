#Requires -Version 5.1
# Acceptance smoke test. Probes every module's health surface.
# Requires the stack to be running (make up, or the individual make *-dev targets).
#
# INTERNAL_KEY is read from the environment (or .env) and sent on every probe: the
# agent routes and the MCP endpoint require it whenever one is configured, so
# without it this script would report 401s as failures.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$internalKey = $env:INTERNAL_KEY
if ([string]::IsNullOrEmpty($internalKey) -and (Test-Path '.env')) {
    $line = Select-String -Path '.env' -Pattern '^INTERNAL_KEY=(.*)$' | Select-Object -First 1
    if ($null -ne $line) { $internalKey = $line.Matches[0].Groups[1].Value }
}
if ($null -eq $internalKey) { $internalKey = '' }

$failures = 0

function Probe {
    param([string]$Name, [string]$Method, [string]$Url, [string]$Body)

    try {
        if ($Method -eq 'POST') {
            $r = Invoke-WebRequest -UseBasicParsing -Method POST -Uri $Url -Body $Body `
                -ContentType 'application/json' -TimeoutSec 15 `
                -Headers @{
                    accept            = 'application/json, text/event-stream'
                    'X-Internal-Key'  = $script:internalKey
                }
        } else {
            $r = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 15 `
                -Headers @{ 'X-Internal-Key' = $script:internalKey }
        }
        if ($r.StatusCode -ge 200 -and $r.StatusCode -lt 300) {
            Write-Output ("PASS  {0,-34} {1} {2}" -f $Name, $r.StatusCode, $Url)
            return
        }
        Write-Output ("FAIL  {0,-34} {1} {2}" -f $Name, $r.StatusCode, $Url)
    } catch {
        Write-Output ("FAIL  {0,-34} {1}" -f $Name, $_.Exception.Message)
    }
    $script:failures++
}

# A real Nmap banner, not a placeholder: the vulnerability agent now runs a rule
# engine, and "placeholder" exercises only the unparseable-source path.
$analyze = '{"source":"nmap","asset":"10.0.0.5","raw_input":"Nmap scan report for 10.0.0.5\n22/tcp open ssh OpenSSH 7.2 (protocol 2.0)\n"}'
$assess = '{"scan_id":"00000000-0000-0000-0000-000000000000","source":"nmap","asset":"10.0.0.5","scan":{"format":"nmap_xml","scanner":"nmap","hosts":[{"address":"10.0.0.5","status":"up","ports":[{"port":22,"protocol":"tcp","state":"open","service":"ssh","product":"OpenSSH","version":"7.2"}]}]},"context":{}}'

Write-Output 'backend (:8000)'
Probe 'GET /health'                 'GET' 'http://localhost:8000/health'
Probe 'GET /health/db [needs db]'   'GET' 'http://localhost:8000/health/db'
Probe 'GET /findings [needs db]'    'GET' 'http://localhost:8000/findings'

Write-Output ''
Write-Output 'ai.engine (:8003)'
Probe 'GET /health'      'GET'  'http://localhost:8003/health'
foreach ($a in @('vulnerability', 'phishing', 'network', 'webapp')) {
    Probe "POST /agents/$a/analyze" 'POST' "http://localhost:8003/agents/$a/analyze" $analyze
}
Probe 'POST /agents/vulnerability/assess' 'POST' 'http://localhost:8003/agents/vulnerability/assess' $assess

Write-Output ''
Write-Output 'frontend (:3000)'
Probe 'GET /'            'GET'  'http://localhost:3000/'

Write-Output ''
Write-Output 'mcpserver (:8004)'
Probe 'GET /health'      'GET'  'http://localhost:8004/health'
$initialize = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"verify","version":"1"}}}'
Probe 'POST /mcp initialize' 'POST' 'http://localhost:8004/mcp' $initialize

Write-Output ''
if ($failures -eq 0) {
    Write-Output 'verify: all checks passed'
    exit 0
}
Write-Output "verify: $failures check(s) failed"
Write-Output 'Probes marked [needs db] fail when PostgreSQL is not running.'
exit 1

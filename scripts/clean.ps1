#Requires -Version 5.1
# Remove every module's virtualenv, caches, and build output.
$ErrorActionPreference = 'Continue'

$root = Split-Path -Parent $PSScriptRoot
$targets = @(
    'backend\.venv', 'ai.engine\.venv', 'mcpserver\.venv',
    'frontend\node_modules', 'frontend\.next', 'frontend\out'
)

foreach ($t in $targets) {
    $p = Join-Path $root $t
    if (Test-Path $p) {
        Write-Output "removing $t"
        Remove-Item -Recurse -Force $p -ErrorAction SilentlyContinue
    }
}

$patterns = @('__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache', '*.egg-info')
foreach ($pattern in $patterns) {
    Get-ChildItem -Path $root -Filter $pattern -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\node_modules\\' } |
        ForEach-Object {
            Write-Output "removing $($_.FullName.Substring($root.Length + 1))"
            Remove-Item -Recurse -Force $_.FullName -ErrorAction SilentlyContinue
        }
}

Write-Output 'clean: done'

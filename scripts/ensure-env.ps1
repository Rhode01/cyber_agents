#Requires -Version 5.1
# Create .env from .env.example when it does not already exist.
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$target = Join-Path $root '.env'
$source = Join-Path $root '.env.example'

if (Test-Path $target) {
    Write-Output '.env already exists - leaving it untouched'
} else {
    Copy-Item $source $target
    Write-Output 'created .env from .env.example - fill in OPENAI_API_KEY before using the ai.engine LLM'
}

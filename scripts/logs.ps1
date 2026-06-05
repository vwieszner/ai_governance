# logs.ps1 — quick look at a backend's recent activity without typing the grep each time.
#
# Usage:
#   .\scripts\logs.ps1 agt-a            # last interesting lines from agt-a's api log
#   .\scripts\logs.ps1 agt-a 40         # last 40 matching lines
#   .\scripts\logs.ps1 agt-b -Raw       # raw tail (no filter)
#
# Names: agt-a agt-b  (matches scripts\clusters.ps1). structlog writes
# the real events (auth_decision, agent_run_failed, peer_call, ...) to the .out file.

param(
    [Parameter(Mandatory = $true)][ValidateSet('agt-a', 'agt-b')][string]$Name,
    [int]$Lines = 25,
    [switch]$Raw
)

$root = Split-Path $PSScriptRoot -Parent
$out = Join-Path $root "logs\$Name-api.out"
$err = Join-Path $root "logs\$Name-api.err"

if (-not (Test-Path $out)) { Write-Host "No log yet: $out" -ForegroundColor DarkGray; return }

# Interesting events to surface by default.
$pattern = 'auth_decision|node_generate_answer|node_retrieve|agent_run_failed|peer_call|a2a|policy_deni|approval|error=|Traceback|ERROR'

Write-Host "=== $Name api.out (tail) ===" -ForegroundColor Cyan
if ($Raw) {
    Get-Content $out -Tail $Lines
} else {
    Get-Content $out -Tail 200 | Select-String -Pattern $pattern | Select-Object -Last $Lines | ForEach-Object { $_.Line }
}

# Surface stderr only if it has real content (tracebacks land here).
if ((Test-Path $err) -and (Get-Item $err).Length -gt 0) {
    $errTail = Get-Content $err -Tail 6 | Where-Object { $_ -match 'Error|Traceback|Exception|raise' }
    if ($errTail) {
        Write-Host "=== $Name api.err (errors) ===" -ForegroundColor Red
        $errTail | ForEach-Object { $_ }
    }
}

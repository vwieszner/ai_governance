# clusters.ps1 — one place that knows all four backends, so we stop hand-typing
# the kill-port / Start-Process / poll-health incantation over and over.
#
# Both federations run the SAME code per solution, selected by RAG_ENV_FILE:
#   a2a-a / a2a-b  -> federated-rag      (.env / .env.cluster-b)   ports 8000 / 8002
#   agt-a / agt-b  -> agt-federated-rag  (.env / .env.cluster-b)   ports 8010 / 8012
#
# Usage (dot-source NOT required; call directly):
#   .\scripts\clusters.ps1 status                 # health of all 4 backends + UI
#   .\scripts\clusters.ps1 restart agt-a          # restart one backend api + its worker
#   .\scripts\clusters.ps1 start  a2a-a a2a-b     # start one or more
#   .\scripts\clusters.ps1 stop   agt-a agt-b     # stop one or more (api + worker)
#   .\scripts\clusters.ps1 restart all            # restart all four
#   .\scripts\clusters.ps1 stop all               # stop everything (backends + workers)
#
# Logs go to logs\<name>-api.out/.err and logs\<name>-worker.out/.err.

param(
    [Parameter(Mandatory = $true)][ValidateSet('status', 'start', 'stop', 'restart')]
    [string]$Action,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Targets
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$py = Join-Path $root '.venv\Scripts\python.exe'
$logDir = Join-Path $root 'logs'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

# The single source of truth for every backend.
$CLUSTERS = @{
    'a2a-a' = @{ dir = 'federated-rag';     env = '.env';            port = 8000 }
    'a2a-b' = @{ dir = 'federated-rag';     env = '.env.cluster-b';  port = 8002 }
    'agt-a' = @{ dir = 'agt-federated-rag'; env = '.env';            port = 8010 }
    'agt-b' = @{ dir = 'agt-federated-rag'; env = '.env.cluster-b';  port = 8012 }
}
$ALL = @('a2a-a', 'a2a-b', 'agt-a', 'agt-b')

function Resolve-Targets([string[]]$t) {
    if (-not $t -or $t.Count -eq 0 -or $t -contains 'all') { return $ALL }
    foreach ($x in $t) { if (-not $CLUSTERS.ContainsKey($x)) { throw "Unknown target '$x'. Valid: $($ALL -join ', '), all" } }
    return $t
}

function Stop-Port([int]$Port) {
    $line = netstat -ano | Select-String ":$Port\s" | Select-String 'LISTENING' | Select-Object -First 1
    if ($line) {
        $procId = ($line.ToString().Trim() -split '\s+')[-1]
        $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
        if ($p -and $p.ProcessName -eq 'python') { Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue }
    }
}

function Stop-Worker([string]$name, [string]$dir, [string]$env) {
    # Workers have no port. The python `-m workflow.worker` command line does NOT
    # contain the working directory, so matching on $dir never worked and left
    # zombie workers on every restart. Track the worker PID in a file at start
    # and kill exactly that PID here.
    $pidFile = Join-Path $logDir "$name-worker.pid"
    if (Test-Path $pidFile) {
        $wpid = (Get-Content $pidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ($wpid) {
            $p = Get-Process -Id $wpid -ErrorAction SilentlyContinue
            if ($p -and $p.ProcessName -eq 'python') {
                # `python -m workflow.worker` spawns a child worker process; a plain
                # Stop-Process kills only the parent and orphans the child (which keeps
                # polling Temporal). taskkill /T kills the whole tree.
                & taskkill /PID $wpid /T /F *> $null
            }
        }
        Remove-Item $pidFile -ErrorAction SilentlyContinue
    }
}

function Start-One([string]$name) {
    $c = $CLUSTERS[$name]
    $dir = Join-Path $root $c.dir
    $env:PYTHONUNBUFFERED = '1'
    $env:RAG_ENV_FILE = $c.env
    Start-Process $py -ArgumentList '-m', 'api.main' -WorkingDirectory $dir `
        -RedirectStandardOutput (Join-Path $logDir "$name-api.out") `
        -RedirectStandardError  (Join-Path $logDir "$name-api.err") -WindowStyle Hidden | Out-Null
    # -PassThru so we can record the worker PID and reliably stop it later.
    $wp = Start-Process $py -ArgumentList '-m', 'workflow.worker' -WorkingDirectory $dir `
        -RedirectStandardOutput (Join-Path $logDir "$name-worker.out") `
        -RedirectStandardError  (Join-Path $logDir "$name-worker.err") -WindowStyle Hidden -PassThru
    $wp.Id | Out-File -FilePath (Join-Path $logDir "$name-worker.pid") -Encoding ascii
    Remove-Item Env:RAG_ENV_FILE -ErrorAction SilentlyContinue
    Write-Host "  started $name ($($c.env) -> :$($c.port))" -ForegroundColor Green
}

function Stop-One([string]$name) {
    $c = $CLUSTERS[$name]
    Stop-Port $c.port
    Stop-Worker $name (Join-Path $root $c.dir) $c.env
    Write-Host "  stopped $name (:$($c.port) + worker)" -ForegroundColor Yellow
}

function Wait-Health([string]$name) {
    $port = $CLUSTERS[$name].port
    for ($i = 0; $i -lt 30; $i++) {
        try {
            if ((Invoke-WebRequest "http://localhost:$port/health" -UseBasicParsing -TimeoutSec 3).StatusCode -eq 200) {
                Write-Host "  $name healthy (:$port)" -ForegroundColor Green; return $true
            }
        } catch {}
        Start-Sleep 2
    }
    Write-Host "  $name did NOT become healthy (:$port) -- see logs\$name-api.err" -ForegroundColor Red
    return $false
}

function Show-Status {
    Write-Host "=== backends ===" -ForegroundColor Cyan
    foreach ($name in $ALL) {
        $port = $CLUSTERS[$name].port
        try {
            $r = Invoke-WebRequest "http://localhost:$port/health" -UseBasicParsing -TimeoutSec 3
            Write-Host ("  {0,-6} :{1}  UP   {2}" -f $name, $port, $r.Content) -ForegroundColor Green
        } catch {
            Write-Host ("  {0,-6} :{1}  down" -f $name, $port) -ForegroundColor DarkGray
        }
    }
    try {
        $ui = (Invoke-WebRequest 'http://localhost:5173' -UseBasicParsing -TimeoutSec 3).StatusCode
        Write-Host "  ui     :5173  UP   $ui" -ForegroundColor Green
    } catch {
        Write-Host "  ui     :5173  down" -ForegroundColor DarkGray
    }
}

# Track health so the script exits 0 only when every targeted backend is healthy
# (start/restart). This gives a meaningful exit code for CI/automation instead of
# leaking a stray non-zero from an internal native command.
$allHealthy = $true

switch ($Action) {
    'status' { Show-Status }
    'stop' { foreach ($n in (Resolve-Targets $Targets)) { Stop-One $n } }
    'start' {
        $names = Resolve-Targets $Targets
        foreach ($n in $names) { Start-One $n }
        Start-Sleep 2
        foreach ($n in $names) { if (-not (Wait-Health $n)) { $allHealthy = $false } }
    }
    'restart' {
        $names = Resolve-Targets $Targets
        foreach ($n in $names) { Stop-One $n }
        Start-Sleep 2
        foreach ($n in $names) { Start-One $n }
        Start-Sleep 2
        foreach ($n in $names) { if (-not (Wait-Health $n)) { $allHealthy = $false } }
    }
}

if ($allHealthy) { exit 0 } else { exit 1 }

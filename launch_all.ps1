# Federated RAG — launch the two REAL backends (+ Temporal workers) and the UI.
#
# Prerequisites (run once, in order):
#   docker compose up -d                       # infra: OpenFGA, Temporal, Keycloak, Postgres
#   docker start claude-qdrant claude-neo4j storyteller-redis-1   # vector/graph/cache
#   .venv\Scripts\python.exe setup_all.py --no-neo4j             # store, realm, ingest, tuples
#
# Then:
#   .\launch_all.ps1
#
# Stop everything later with:  .\launch_all.ps1 -Stop

param([switch]$Stop)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$py   = Join-Path $root ".venv\Scripts\python.exe"

# Both clusters run the SAME federated-rag codebase; RAG_ENV_FILE selects which
# cluster config to load (.env = cluster-a, .env.cluster-b = cluster-b). This is
# one concept deployed as two federated clusters, not two different products.
$procs = @(
    @{ Name="cluster-a-api";    Dir="federated-rag"; Args=@("-m","api.main");        EnvFile=".env" },
    @{ Name="cluster-a-worker"; Dir="federated-rag"; Args=@("-m","workflow.worker"); EnvFile=".env" },
    @{ Name="cluster-b-api";    Dir="federated-rag"; Args=@("-m","api.main");        EnvFile=".env.cluster-b" },
    @{ Name="cluster-b-worker"; Dir="federated-rag"; Args=@("-m","workflow.worker"); EnvFile=".env.cluster-b" }
)

function Stop-Port([int]$Port) {
    $line = netstat -ano | Select-String ":$Port\s" | Select-String LISTENING | Select-Object -First 1
    if ($line) {
        $procId = ($line.ToString().Trim() -split '\s+')[-1]
        Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
    }
}

if ($Stop) {
    Write-Host "Stopping backends, workers, and UI..." -ForegroundColor Yellow
    foreach ($p in 8000, 8002, 5173) { Stop-Port $p }
    # Workers have no port; kill python processes whose command line names our modules.
    Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
        Where-Object { $_.CommandLine -match "workflow.worker" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Write-Host "Stopped." -ForegroundColor Green
    return
}

# ── Pre-flight checks ─────────────────────────────────────────────────────────
foreach ($d in @("federated-rag", "agt-federated-rag")) {
    $envPath = Join-Path $root "$d\.env"
    if (-not (Test-Path $envPath)) {
        Write-Host "ERROR: $d\.env not found. Run setup_all.py first." -ForegroundColor Red
        exit 1
    }
}

# ── Free our ports, then start each process detached with redirected logs ─────
Write-Host "=== Launching real federated RAG ===" -ForegroundColor Cyan
foreach ($p in 8000, 8002) { Stop-Port $p }
Start-Sleep 1

$env:PYTHONUNBUFFERED = "1"
# All process logs go to a dedicated, gitignored logs/ directory (not the repo root).
$logDir = Join-Path $root "logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
foreach ($p in $procs) {
    $dir = Join-Path $root $p.Dir
    $out = Join-Path $logDir "$($p.Name).out"
    $err = Join-Path $logDir "$($p.Name).err"
    # Child process inherits this; selects the cluster's config file.
    $env:RAG_ENV_FILE = $p.EnvFile
    Start-Process -FilePath $py -ArgumentList $p.Args -WorkingDirectory $dir `
        -RedirectStandardOutput $out -RedirectStandardError $err -WindowStyle Hidden | Out-Null
    Write-Host "  started $($p.Name)  ($($p.EnvFile) -> logs/$($p.Name).out)" -ForegroundColor Green
}
Remove-Item Env:RAG_ENV_FILE -ErrorAction SilentlyContinue

# ── Wait for both API health endpoints ────────────────────────────────────────
function Wait-Health([int]$Port, [string]$Label) {
    $url = "http://localhost:$Port/health"
    for ($i = 0; $i -lt 40; $i++) {
        try {
            if ((Invoke-WebRequest $url -UseBasicParsing -TimeoutSec 3).StatusCode -eq 200) {
                Write-Host "  $Label healthy" -ForegroundColor Green
                return $true
            }
        } catch {}
        Start-Sleep 2
    }
    Write-Host "  $Label did NOT become healthy — see _$Label.err" -ForegroundColor Red
    return $false
}

Write-Host "Waiting for backends..." -ForegroundColor Gray
$aOk = Wait-Health 8000 "cluster-a-api"
$bOk = Wait-Health 8002 "cluster-b-api"

if (-not ($aOk -and $bOk)) {
    Write-Host "One or more backends failed to start. Aborting UI launch." -ForegroundColor Red
    exit 1
}

# ── Start the UI (foreground; Ctrl+C stops just the UI) ───────────────────────
Write-Host ""
Write-Host "Backends up. Starting UI at http://localhost:5173 ..." -ForegroundColor Cyan
Write-Host "Login: alice / demo (left)   bob / demo (right)" -ForegroundColor Gray
Write-Host "Stop everything later with:  .\launch_all.ps1 -Stop" -ForegroundColor Gray
Write-Host ""

Stop-Port 5173
Set-Location (Join-Path $root "ui")
$env:NODE_OPTIONS = "--use-system-ca"
npx vite --mode prod

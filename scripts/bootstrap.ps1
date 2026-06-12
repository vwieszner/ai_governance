# One-shot fresh-machine bring-up for the AGT federated-RAG product (Windows).
#
#   powershell -File scripts\bootstrap.ps1                 # alpha + beta (the demo pair)
#   powershell -File scripts\bootstrap.ps1 -ThreeDivisions # + gamma
#   powershell -File scripts\bootstrap.ps1 -SkipDeps       # infra only (venv/npm already done)
#
# Prereqs it checks for you: Python 3.11+, Node 18+, a running Docker daemon, and an
# NVIDIA_API_KEY (or any OpenAI-compatible key) in .\.env. Everything else - venv,
# pinned Python deps, npm packages, per-division Docker stacks, Keycloak/OpenFGA/DID
# provisioning, federation cross-wiring, agent processes - is done here, idempotently.
# Re-running is safe: onboarding is idempotent and running stacks are left alone.
#
# NOTE: keep this file pure ASCII. Windows PowerShell 5.1 reads BOM-less files as ANSI,
# and UTF-8 punctuation (em-dashes etc.) decodes into curly quotes that BREAK parsing.
param(
    [switch]$ThreeDivisions,
    [switch]$SkipDeps
)
# EAP must be Continue, NOT Stop: docker compose prints normal progress to STDERR, and
# Windows PowerShell 5.1 wraps native stderr in ErrorRecords - under Stop that kills the
# script on a healthy "Container ... Running" line. We gate on $LASTEXITCODE instead.
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Fail($msg) { Write-Host "`n[bootstrap] FATAL: $msg" -ForegroundColor Red; exit 1 }
function Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
# Run a native command, merging stderr into stdout as PLAIN STRINGS. PS 5.1 wraps native
# stderr lines in ErrorRecords; stringifying them keeps healthy stderr progress (docker
# compose prints there) from looking like errors, while we still gate on the exit code.
function Run-Native([string]$exe, [string[]]$cmdArgs) {
    # Write-Host (not the output stream) so `$rc = Run-Native ...` captures ONLY the
    # returned exit code - in PS a function's return value includes all pipeline output.
    & $exe @cmdArgs 2>&1 | ForEach-Object { Write-Host "$_" }
    return $LASTEXITCODE
}

# -- 1. Prerequisites ----------------------------------------------------------
Step "Checking prerequisites"
$pyExe = $null
foreach ($cand in @('py -3.12', 'py -3.11', 'python')) {
    try {
        $v = Invoke-Expression "$cand --version" 2>$null
        if ($v -match 'Python 3\.(\d+)' -and [int]$Matches[1] -ge 11) { $pyExe = $cand; break }
    } catch {}
}
if (-not $pyExe) { Fail "Python 3.11+ not found on PATH (install from python.org, then re-run)." }
Write-Host "  python : $pyExe"

if (-not (Get-Command node -ErrorAction SilentlyContinue)) { Fail "Node 18+ not found on PATH (install from nodejs.org)." }
$nodeV = node --version
if ([int]($nodeV -replace '^v(\d+).*', '$1') -lt 18) { Fail "Node 18+ required, found $nodeV." }
Write-Host "  node   : $nodeV"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Fail "Docker not found on PATH (install Docker Desktop)." }
docker info *> $null
if ($LASTEXITCODE -ne 0) { Fail "Docker daemon not reachable. Start Docker Desktop and re-run." }
Write-Host "  docker : OK"

# LLM key: onboard_division.py reads NVIDIA_API_KEY from .\.env and writes it into
# each agent's gitignored .env.<division>.
$envFile = Join-Path $root '.env'
$hasKey = (Test-Path $envFile) -and ((Get-Content $envFile -Raw) -match 'NVIDIA_API_KEY\s*=\s*\S')
if (-not $hasKey -and -not $env:NVIDIA_API_KEY) {
    Fail "No LLM key. Put NVIDIA_API_KEY=<your key> in $envFile (any OpenAI-compatible key works; the base URL is set per agent env). Then re-run."
}
Write-Host "  LLM key: present"

# -- 2. Python venv + pinned deps ------------------------------------------------
$venvPy = Join-Path $root '.venv\Scripts\python.exe'
if (-not $SkipDeps) {
    Step "Python venv + dependencies (pinned: agt-federated-rag\requirements.lock.txt)"
    if (-not (Test-Path $venvPy)) { Invoke-Expression "$pyExe -m venv `"$root\.venv`"" }
    & $venvPy -m pip install --quiet --upgrade pip
    & $venvPy -m pip install --quiet -r (Join-Path $root 'agt-federated-rag\requirements.lock.txt')
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  pip hit an error - on corporate-TLS networks retry with: pip install --use-feature=truststore -r agt-federated-rag\requirements.lock.txt" -ForegroundColor Yellow
        Fail "Python dependency install failed."
    }
    Write-Host "  venv ready: $venvPy"

    # -- 3. UI deps --------------------------------------------------------------
    Step "UI dependencies (npm install)"
    Push-Location (Join-Path $root 'ui')
    npm install --no-audit --no-fund 2>&1 | Select-Object -Last 1
    if ($LASTEXITCODE -ne 0) {
        # Corporate TLS interception: retry trusting the OS certificate store.
        Write-Host "  npm failed - retrying with system CA (corporate-TLS networks)" -ForegroundColor Yellow
        $env:NODE_OPTIONS = '--use-system-ca'
        npm install --no-audit --no-fund 2>&1 | Select-Object -Last 1
        if ($LASTEXITCODE -ne 0) { Pop-Location; Fail "npm install failed." }
    }
    Pop-Location
    # UI env: copy the committed example (live-division topology) and inject the key.
    $uiProd = Join-Path $root 'ui\.env.prod'
    if (-not (Test-Path $uiProd)) {
        Copy-Item (Join-Path $root 'ui\.env.example') $uiProd
        $key = $env:NVIDIA_API_KEY
        if (-not $key -and (Test-Path $envFile)) {
            $m = Select-String -Path $envFile -Pattern '^NVIDIA_API_KEY\s*=\s*(\S+)'
            if ($m) { $key = $m.Matches[0].Groups[1].Value }
        }
        if ($key) { (Get-Content $uiProd) -replace '^NVIDIA_API_KEY=$', "NVIDIA_API_KEY=$key" | Set-Content $uiProd }
        Write-Host "  created ui\.env.prod from .env.example (gitignored)"
    }
}

# -- 4. Onboard divisions (stack + provisioning, idempotent) ---------------------
$divisions = @('alpha', 'beta')
if ($ThreeDivisions) { $divisions += 'gamma' }
foreach ($d in $divisions) {
    Step "Onboarding division '$d' (Docker stack + Keycloak/OpenFGA/DID/ingest)"
    $rc = Run-Native $venvPy @((Join-Path $root 'scripts\onboard_division.py'), (Join-Path $root "infra\divisions\$d.yml"))
    if ($rc -ne 0) { Fail "Onboarding '$d' failed - see output above." }
}

# -- 5. Federate (cross-wire peer DIDs, issuers, trust map) ----------------------
Step "Federating divisions ($($divisions -join ' <-> '))"
$rc = Run-Native $venvPy (@((Join-Path $root 'scripts\federate_divisions.py'), '--only') + $divisions)
if ($rc -ne 0) { Fail "Federation failed - see output above." }

# -- 6. Start agents + workers, verify health ------------------------------------
Step "Starting agents + Temporal workers"
& (Join-Path $root 'scripts\clusters.ps1') restart all
& (Join-Path $root 'scripts\clusters.ps1') status all

# -- 7. Done - how to demo --------------------------------------------------------
Step "DONE - next steps"
Write-Host "  UI:        cd ui; npm run start          ->  http://localhost:5173" -ForegroundColor Green
Write-Host "  Logins:    left  = alice  (password: infra\generated\alpha\secrets.json -> seed_user_password)" -ForegroundColor Green
Write-Host "             right = bob    (password: infra\generated\beta\secrets.json  -> seed_user_password)" -ForegroundColor Green
Write-Host "  Verify:    cd agt-federated-rag; ..\.venv\Scripts\python.exe -m pytest tests -q" -ForegroundColor Green
Write-Host "  UI e2e:    cd ui; npm run e2e            (needs the UI dev server running)" -ForegroundColor Green
Write-Host "  TIP:       run one throwaway query per pane first - the free-tier LLM cold-starts" -ForegroundColor Green
Write-Host "             (~1-2 min); warm queries answer in seconds." -ForegroundColor Green

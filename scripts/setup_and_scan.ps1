# PRAS — Full Setup + Scan for any GitHub Repo
# ─────────────────────────────────────────────
# Installs every dependency, starts Neo4j + Ollama, clones the target repo,
# runs Pipeline A, and opens the risk report in your browser.
#
# Usage:
#   .\scripts\setup_and_scan.ps1 -RepoUrl "https://github.com/owner/repo"
#   .\scripts\setup_and_scan.ps1 -RepoUrl "https://github.com/owner/repo" -WithNeo4j
#   .\scripts\setup_and_scan.ps1 -RepoUrl "https://github.com/owner/repo" -WithLLM
#   .\scripts\setup_and_scan.ps1 -RepoUrl "https://github.com/owner/repo" -WithNeo4j -WithLLM
#
# Flags:
#   -RepoUrl    (Required) Full GitHub HTTPS URL of the repo to scan
#   -WithNeo4j  Start Neo4j via Docker and enable graph phases (requires Docker Desktop)
#   -WithLLM    Enable Ollama LLM explanations (requires Ollama installed + llama3 pulled)
#   -OutputDir  Where to write the report (default: .\scans\<repo-name>)
#   -SkipClone  If set, expects the repo already cloned under .\scans\repos\<name>
#   -Branch     Git branch to check out after cloning (default: repo default branch)

param(
    [Parameter(Mandatory)][string]$RepoUrl,
    [switch]$WithNeo4j,
    [switch]$WithLLM,
    [string]$OutputDir = "",
    [switch]$SkipClone,
    [string]$Branch = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

# ── Helpers ────────────────────────────────────────────────────────────────────

function Write-Step([string]$msg) {
    Write-Host ""
    Write-Host "══ $msg" -ForegroundColor Cyan
}

function Write-OK([string]$msg) { Write-Host "  ✔ $msg" -ForegroundColor Green }
function Write-Warn([string]$msg) { Write-Host "  ⚠ $msg" -ForegroundColor Yellow }
function Write-Fail([string]$msg) { Write-Host "  ✘ $msg" -ForegroundColor Red }

function Assert-Command([string]$cmd, [string]$installHint) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Fail "$cmd not found on PATH."
        Write-Host "  → $installHint" -ForegroundColor Yellow
        exit 1
    }
    Write-OK "$cmd found"
}

function Wait-HealthCheck([string]$url, [string]$label, [int]$timeoutSec = 60) {
    Write-Host "  Waiting for $label to be ready..." -NoNewline
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
            if ($r.StatusCode -lt 500) {
                Write-Host " ready." -ForegroundColor Green
                return
            }
        } catch {}
        Write-Host "." -NoNewline
        Start-Sleep 3
    }
    Write-Host ""
    Write-Warn "$label did not respond within ${timeoutSec}s — continuing anyway."
}

# ── Banner ──────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║   PRAS — Predictive Risk Assessment System           ║" -ForegroundColor Magenta
Write-Host "║   Full Setup + Scan                                  ║" -ForegroundColor Magenta
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host "  Target : $RepoUrl"
Write-Host "  Neo4j  : $(if ($WithNeo4j) { 'enabled' } else { 'disabled (pass -WithNeo4j to enable)' })"
Write-Host "  LLM    : $(if ($WithLLM)   { 'enabled' } else { 'disabled (pass -WithLLM to enable)' })"

# ── Phase 1: Prerequisite checks ───────────────────────────────────────────────

Write-Step "Phase 1 — Checking prerequisites"

Assert-Command "python"  "Install Python 3.10+ from https://python.org/downloads"
Assert-Command "git"     "Install Git from https://git-scm.com/download/win"
Assert-Command "semgrep" "pip install semgrep   (or: winget install semgrep.semgrep)"

# Optional tools — warn but don't abort
if ($WithNeo4j) {
    Assert-Command "docker" "Install Docker Desktop from https://www.docker.com/products/docker-desktop"
}
if ($WithLLM) {
    Assert-Command "ollama" "Install Ollama from https://ollama.com/download"
}

# Check Python version >= 3.10
$pyVer = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
if (-not $pyVer -or ([version]$pyVer -lt [version]"3.10")) {
    Write-Fail "Python 3.10+ required (found: $pyVer)"
    exit 1
}
Write-OK "Python $pyVer"

# ── Phase 2: Python virtual environment ────────────────────────────────────────

Write-Step "Phase 2 — Python virtual environment"

if (-not (Test-Path "venv\Scripts\python.exe")) {
    Write-Host "  Creating venv..."
    python -m venv venv
    Write-OK "venv created"
} else {
    Write-OK "venv already exists"
}

Write-Host "  Installing core dependencies..."
& .\venv\Scripts\pip install -q --upgrade pip
& .\venv\Scripts\pip install -q -r requirements-core.txt
Write-OK "requirements-core.txt installed"

if ($WithNeo4j) {
    Write-Host "  Installing graph dependencies..."
    & .\venv\Scripts\pip install -q -r requirements-graph.txt
    Write-OK "requirements-graph.txt installed"
}

# ── Phase 3: Environment / .env ────────────────────────────────────────────────

Write-Step "Phase 3 — Environment configuration"

if (-not (Test-Path ".env")) {
    Write-Host "  Creating .env with defaults..."
    @"
NEO4J_PASSWORD=demo-password
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3
"@ | Set-Content ".env" -Encoding UTF8
    Write-OK ".env created"
} else {
    # Ensure all keys exist without overwriting user values
    $envContent = Get-Content ".env" -Raw
    $defaults = @{
        "NEO4J_PASSWORD"   = "demo-password"
        "NEO4J_URI"        = "bolt://localhost:7687"
        "NEO4J_USER"       = "neo4j"
        "OLLAMA_BASE_URL"  = "http://localhost:11434"
        "OLLAMA_MODEL"     = "llama3"
    }
    $changed = $false
    foreach ($key in $defaults.Keys) {
        if ($envContent -notmatch "(?m)^$key\s*=") {
            Add-Content ".env" "`n$key=$($defaults[$key])"
            $changed = $true
        }
    }
    if ($changed) { Write-OK ".env updated with missing keys" }
    else          { Write-OK ".env already configured" }
}

# Read NEO4J_PASSWORD for docker-compose
$neo4jPass = (Get-Content ".env" | Where-Object { $_ -match "^NEO4J_PASSWORD\s*=" }) -replace "^NEO4J_PASSWORD\s*=\s*", "" | Select-Object -First 1
if (-not $neo4jPass) { $neo4jPass = "demo-password" }

# ── Phase 4: Neo4j ─────────────────────────────────────────────────────────────

if ($WithNeo4j) {
    Write-Step "Phase 4 — Neo4j (Docker)"

    # Check Docker daemon is running
    $dockerOk = docker info 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Docker daemon is not running. Start Docker Desktop and retry."
        exit 1
    }
    Write-OK "Docker daemon running"

    # Check if neo4j container already running
    $running = docker ps --filter "name=pras-neo4j" --format "{{.Names}}" 2>$null
    if ($running -match "pras-neo4j") {
        Write-OK "Neo4j container already running"
    } else {
        Write-Host "  Starting Neo4j container..."
        $env:NEO4J_PASSWORD = $neo4jPass
        docker compose up -d 2>&1 | ForEach-Object { Write-Host "    $_" }
        if ($LASTEXITCODE -ne 0) {
            # Fallback: run standalone without compose naming
            Write-Warn "docker compose failed, trying standalone docker run..."
            docker run -d --name pras-neo4j `
                -p 7474:7474 -p 7687:7687 `
                -e NEO4J_AUTH="neo4j/$neo4jPass" `
                -e NEO4J_server_memory_heap_max__size="512m" `
                -e NEO4J_server_memory_pagecache_size="256m" `
                neo4j:5-community 2>&1
        }
        Write-OK "Neo4j container started"
    }

    Wait-HealthCheck "http://localhost:7474" "Neo4j" 90
} else {
    Write-Step "Phase 4 — Neo4j"
    Write-Warn "Skipped (use -WithNeo4j to enable graph analysis)"
}

# ── Phase 5: Ollama ────────────────────────────────────────────────────────────

if ($WithLLM) {
    Write-Step "Phase 5 — Ollama LLM"

    # Start ollama serve in background if not already running
    $ollamaRunning = $false
    try {
        $r = Invoke-WebRequest -Uri "http://localhost:11434" -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
        $ollamaRunning = $r.StatusCode -lt 500
    } catch {}

    if (-not $ollamaRunning) {
        Write-Host "  Starting Ollama server..."
        Start-Process -FilePath "ollama" -ArgumentList "serve" -WindowStyle Hidden
        Start-Sleep 4
        Wait-HealthCheck "http://localhost:11434" "Ollama" 30
    } else {
        Write-OK "Ollama server already running"
    }

    # Pull model if not present
    $ollamaModel = (Get-Content ".env" | Where-Object { $_ -match "^OLLAMA_MODEL\s*=" }) -replace "^OLLAMA_MODEL\s*=\s*", "" | Select-Object -First 1
    if (-not $ollamaModel) { $ollamaModel = "llama3" }

    Write-Host "  Checking model '$ollamaModel'..."
    $models = ollama list 2>$null
    if ($models -match $ollamaModel) {
        Write-OK "Model '$ollamaModel' already pulled"
    } else {
        Write-Host "  Pulling '$ollamaModel' (this may take several minutes)..."
        ollama pull $ollamaModel
        Write-OK "Model '$ollamaModel' pulled"
    }
} else {
    Write-Step "Phase 5 — Ollama LLM"
    Write-Warn "Skipped (use -WithLLM to enable AI explanations)"
}

# ── Phase 6: Clone target repo ─────────────────────────────────────────────────

Write-Step "Phase 6 — Target repository"

# Extract repo name from URL
$repoName = ($RepoUrl -split "/")[-1] -replace "\.git$", ""
$reposDir = Join-Path $Root "scans\repos"
$repoPath = Join-Path $reposDir $repoName

if ($SkipClone -and (Test-Path $repoPath)) {
    Write-OK "Using existing clone at $repoPath"
} elseif (Test-Path $repoPath) {
    Write-Host "  Repo directory exists — pulling latest changes..."
    Push-Location $repoPath
    git pull --ff-only 2>&1 | ForEach-Object { Write-Host "    $_" }
    Pop-Location
    Write-OK "Repository updated: $repoPath"
} else {
    New-Item -ItemType Directory -Force -Path $reposDir | Out-Null
    Write-Host "  Cloning $RepoUrl ..."
    git clone --depth 1 $RepoUrl $repoPath 2>&1 | ForEach-Object { Write-Host "    $_" }
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "git clone failed. Check the URL and your internet connection."
        exit 1
    }
    Write-OK "Cloned to $repoPath"
}

if ($Branch) {
    Push-Location $repoPath
    git checkout $Branch 2>&1 | ForEach-Object { Write-Host "    $_" }
    Pop-Location
    Write-OK "Checked out branch: $Branch"
}

# ── Phase 7: Resolve output directory ──────────────────────────────────────────

if (-not $OutputDir) {
    $OutputDir = Join-Path $Root "scans\reports\$repoName"
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
Write-OK "Output directory: $OutputDir"

# ── Phase 8: Build pipeline arguments ──────────────────────────────────────────

Write-Step "Phase 7 — Running Pipeline A"

$pipelineArgs = @(
    "pipeline_a.py",
    "--project-dir", $repoPath,
    "--output-dir", $OutputDir
)

# --present sets --no-graph internally, so skip it when Neo4j graph is requested
if (-not $WithNeo4j) { $pipelineArgs += "--present" }
if (-not $WithLLM)   { $pipelineArgs += "--skip-llm" }
if (-not $WithNeo4j) { $pipelineArgs += "--offline" }
if ($WithNeo4j)      { $pipelineArgs += "--neo4j" }

Write-Host "  Command: python $($pipelineArgs -join ' ')"
Write-Host ""

& .\venv\Scripts\python @pipelineArgs
$exitCode = $LASTEXITCODE

# ── Phase 9: Open report ────────────────────────────────────────────────────────

Write-Host ""
if ($exitCode -ne 0) {
    Write-Fail "Pipeline exited with code $exitCode."
    Write-Host "  Check the output above for errors."
    Write-Host "  Common fixes:"
    Write-Host "    • Semgrep not on PATH: pip install semgrep"
    Write-Host "    • Neo4j not reachable: docker compose up -d"
    Write-Host "    • Missing deps:        .\venv\Scripts\pip install -r requirements-core.txt"
    exit $exitCode
}

$report = Join-Path $OutputDir "risk_report.html"
if (Test-Path $report) {
    Write-Host "══ Done ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Report : $report" -ForegroundColor White
    Write-Host "  Repo   : $repoPath" -ForegroundColor White
    if ($WithNeo4j) {
        Write-Host "  Neo4j  : http://localhost:7474  (user: neo4j / pass: $neo4jPass)" -ForegroundColor White
        Write-Host "  Explorer: $Root\neo4j_explorer.html" -ForegroundColor White
    }
    Write-Host ""
    Start-Process $report
    Write-OK "Report opened in browser"
} else {
    Write-Warn "Pipeline finished but risk_report.html was not found at $report"
    Write-Host "  Check $OutputDir for partial output."
}

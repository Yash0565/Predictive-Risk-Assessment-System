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
#   -RepoUrl    (Required) GitHub HTTPS URL to clone, OR a local directory path
#               which is scanned in place. The local path may be anywhere on disk
#               and may be absolute (e.g. D:\mini-demo-app) or relative to your
#               current shell location (e.g. .\mini-demo-app or ..\mini-demo-app).
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
# Remember where the caller invoked us from, so a relative -RepoUrl (e.g.
# ".\my-app" or "..\my-app") resolves against their shell's location — not the
# PRAS repo root we're about to switch into. Absolute paths are unaffected.
$InvocationDir = (Get-Location).Path
Set-Location $Root

# ── Helpers ────────────────────────────────────────────────────────────────────

function Write-Step([string]$msg) {
    Write-Host ""
    Write-Host "══ $msg" -ForegroundColor Cyan
}

function Write-OK([string]$msg) { Write-Host "  ✔ $msg" -ForegroundColor Green }
function Write-Warn([string]$msg) { Write-Host "  ⚠ $msg" -ForegroundColor Yellow }
function Write-Fail([string]$msg) { Write-Host "  ✘ $msg" -ForegroundColor Red }

# Bold (ANSI SGR 1); resets after. Falls back to plain text on terminals that
# don't parse escapes. Kept separate so callers can still set -ForegroundColor.
$script:Esc = [char]27
function BoldText([string]$msg) { "$script:Esc[1m$msg$script:Esc[0m" }

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
Write-Host "  Graph  : $(if ($WithNeo4j) { 'Neo4j (live)' } else { 'JSON snapshot (no Docker needed)' })"
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
    if (-not $dockerOk) {
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

# ── Phase 6: Resolve target repo (local path or remote URL) ─────────────────────

Write-Step "Phase 6 — Target repository"

# A remote URL looks like http(s)://… or git@host:…; anything else is treated as
# a local directory (scanned in place, wherever it lives on disk). Relative paths
# are resolved against the caller's original location, not the PRAS repo root.
$isRemote = $RepoUrl -match '^(https?://|git@)'

$localCandidate = $RepoUrl
if (-not $isRemote -and -not [System.IO.Path]::IsPathRooted($RepoUrl)) {
    $localCandidate = Join-Path $InvocationDir $RepoUrl
}
$isLocal = (-not $isRemote) -and (Test-Path -LiteralPath $localCandidate -PathType Container)

# A non-remote argument that doesn't resolve to a directory is a user error —
# fail early with a clear message rather than trying to git-clone a bad path.
if (-not $isRemote -and -not $isLocal) {
    Write-Fail "Local path not found: $RepoUrl"
    Write-Host "  → Pass an existing directory, or a GitHub URL (https://… / git@…)." -ForegroundColor Yellow
    exit 1
}

if ($isLocal) {
    $repoPath = (Resolve-Path -LiteralPath $localCandidate).Path
    $repoName = Split-Path -Leaf $repoPath
    Write-OK "Using local repository: $repoPath"
} else {
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

# Graph phases always run: they use the JSON snapshot by default and only talk
# to Neo4j when -WithNeo4j is passed. (Note: --present implies --no-graph, so we
# never add it here — we use --quiet for compact output instead.)
$pipelineArgs += "--quiet"
$pipelineArgs += "--offline"
if (-not $WithLLM) { $pipelineArgs += "--skip-llm" }
if ($WithNeo4j)    { $pipelineArgs += "--neo4j" }

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
        Write-Host "  Graph  : open the report's Graph tab (rendered inline)" -ForegroundColor White
    }
    Write-Host ""
    Start-Process $report
    Write-OK "Report opened in browser"

    # ── How to read the graph (developer reference) ──────────────────────────
    Write-Host ""
    Write-Host (BoldText "How to read the graph") -ForegroundColor Cyan
    Write-Host "  Open the " -NoNewline
    Write-Host (BoldText "Graph") -ForegroundColor Cyan -NoNewline
    Write-Host " tab. It shows the reachability call graph: which functions"
    Write-Host "  reach a vulnerable symbol, and from which entry points."
    Write-Host ""
    Write-Host "  Nodes"
    Write-Host "    " -NoNewline
    Write-Host (BoldText "Entry point") -ForegroundColor Blue -NoNewline
    Write-Host "   a service/route where untrusted input enters — start reading here."
    Write-Host "    " -NoNewline
    Write-Host (BoldText "Function") -ForegroundColor Gray -NoNewline
    Write-Host "      an internal function on a call path."
    Write-Host "    " -NoNewline
    Write-Host (BoldText "BLOCK") -ForegroundColor Red -NoNewline
    Write-Host "         a vulnerable symbol that " -NoNewline
    Write-Host (BoldText "is reachable") -ForegroundColor Red -NoNewline
    Write-Host " from an entry point — fix first."
    Write-Host "    " -NoNewline
    Write-Host (BoldText "REVIEW") -ForegroundColor Yellow -NoNewline
    Write-Host "        a vulnerable symbol present but not proven reachable — verify manually."
    Write-Host ""
    Write-Host "  Edges"
    Write-Host "    An arrow " -NoNewline
    Write-Host (BoldText "A -> B") -ForegroundColor White -NoNewline
    Write-Host " means A calls B. Follow arrows from an " -NoNewline
    Write-Host (BoldText "Entry point") -ForegroundColor Blue -NoNewline
    Write-Host " to a"
    Write-Host "    " -NoNewline
    Write-Host (BoldText "BLOCK") -ForegroundColor Red -NoNewline
    Write-Host " node to trace the exact reachable path (the dependency chain)."
    Write-Host ""
    Write-Host "  Tips"
    Write-Host "    Tick " -NoNewline
    Write-Host (BoldText "BLOCK only") -ForegroundColor Red -NoNewline
    Write-Host " to hide noise and see just the reachable, must-fix paths."
    Write-Host "    Click any node for its file, symbol, and CVE details in the side panel."
    Write-Host "    Use " -NoNewline
    Write-Host (BoldText "Reset view") -ForegroundColor White -NoNewline
    Write-Host " to re-center after zooming/dragging."
} else {
    Write-Warn "Pipeline finished but risk_report.html was not found at $report"
    Write-Host "  Check $OutputDir for partial output."
}

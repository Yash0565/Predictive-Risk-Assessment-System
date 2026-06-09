# Team demo — full Pipeline A run on the bundled sample app.
# Requires: Python 3.10+, Semgrep on PATH, optional Trivy for live scans.
#
# Usage:
#   .\scripts\demo.ps1
#   .\scripts\demo.ps1 -Quick          # skip pipeline; open sample HTML only
#   .\scripts\demo.ps1 -WithGraph      # include Neo4j graph phases (slower)

param(
    [switch]$Quick,
    [switch]$WithGraph,
    [string]$OutputDir = "output"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

function Ensure-Venv {
    if (-not (Test-Path "venv\Scripts\python.exe")) {
        Write-Host "Creating venv and installing requirements-core.txt ..."
        python -m venv venv
        & .\venv\Scripts\pip install -q -r requirements-core.txt
    }
}

function Open-Report {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        Write-Error "Report not found: $Path"
    }
    Write-Host ""
    Write-Host "Opening $Path"
    Start-Process $Path
}

if ($Quick) {
    Ensure-Venv
    $sample = Join-Path $OutputDir "sample_report.html"
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    & .\venv\Scripts\python -c @"
from src.html_reporter_final_v2 import assemble_sample_report
assemble_sample_report(r'$sample', offline=True)
print('Sample report written.')
"@
    Open-Report $sample
    exit 0
}

Ensure-Venv

$args = @(
    "pipeline_a.py",
    "--project-dir", "./vulnerable-task-tracker",
    "--output-dir", "./$OutputDir",
    "--skip-llm",
    "--present",
    "--offline"
)

if ($WithGraph) {
    $args = $args | Where-Object { $_ -ne "--present" }
    $args += "--neo4j"
    Write-Host "Graph mode: ensure Neo4j is up (docker compose up -d) and requirements-graph.txt is installed."
}

Write-Host ""
Write-Host "Running Pipeline A (expect ~5–15 min on first run; Semgrep + patch fetch) ..."
Write-Host "Command: python $($args -join ' ')"
Write-Host ""

& .\venv\Scripts\python @args
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Open-Report (Join-Path $OutputDir "risk_report.html")

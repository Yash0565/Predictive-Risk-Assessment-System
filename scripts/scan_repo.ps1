# Scan any Python repository with Pipeline A.
#
# Usage:
#   .\scripts\scan_repo.ps1 -RepoPath "D:\path\to\your-repo"
#   .\scripts\scan_repo.ps1 -RepoPath "D:\path\to\your-repo" -WithGraph
#   .\scripts\scan_repo.ps1 -RepoPath "D:\path\to\your-repo" -OutputDir "D:\scans\run-1"

param(
    [Parameter(Mandatory)][string]$RepoPath,
    [string]$OutputDir = "",
    [switch]$WithGraph,
    [switch]$Offline = $true
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$repo = (Resolve-Path $RepoPath).Path
if (-not $OutputDir) {
    $OutputDir = Join-Path $repo ".risk-scan"
}

function Ensure-Venv {
    if (-not (Test-Path "venv\Scripts\python.exe")) {
        Write-Host "Creating venv and installing requirements-core.txt ..."
        python -m venv venv
        & .\venv\Scripts\pip install -q -r requirements-core.txt
    }
}

Ensure-Venv

$args = @(
    "pipeline_a.py",
    "--project-dir", $repo,
    "--output-dir", $OutputDir,
    "--skip-llm",
    "--present"
)

if ($Offline) { $args += "--offline" }
if ($WithGraph) {
    $args = $args | Where-Object { $_ -ne "--present" }
    $args += "--neo4j"
    Write-Host "Graph mode: optional Neo4j (docker compose up -d) and requirements-graph.txt"
}

Write-Host ""
Write-Host "Target repo: $repo"
Write-Host "Output dir:  $OutputDir"
Write-Host "Command:     python $($args -join ' ')"
Write-Host ""

& .\venv\Scripts\python @args
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$report = Join-Path $OutputDir "risk_report.html"
Write-Host ""
Write-Host "Report: $report"
Start-Process $report

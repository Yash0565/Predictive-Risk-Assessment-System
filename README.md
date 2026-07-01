# Predictive Risk Assessment System

Pre-upgrade risk analysis for Python projects. It discovers pinned dependencies,
finds CVEs with Trivy, maps each patch to the symbols it changed, checks whether
your code actually reaches those symbols, runs Semgrep rules (official registry
plus patch-aware sinks), simulates dependency upgrades, scores risk
deterministically, and emits a tabbed HTML report.

The verdict (BLOCK / REVIEW / PROCEED) always comes from the deterministic scorer
in `src/scorer.py`. The optional LLM only helps generate scan rules; it never
decides the outcome.

## Why it is useful

A raw Trivy scan of pinned dependencies typically reports dozens of CVEs, most of
which your code never touches. This tool narrows that list to the CVEs whose
vulnerable APIs your code actually calls, then explains the impact and simulates
the upgrade so you can decide with evidence instead of guesswork.

Typical run on the bundled sample app: ~80 CVEs in pins, a handful reach the code,
one BLOCK verdict, and an HTML report you open in a browser.

## Requirements

| Component | Purpose | Required |
| --- | --- | --- |
| Python 3.11+ | Runtime | Yes |
| `pip install -r requirements-core.txt` | Pipeline, scanners, HTML report | Yes |
| [Trivy](https://github.com/aquasecurity/trivy) | Live CVE discovery (`trivy fs`) | For live scans |
| [Semgrep](https://semgrep.dev/) | Static rule scanning (Phase 4) | For live scans |
| `pip install -r requirements-graph.txt` | Neo4j graph phases | Optional |
| [Ollama](https://ollama.com) | LLM rule generation (`ollama pull qwen2.5:3b`) | Optional |
| Gemini API key | Alternative LLM (`GOOGLE_API_KEY` in `.env`) | Optional |

`pip install -r requirements.txt` is equivalent to `requirements-core.txt`.

## Quick start

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements-core.txt

# Full pipeline on the bundled sample app
python pipeline_a.py `
  --project-dir ./vulnerable-task-tracker `
  --output-dir ./output `
  --skip-llm --present --offline
```

Open `output/risk_report.html` when the run finishes.

`--present` is presentation mode: colored compact tables, and it skips the graph
phases (equivalent to `--quiet --no-graph`).

## Scan any Python repository

Point `--project-dir` at any Python project. Paths are scoped to that repo, so the
tool does not reuse this repo's files when scanning elsewhere.

```powershell
# Convenience wrapper (artifacts go to <your-repo>/.risk-scan/)
.\scripts\scan_repo.ps1 -RepoPath "D:\path\to\your-python-app"

# Or directly
python pipeline_a.py `
  --project-dir "D:\path\to\your-python-app" `
  --skip-llm --present --offline
```

The target repo should contain Python source and pinned dependencies in
`requirements.txt`, `pyproject.toml`, or `Pipfile` (with `==` pins so the upgrade
simulator can run). Optionally add a `services.yaml` to declare HTTP entry points
for the graph; see `vulnerable-task-tracker/services.yaml` for the format.

| Default | Location |
| --- | --- |
| Artifacts | `<project-dir>/.risk-scan/` |
| Trivy input | `<output-dir>/enriched_trivy_output.json` (live `trivy fs` when missing) |
| Graph entry points | `<project-dir>/services.yaml` if present, else auto-discovered routes |

## Command-line flags

| Flag | Effect |
| --- | --- |
| `--project-dir` | Target Python project to analyze |
| `--output-dir` | Where JSON/HTML artifacts are written (default: `<project-dir>/.risk-scan`) |
| `--input` | Trivy enriched JSON (default: `<output-dir>/enriched_trivy_output.json`) |
| `--services` | Entry-points YAML (`auto` = `<project-dir>/services.yaml` or route discovery) |
| `--skip-llm` | Use registry and patch-aware symbol rules only (no Ollama/Gemini) |
| `--present` | Colored compact terminal output; skips graph phases |
| `--quiet` | Compact tables; suppress per-family logs |
| `--plain` | Disable terminal colors |
| `--no-graph` | Skip graph build and query phases |
| `--offline` | Inline vendor JS/CSS in the HTML report |
| `--neo4j` | Use the Bolt driver for graph queries |
| `--llm gemini` | Use Gemini instead of Ollama for rule generation |

## Pipeline phases

The pipeline (`pipeline_a.py`) runs a fixed 12-phase sequence. Core modules live
under `src/`.

| Phase | Module | Input | Output |
| --- | --- | --- | --- |
| Preflight | `tool_registry.run_trivy_on_repo` | `--project-dir` | `enriched_trivy_output.json` (when `--input` missing) |
| 1 Normalize | `normalizer.py` | Trivy JSON | CWE families (in memory) |
| 2 Patches | `patch_fetcher.py` | CVE list | `patches.json` (+ cache in `data/patches/`) |
| 3 Rules | `rule_resolver.py`, `registry_matcher.py`, `symbol_rule_builder.py` | Families + patches | `{output_dir}/semgrep_rules/*.yaml` |
| 4 Semgrep | `executor.py` | Resolved rules | Semgrep matches (in memory) |
| 5 Report | `reporter.py` | Matches | `pipeline_a_report.json` |
| 6 Reachability | `symbol_scanner.py` | Patches + project AST | `symbol_scan.json` |
| 7 Upgrade sim | `upgrade_simulator.py`, `project_deps.py` | Reachable CVEs + pins | `upgrade_simulation.json` |
| 8 Graph build | `graph_builder.py`, `static_analyzer.py` | Trivy, Semgrep, `services.yaml` | `graph_snapshot.json` (+ optional Neo4j) |
| 9 Graph queries | `graph_queries.py` | Graph snapshot / Neo4j | Reachability evidence (in memory) |
| 10 Score | `scorer.py` | Trivy + graph evidence | `risk_assessment.json` |
| 11 Explain | `explainer.py` | Assessment | `explanations.json` |
| 12 HTML report | `html_reporter_final_v2.py` | All JSON artifacts | `risk_report.html` |

Rules in Phase 3 are resolved from three live sources, with no frozen demo
overlay: the local cache (`data/rules_db.json` plus validated on-disk YAML), the
official Semgrep registry matched by CWE (`data/cwe_rule_map.json`), and,
optionally, an LLM (`--skip-llm` disables it). Patch-aware sink rules are then
layered on top (for example `yaml.load`, `Image.open`).

## ReAct agent (optional)

An alternative, LLM-driven entry point for interactive investigation. It calls the
same core tools through a fixed whitelist; the verdict still comes from the
deterministic scorer.

```powershell
python -m src.agent --target ./vulnerable-task-tracker --verbose
python -m src.agent --target ./vulnerable-task-tracker --no-llm
```

Requires Trivy for live CVE scans. The step trace is written to
`data/agent_trace.json` (gitignored). The agent does not run the Semgrep or graph
phases; use `pipeline_a.py` for full analysis.

## Optional: Neo4j graph

```powershell
# Set NEO4J_PASSWORD in .env first
docker compose up -d
pip install -r requirements-graph.txt
python pipeline_a.py --project-dir ./vulnerable-task-tracker --neo4j --skip-llm --offline
```

The pipeline completes without Neo4j using the JSON snapshot; the driver is only
needed for Cypher-based reachability queries. `neo4j_explorer.html` is a
standalone browser UI for exploring the graph against a running Neo4j instance.
The default local password in `docker-compose.yml` is `demo-password` (dev only).

## Sample report without a full run

```powershell
python -c "from src.html_reporter import assemble_sample_report; assemble_sample_report('sample_report.html', offline=True)"
```

Uses `tests/fixtures/symbol_scan_output.json` plus synthetic assessment data.

## Tests

```powershell
pip install -r requirements-core.txt
pytest tests/ -q
```

CI (GitHub Actions) runs the suite on Python 3.11 and 3.12, plus an integrity
guard that fails if demo overlays are reintroduced, and the benchmark harness.

## Repository layout

```
pipeline_a.py              12-phase pipeline entry point
src/                       Core modules (patch fetcher, symbol scanner, scorer, ...)
  api/                     Multi-tenant service: RBAC, tenant isolation, audit log
  ml/                      Deterministic exploit model + cross-scan flywheel
tests/                     Unit tests and fixtures
templates/                 Jinja templates for the HTML report
static/vendor/             Vendored JS/CSS for offline reports
scripts/                   Demo and maintenance scripts
data/                      Committed offline caches (see below)
semgrep-rules/             Official Semgrep rules (fetched, gitignored — see below)
vulnerable-task-tracker/   Sample Flask app with real CVE reachability
neo4j_explorer.html        Standalone graph explorer UI
docker-compose.yml         Neo4j 5 Community for local graph phases
```

### Committed offline caches (`data/`)

These are intentionally committed so the tool runs offline and in CI without
network access.

| Store | Path | Used by |
| --- | --- | --- |
| Patch cache | `data/patches/{CVE}.json` | patch_fetcher, symbol_scanner (30-day TTL) |
| deps.dev graphs | `data/depsdev/PyPI/` | upgrade_simulator |
| OSV snapshots | `data/osv/` | upgrade conflict analysis |
| EPSS / KEV | `data/epss_snapshot.json`, `data/kev_snapshot.json` | scorer |
| Rule cache | `data/rules_db.json` | rule_resolver |
| Semgrep registry index | `data/cwe_rule_map.json` | registry_matcher |

Refresh the deps.dev cache with `python scripts/populate_depsdev_cache.py`, and
rebuild the Semgrep registry index with `python scripts/index_registry.py`. Set
`GITHUB_TOKEN` for higher GitHub API rate limits when fetching patches.

The `semgrep-rules/` directory holds the official Semgrep rule set that
`data/cwe_rule_map.json` points to. It is large and gitignored, so fetch it once
after cloning (it clones from `github.com/semgrep/semgrep-rules` and reindexes):

```powershell
python scripts/index_registry.py
```

## Generated output (not committed)

Runtime artifacts are gitignored: `<project-dir>/.risk-scan/`, `output/`,
`demo_out/`, `scans/`, the per-run `semgrep_rules/` under `--output-dir`, and the
report/JSON files produced by local runs. Do not commit these.

## Configuration

Local settings live in `.env` (gitignored):

```env
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=demo-password
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5:3b
# GOOGLE_API_KEY=...   # only for --llm gemini
```

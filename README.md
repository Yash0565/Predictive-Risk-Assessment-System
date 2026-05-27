# Predictive Risk Assessment System

Pre-upgrade risk analysis for Python projects: discover pinned dependencies, find CVEs (Trivy), map patches to changed symbols, check whether your code reaches those symbols, run Semgrep rules (registry + patch-aware sinks), simulate upgrades, score risk deterministically, and emit a tabbed HTML report.

**Team docs:** [ARCHITECTURE.md](ARCHITECTURE.md) · [TODO.md](TODO.md)

---

## Quick start

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements-core.txt

# Optional: graph phases + Neo4j extras
pip install -r requirements-graph.txt

# Install Trivy for live CVE scans
# https://github.com/aquasecurity/trivy

# Run the full pipeline on the bundled sample app
python pipeline_a.py ^
  --project-dir ./vulnerable-task-tracker ^
  --output-dir ./output ^
  --skip-llm --present --offline
```

Open `output/risk_report.html` in a browser when the run finishes.

**Presentation mode** (`--present`) = colored Rich tables + compact output + skip graph phases (`--quiet --no-graph`).

---

## What to install

| Component | Purpose |
|-----------|---------|
| **Python 3.10+** | Runtime |
| **`pip install -r requirements-core.txt`** | Pipeline, agent, scanners, HTML report |
| **`pip install -r requirements-graph.txt`** | Neo4j graph phases (optional) |
| **[Trivy](https://github.com/aquasecurity/trivy)** | Live CVE discovery (`trivy fs`) |
| **[Semgrep](https://semgrep.dev/)** | Static rule scanning in Phase 4 |
| **[Ollama](https://ollama.com)** | Optional LLM rule generation (`ollama pull qwen2.5:3b`) |
| **Gemini API key** | Optional; set `GOOGLE_API_KEY` in `.env` for `--llm gemini` |

`pip install -r requirements.txt` is equivalent to `requirements-core.txt`.

---

## Repository layout

```
pipeline_a.py              Main 12-phase pipeline entry point
src/                       Core modules (agent, patch fetcher, symbol scanner, scorer, …)
vulnerable-task-tracker/   Sample Flask app with real CVE reachability (use as --project-dir)
services.yaml              Entry-point routes for graph reachability (matches sample app)
data/patches/              Offline patch cache (auto-refreshed when online)
data/depsdev/              Offline deps.dev graphs for upgrade simulation
data/osv/                  OSV snapshots for conflict class D
tests/                     Unit tests + fixtures
templates/                 HTML report Jinja templates
static/vendor/             Vendored JS/CSS for offline reports
```

Generated at runtime (gitignored): `output/`, `semgrep_rules/` under `--output-dir`, `enriched_trivy_output.json`, etc.

---

## Pipeline A

### Recommended command

```powershell
python pipeline_a.py `
  --project-dir ./vulnerable-task-tracker `
  --output-dir ./output `
  --skip-llm `
  --present `
  --offline
```

### Flags

| Flag | Effect |
|------|--------|
| `--project-dir` | Target Python project to analyze |
| `--output-dir` | Where JSON/HTML artifacts are written (default: cwd) |
| `--input` | Pre-built Trivy JSON; if missing, runs `trivy fs` on project-dir |
| `--skip-llm` | Use registry + patch-aware symbol rules only (no Ollama/Gemini) |
| `--present` | Colored compact terminal output; skips graph phases |
| `--quiet` | Compact tables; suppress per-family logs |
| `--plain` | Disable terminal colors |
| `--no-graph` | Skip graph build/query phases |
| `--offline` | Inline vendor assets in HTML report |
| `--llm gemini` | Use Gemini instead of Ollama for rule generation |

### Phases

1. Ingestion & normalization (Trivy JSON → CWE families)
2. Patch intelligence (preload patches for sink rules)
3. Rule resolution (cache → registry → LLM) + patch-aware Semgrep sinks
4. Parallel Semgrep execution
5. Semgrep report JSON
6. Symbol reachability (AST scan)
7. Upgrade simulation (deps.dev)
8–9. Knowledge graph (optional Neo4j)
10. Deterministic risk scoring
11. Template explanations
12. Tabbed HTML report

### Rule generation (no demo overlay)

Rules come from three live sources:

1. **Registry** — official Semgrep rules matched by CWE
2. **Symbol sinks** — patch-aware rules from `src/symbol_rule_builder.py` (e.g. `yaml.load`, `Image.open`)
3. **LLM** — Ollama/Gemini when `--skip-llm` is not set; validated with `semgrep --validate`

---

## ReAct agent

```powershell
python -m src.agent --target ./vulnerable-task-tracker --verbose
python -m src.agent --target ./vulnerable-task-tracker --no-llm
```

The agent calls the same tools through a fixed whitelist. **PROCEED / REVIEW / BLOCK** always comes from the deterministic scorer, not the LLM.

Requires Trivy for live CVE scans. Trace output: `data/agent_trace.json` (gitignored).

---

## Sample HTML report (no pipeline run)

```powershell
python -c "from src.html_reporter import assemble_sample_report; assemble_sample_report('sample_report.html', offline=True)"
```

Uses `tests/fixtures/symbol_scan_output.json` + synthetic assessment data.

---

## Tests

```powershell
pip install -r requirements-core.txt
pytest tests/ -q
```

---

## Optional: Neo4j

```powershell
docker compose up -d
python pipeline_a.py --project-dir ./vulnerable-task-tracker --neo4j --output-dir ./output
```

Default password in `docker-compose.yml`: `demo-password` (local dev only).

---

## Caching

| Cache | Path | TTL |
|-------|------|-----|
| Patches | `data/patches/{CVE}.json` | 30 days |
| deps.dev | `data/depsdev/PyPI/` | Manual refresh via `scripts/populate_depsdev_cache.py` |
| Semgrep rules | `{output_dir}/semgrep_rules/` | Per run |

Set `GITHUB_TOKEN` for higher GitHub API rate limits when fetching patches.

---

## Team notes

- Analyze **any** Python repo by pointing `--project-dir` at it; pins are read from `requirements.txt`, `pyproject.toml`, or `Pipfile`.
- The bundled `vulnerable-task-tracker/` app is the reference target for integration tests and demos.
- Do not commit `output/`, root-level `semgrep_rules/`, or generated JSON/HTML from local runs.

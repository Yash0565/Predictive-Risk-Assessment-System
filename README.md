# Predictive Risk Assessment System

## Prerequisites

### Install Ollama

Download and install Ollama from:
[Ollama Official Website](https://ollama.com)

After installation, verify:

```bash
ollama --version
```

---

## Pull Required Ollama Model

Example using Qwen 2.5 7B:

```bash
ollama pull qwen2.5:7b
```

You can use other Ollama-supported models as well.

---

## Create Environment File

Create a `.env` file in the project root:

```env
GOOGLE_API_KEY=your_gemini_api_key
```

This is required only when using the Gemini backend.

---

# Setup Instructions

## 1. Create Virtual Environment

```powershell
python -m venv venv
```

---

## 2. Activate Virtual Environment

### Windows PowerShell

```powershell
.\venv\Scripts\Activate.ps1
```

### Git Bash

```bash
source venv/Scripts/activate
```

---

## 3. Install Dependencies

```powershell
pip install -r requirements.txt
```

---

## 4. Generate Enriched Trivy Output

If you need to regenerate the enriched Trivy output:

```powershell
python trivy_runner.py
```

This generates:

```text
enriched_trivy_output.json
```

which is used as the input for Pipeline A.

---

# Running Pipeline A

## Default Run

Uses:

- Ollama backend
- Scans the `test/` directory

```powershell
python pipeline_a.py --input enriched_trivy_output.json --project-dir ./test
```

---

## Specify Exact Ollama Model

Example using Qwen 2.5 7B:

```powershell
python pipeline_a.py --input enriched_trivy_output.json --project-dir ./test --ollama-model qwen2.5:7b
```

---

## Using Gemini Backend Instead of Ollama

```powershell
python pipeline_a.py --input enriched_trivy_output.json --project-dir ./test --llm gemini
```

---

# Presentation Demo (Phases 1–9, no LLM)

Uses frozen Trivy input, handcrafted Semgrep rules, offline EPSS/KEV, and optional Neo4j.

```powershell
# 1. Start Neo4j (optional — pipeline falls back to graph_snapshot.json)
docker compose up -d

# 2. Install graph/report dependencies
pip install -r requirements-graph.txt

# 3. Run full demo pipeline
python pipeline_a.py --demo --project-dir ./test --services services.yaml --output-dir ./demo_out

# 4. Open HTML report
start .\demo_out\risk_report.html

# 5. Future-work agent stub (mocked, no LLM)
python -m src.agent

# 6. Tear down Neo4j
docker compose down
```

If Neo4j is not running, the pipeline still completes using the JSON graph snapshot.

Skip graph phases: add `--no-graph`.

---

## Patch Fetcher (`src/patch_fetcher.py`)

The patch fetcher sits between Trivy/CVE discovery and the Symbol Scanner. For each CVE it locates the official GitHub security fix (via Trivy commit URLs, NVD, OSV, or GitHub Advisories), downloads the raw `.patch`, and parses the diff to list **exact symbols** that changed (function names, signatures, hardening vs. breaking changes).

### Why patch-aware beats CWE-pattern matching

CWE-based rules guess likely vulnerable APIs (e.g. “any `pickle.load`”). Patch-aware analysis **knows** which functions the maintainer changed to fix the CVE—e.g. `rebuild_proxies` for CVE-2023-32681 or `yaml.load`’s loader path for CVE-2020-1747—so downstream reachability and upgrade simulation target real fix sites, not generic patterns.

### Caching (offline-first)

- Cache path: `data/patches/{CVE_ID}.json`
- Fresh for **30 days**; after that, the next `fetch_patch` refreshes from the network unless the cache is still readable (network errors fall back to stale cache).
- Pre-populated demo caches ship for the eight TaskFlow CVEs so demos work without Wi‑Fi.

### Public API

```python
from src.patch_fetcher import fetch_patch, fetch_patches_batch, get_vulnerable_symbols

record = fetch_patch("CVE-2023-32681", package="requests")
symbols = get_vulnerable_symbols("CVE-2023-32681")
```

Optional: set `GITHUB_TOKEN` for higher GitHub API rate limits (anonymous `.patch` downloads work without it).

### Refresh the cache

```powershell
python -c "from src.patch_fetcher import fetch_patch; fetch_patch('CVE-2023-32681', 'requests', force_refresh=True)"
```

Or delete `data/patches/CVE-2023-32681.json` and call `fetch_patch` again.

### Tests

```powershell
pip install -r requirements.txt
pytest tests/test_patch_fetcher.py -v
```

---

## Symbol Scanner (`src/symbol_scanner.py`)

The symbol scanner consumes Patch Fetcher output and walks the user's Python project with `ast` to find **every import and call** that resolves to a patched vulnerable symbol.

### Why AST-based beats grep

`grep rebuild_auth` matches comments, strings, unrelated identifiers, and misses `ra(x)` after `import rebuild_auth as ra`. The scanner builds a per-file alias table from `import` / `from … import` nodes and resolves call targets to fully qualified names before matching CVE symbols.

### Confidence levels

| Level | Meaning |
|-------|---------|
| **HIGH** | Direct binding from a resolved import; call chain is complete |
| **MEDIUM** | Star import or attribute access on a known module (possible match) |
| **LOW** | Name matches but import chain could not be resolved |

### Interpreting output

- `findings_by_cve[CVE].is_reachable` — `true` when at least one reference exists in your code (not merely a transitive dependency).
- `references[].in_entry_point` — finding sits under a Flask/Django/FastAPI route (or similar); higher operational risk.
- `summary.noise_reduction_percent` — share of scanned CVEs with **no** direct code references (transitive-only noise filtered out).

### Usage

```python
from src.symbol_scanner import load_patches_from_cache, scan_symbols, save_findings

patches = load_patches_from_cache()
report = scan_symbols("./vulnerable-task-tracker", patches)
save_findings(report, "demo_out/symbol_scan.json")
```

TaskFlow demo:

```powershell
python -m pytest tests/test_symbol_scanner.py -v
```

---

## Upgrade Simulator (`src/upgrade_simulator.py`)

Predicts whether a dependency upgrade will resolve on PyPI **before** you run `pip install`. This is the core “pre-upgrade” differentiator: Snyk/Dependabot/Trivy flag CVEs; this module models **resolver conflicts and forced cascades**.

### Why deps.dev

[deps.dev](https://deps.dev) exposes precomputed dependency graphs per package version (`…/versions/{version}:dependencies`). The simulator walks those graphs offline (cached under `data/depsdev/PyPI/`) and applies `packaging` specifier math—no pip, no venv changes.

### Four conflict classes

| Class | Code | Meaning |
|-------|------|---------|
| A | `DIRECT_CONFLICT` | Two parents need incompatible ranges on the same shared dependency |
| B | `cascade` | Upgrading A forces B, then C (transitive bumps) |
| C | `runtime_conflicts` | `Requires-Python` incompatible with your project interpreter |
| D | `target_introduces_cves` | Target version still has known CVEs (OSV / Trivy enrichment) |

### Resolution planning

When conflicts are fixable, `resolution_plan.steps` lists upgrades in **topological order** (e.g. bump `boto3` before `requests` to release the `urllib3` pin).

### Usage

```python
from src.upgrade_simulator import parse_requirements, simulate_upgrade

reqs = parse_requirements("vulnerable-task-tracker/requirements.txt")
report = simulate_upgrade(
    reqs,
    [{"package": "requests", "target_version": "2.31.0"}],
    python_version="3.9.5",
)
print(report["summary"]["verdict"], report["resolution_plan"]["steps"])
```

### Refresh deps.dev cache

```powershell
python scripts/populate_depsdev_cache.py
```

### Tests

```powershell
python -m pytest tests/test_upgrade_simulator.py -v
```

## HTML risk report

Phase 9 (`src/html_reporter.py`) produces a **five-tab, self-contained HTML dashboard**:

| Tab | Content |
|-----|---------|
| Executive | Overall recommendation, stats, donut chart, top concerns |
| Technical | Sortable/filterable CVE table with score breakdown |
| Patches | Before/after code from patch fetcher |
| Upgrade | Conflict timeline and resolution steps |
| Reachability Graph | vis-network graph from symbol scan references |

### Generate a demo report

```powershell
python -c "from src.html_reporter import assemble_and_generate_demo; assemble_and_generate_demo('examples/sample_report.html', offline=True)"
start examples\sample_report.html
```

### Pipeline integration

```powershell
python pipeline_a.py --demo --project-dir ./test --offline
```

Optional inputs: `--symbol-scan path/to/symbol_scan.json`, `--upgrade-sim path/to/upgrade.json`. When omitted, the pipeline looks for `symbol_scan.json` in the output directory or `examples/symbol_scan_output.json`.

### Offline mode

Pass `offline=True` to `generate_report()` or `--offline` on the pipeline. Vendor assets under `static/vendor/` are inlined so the file opens via `file://` without network access (target size &lt; 2 MB).

### Tests

```powershell
python -m pytest tests/test_html_reporter.py -v
```

## ReAct agent

`src/agent.py` replaces rigid phase-by-phase orchestration with an **LLM-driven ReAct loop** that chooses the next investigation step. The same pipeline modules are exposed as **whitelisted tools**; the LLM never scores risk or writes rules.

### Why the LLM is on a leash

| Guardrail | Effect |
|-----------|--------|
| Tool whitelist | Only 8 named tools; unknown tools are rejected |
| Pydantic JSON schema | Every LLM reply must match `{thought, action, done}` |
| Entity whitelist | CVE/package/version strings must already appear in the scratchpad |
| Deterministic scorer | `compute_score` calls `scorer.py`; the LLM cannot override PROCEED/REVIEW/BLOCK |
| Fallback pipeline | After repeated invalid output or if Ollama is down, a scripted path runs the same tools in order |

### Run the agent

```powershell
# Live LLM investigation (Ollama + qwen2.5:7b)
python -m src.agent --target ./vulnerable-task-tracker --verbose

# Scripted fallback only (no Ollama) — same output schema
python -m src.agent --target ./vulnerable-task-tracker --no-llm

# Open the report and inspect the trace
start data\report.html
type data\agent_trace.json
```

### Trace file

Each run writes `data/agent_trace.json` with metadata, per-step thought/action/result, and `collected_data`. A trimmed sample lives in `examples/agent_trace_demo.json`.

### Tests

```powershell
python -m pytest tests/test_agent.py -v
```
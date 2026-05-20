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
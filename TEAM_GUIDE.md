# Team Guide — Predictive Risk Assessment System

Simple overview for the team: what we built, how to try it, what's left.

**More detail:** [README.md](README.md) · [ARCHITECTURE.md](ARCHITECTURE.md) · [TODO.md](TODO.md)

---

## What is this?

A tool that scans a **Python project** before you upgrade dependencies. It:

1. Finds CVEs in your pinned packages (Trivy)
2. Checks if **your code actually uses** the vulnerable APIs (symbol scan)
3. Runs Semgrep rules and simulates upgrades
4. Gives a clear verdict: **BLOCK**, **REVIEW**, or **PROCEED** (deterministic — not LLM guesswork)
5. Writes an HTML report you can open in a browser

**Sample result:** 81 CVEs in pins → 6 touch your code → 1 BLOCK → report at `risk_report.html`.

---

## What's done

- Full **12-phase pipeline** (`pipeline_a.py`) — works end-to-end
- Scan **any Python repo** (not just the sample app)
- **HTML report** (tabbed, offline-friendly)
- **Demo scripts** — quick preview or full run
- **Patch fetcher**, **symbol scanner**, **upgrade simulator**, **scorer**
- **SARIF / VEX / SBOM** exports
- **157 tests** + CI on GitHub Actions
- **Optional knowledge graph** + Neo4j (code exists; team still needs to validate)

---

## How to test it

### One-time setup

```powershell
cd D:\Predictive-Risk-Assessment-System
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements-core.txt
```

Install on your machine (not in pip):

- [Trivy](https://github.com/aquasecurity/trivy) — CVE scan
- [Semgrep](https://semgrep.dev/) — static rules

Check they work:

```powershell
trivy --version
semgrep --version
```

---

### Test 1 — Quick preview (~30 seconds)

No Trivy/Semgrep run. Opens a sample HTML report.

```powershell
.\scripts\demo.ps1 -Quick
```

---

### Test 2 — Full run on sample app (~10 minutes)

Uses the bundled `vulnerable-task-tracker/` app.

```powershell
.\scripts\demo.ps1
```

When done, open `output/risk_report.html`.

---

### Test 3 — Your own repo

Point at any Python project on your machine:

```powershell
.\scripts\scan_repo.ps1 -RepoPath "D:\path\to\your-python-app"
```

Results go to: `D:\path\to\your-python-app\.risk-scan\risk_report.html`

Your repo should have:

- Python source code
- Pinned deps in `requirements.txt`, `pyproject.toml`, or `Pipfile` (with `==` pins)

---

### Test 4 — Automated tests

```powershell
pytest tests/ -q
```

You should see **157 passed**.

---

### Optional — Neo4j graph

Only if you want graph phases (slower, not needed for first test):

```powershell
# In .env: NEO4J_PASSWORD=your-password
docker compose up -d
pip install -r requirements-graph.txt
python pipeline_a.py --project-dir ./vulnerable-task-tracker --neo4j --skip-llm --offline
```

---

## What's next (team backlog)

| Priority | Item |
|----------|------|
| **P0** | Validate Neo4j on a clean machine (Windows + Linux) |
| **P1** | Agent path — same features as full pipeline (Semgrep, graph) |
| **P1** | Richer graph view in HTML report |
| **P2** | Docs for rule cache, optional CI with live Trivy/Semgrep |

Pick a task in [TODO.md](TODO.md), add your name, and check boxes as you go.

---

## Questions?

- **Pipeline vs agent:** use `pipeline_a.py` (or `scan_repo.ps1`) for full analysis; use `python -m src.agent --target ./repo` for interactive exploration only.
- **Report location:** default is `<project-dir>/.risk-scan/risk_report.html`
- **Stuck?** Make sure Trivy and Semgrep are on your PATH, then run `pytest tests/ -q` to confirm the repo is healthy.

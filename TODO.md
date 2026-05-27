# Team TODO

Shared backlog for the Predictive Risk Assessment System. Update this file when you start or finish an item.

**Architecture context:** [ARCHITECTURE.md](ARCHITECTURE.md)  
**Setup:** [README.md](README.md)

---

## Priority legend

| Priority | Meaning |
|----------|---------|
| **P0** | Blocks demo / merge / team parity — do first |
| **P1** | Important for production quality |
| **P2** | Nice to have / polish |

---

## P0 — Do first

### 1. Integrate HTML report v2 into Pipeline A and agent

**Status:** Not started  
**Owner:** _unassigned_

v2 is implemented (`src/html_reporter_v2.py`, `templates/report_v2.html.j2`) and tested, but production still uses v1.

**Tasks:**

- [ ] Add `--report-version {v1,v2}` to `pipeline_a.py` (default `v1` until QA, then flip to `v2`)
- [ ] Switch `tool_registry.generate_report` to support v2
- [ ] Pass `graph_snapshot.json` into `build_report_data(..., graph=snapshot)` when available
- [ ] Unify output filename (`risk_report.html`) for agent and pipeline
- [ ] Update README quick start to mention v2
- [ ] Run `pytest tests/test_html_reporter_v2.py` in CI

**Files:** `pipeline_a.py`, `src/tool_registry.py`, `src/html_reporter_v2.py`

---

### 2. Neo4j integration — verify, document, and push-ready

**Status:** Code in repo; needs team validation  
**Owner:** _unassigned_

Neo4j stack exists (`docker-compose.yml`, `graph_builder.py`, `graph_queries.py`, `--neo4j` flag) but is often skipped with `--present` / `--no-graph`.

**Tasks:**

- [ ] Document team runbook: `docker compose up -d`, `pip install -r requirements-graph.txt`, `pipeline_a.py --neo4j`
- [ ] Confirm upsert + Phase 9 queries on a clean machine (Windows + Linux)
- [ ] Decide: keep **full DB clear** on each run vs incremental merge (see ARCHITECTURE.md)
- [ ] Add smoke test or script that asserts Neo4j connectivity when `--neo4j` is set
- [ ] Ensure `requirements-graph.txt` is referenced in CI / onboarding

**Files:** `docker-compose.yml`, `src/graph_builder.py`, `src/graph_queries.py`, `pipeline_a.py`

---

## P1 — Pipeline parity & quality

### 3. Align ReAct agent with Pipeline A capabilities

**Status:** Not started  
**Owner:** _unassigned_

Agent path is missing Semgrep, graph phases, and batch patch fetch.

**Tasks:**

- [ ] Add optional `fetch_patches_batch` tool (or auto-batch in scripted fallback only)
- [ ] Evaluate exposing Semgrep phase as agent tool vs keeping agent lightweight
- [ ] Align reachability evidence: agent should use same merge as Pipeline A where possible
- [ ] Document when to use `pipeline_a.py` vs `python -m src.agent`

---

### 4. Scoring reachability consistency

**Status:** Not started  
**Owner:** _unassigned_

Pipeline A merges **graph + symbol** evidence before scoring; agent uses **symbol-only** conversion (`_symbol_scan_to_graph_evidence`).

**Tasks:**

- [ ] Extract shared `build_scoring_evidence(symbol_findings, graph_evidence)` helper
- [ ] Add regression test: same repo → same BLOCK/REVIEW counts (modulo graph-off runs)

---

### 5. Wire knowledge graph into HTML reports

**Status:** Not started  
**Owner:** _unassigned_

`render_html` currently passes `graph=None`. Snapshot from Phase 8 is not shown in the report graph tab.

**Tasks:**

- [ ] Load `graph_snapshot.json` in Phase 12 when present
- [ ] v2 graph tab: show packages → CVEs → entry points from real snapshot

---

## P2 — Polish & maintenance

### 6. Rule cache hygiene

- [ ] Script or doc to reset stale entries in `data/rules_db.json` when Semgrep validation fails
- [ ] Document `semgrep-rules/` registry setup (`scripts/index_registry.py`)

### 7. CI / developer experience

- [ ] GitHub Actions: `pytest tests/`, optional Trivy + Semgrep in CI
- [ ] Pre-commit or lint for `src/` (optional)

### 8. Phase numbering cleanup

- [ ] Align docstrings in `graph_builder.py` / `graph_queries.py` with orchestrator phases 8–9

### 9. Presentation defaults

- [ ] Consider making `--report-version v2` the default after integration
- [ ] Optional `--verbose` rule resolution log for debugging Semgrep rule sources

---

## Completed recently

- [x] Remove frozen `--demo` mode; rules generated via registry + symbol sinks + LLM
- [x] Rich terminal UI for Pipeline A (`src/pipeline_console.py`, `--present`)
- [x] Semgrep rule validation (`semgrep --validate`) before cache/execute
- [x] Patch-aware sink rules (`symbol_rule_builder.py`)
- [x] HTML report v2 implementation + tests (not yet wired to pipeline)
- [x] Repo cleanup: removed `demo_rules/`, `examples/`, root generated artifacts
- [x] Team docs: README rewrite, ARCHITECTURE.md, this TODO

---

## How to update this file

1. Pick an unassigned item; add your name under **Owner**
2. Check boxes as you complete sub-tasks
3. Move finished items to **Completed recently** with date
4. Open a PR referencing the TODO item number

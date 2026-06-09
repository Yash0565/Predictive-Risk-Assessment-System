# Team TODO

Shared backlog. See **[TEAM_GUIDE.md](TEAM_GUIDE.md)** for how to test what's already done.

**Architecture:** [ARCHITECTURE.md](ARCHITECTURE.md) · **Setup:** [README.md](README.md)

---

## Priority legend

| Priority | Meaning |
|----------|---------|
| **P0** | Do first — blocks team validation |
| **P1** | Important next |
| **P2** | Polish |

---

## Open work

### P0 — Neo4j validation

**Status:** Code done; needs someone to run it on a clean machine  
**Owner:** _unassigned_

- [ ] Run: `docker compose up -d`, `pip install -r requirements-graph.txt`, `pipeline_a.py --neo4j`
- [ ] Confirm graph phases work on Windows and Linux
- [ ] Add a small smoke test when `--neo4j` is set (optional)

---

### P1 — Agent parity with Pipeline A

**Status:** Not started  
**Owner:** _unassigned_

Agent is missing Semgrep, graph phases, and batch patch fetch.

- [ ] Document when to use `pipeline_a.py` vs `python -m src.agent`
- [ ] Add batch patch fetch (or align scripted fallback)
- [ ] Same repo → same score as pipeline (regression test)

---

### P1 — Graph tab polish in HTML report

**Status:** Partial  
**Owner:** _unassigned_

- [ ] Richer package → CVE → entry-point graph when `graph_snapshot.json` exists

---

### P2 — Maintenance

- [ ] Doc: reset stale `data/rules_db.json` entries
- [ ] Doc: `scripts/index_registry.py` for Semgrep registry
- [ ] Optional: Trivy + Semgrep in CI (unit tests already run in CI)

---

## Done (no action needed)

- [x] 12-phase Pipeline A end-to-end
- [x] HTML report (`html_reporter_final_v2.py` → `risk_report.html`)
- [x] Scan any repo (`src/scan_paths.py`, `scripts/scan_repo.ps1`)
- [x] Demo scripts (`scripts/demo.ps1`)
- [x] Team guide (`TEAM_GUIDE.md`)
- [x] Symbol scan cache fix
- [x] Rich terminal UI (`--present`)
- [x] Patch-aware Semgrep sink rules
- [x] SARIF / VEX / SBOM exports
- [x] 157 tests + GitHub Actions CI
- [x] README + ARCHITECTURE docs

---

## How to update this file

1. Pick an open item; add your name under **Owner**
2. Check boxes when done
3. Move finished items to **Done**

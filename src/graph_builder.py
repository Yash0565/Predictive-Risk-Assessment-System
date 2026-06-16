"""Phase 5 — Neo4j graph ingestion + JSON snapshot.

Ingests Trivy CVEs, Semgrep findings, services.yaml entry points, and
AST call-graph edges. Writes graph_snapshot.json always; upserts to Neo4j
when available.
"""

import json
import logging
import os

# Silence neo4j driver cartesian product notifications
logging.getLogger("neo4j").setLevel(logging.ERROR)

import yaml

from src.config import CWE_FAMILY_MAP, CWE_NAMES
from src.static_analyzer import analyze_project, find_enclosing_function

# ── Node / edge ID helpers ───────────────────────────────────────────

def _pkg_id(name, version):
    return f"pkg:{name.lower()}@{version or 'unknown'}"


def _cve_id(cve):
    return f"cve:{cve}"


def _cwe_id(cwe):
    return f"cwe:{cwe}"


def _fn_id(file_path, qualified_name, line_start):
    return f"fn:{file_path}:{qualified_name}:{line_start}"


def _svc_id(route, method):
    return f"svc:{route}:{method}"


def _to_rel_path(path, project_dir):
    if not path:
        return ""
    path_abs = os.path.abspath(path)
    proj_abs = os.path.abspath(project_dir)
    try:
        rel = os.path.relpath(path_abs, proj_abs).replace("\\", "/")
        return rel
    except Exception:
        return path.replace("\\", "/")


# ── Public API ───────────────────────────────────────────────────────

def build_graph(
    trivy_path,
    semgrep_report,
    services_path,
    project_dir,
    families=None,
    neo4j_uri=None,
    neo4j_user=None,
    neo4j_password=None,
    snapshot_path="graph_snapshot.json",
    symbol_findings=None,
):
    """Build the security graph and optionally persist to Neo4j.

    Returns summary dict with counts and ``snapshot_path``.
    """
    project_dir = os.path.abspath(project_dir)
    families = families or {}

    nodes = {"packages": [], "cves": [], "cwes": [], "functions": [], "services": []}
    edges = {
        "depends_on": [],
        "affected_by": [],
        "has_cwe": [],
        "vulnerable_in": [],
        "exposes": [],
        "calls": [],
        # Chain edges: Package → Function → CVE → CWE → Service
        "provides": [],       # Package → Function
        "has_cve": [],         # Function → CVE
        "classified_as": [],   # CVE → CWE
        "affects": [],         # CWE → Service
    }

    # 1. Trivy → Package, CVE, AFFECTED_BY
    _ingest_trivy(trivy_path, nodes, edges)

    # 2. requirements.txt → DEPENDS_ON
    _ingest_requirements(project_dir, nodes, edges)

    # 3. Static analyzer → Function nodes + CALLS
    ast_result = analyze_project(project_dir)
    fn_index = {}
    for fn in ast_result["functions"]:
        nid = _fn_id(fn["file"], fn["qualified_name"], fn["line_start"])
        fn_index[nid] = fn
        nodes["functions"].append({
            "id": nid,
            "qualified_name": fn["qualified_name"],
            "file": fn["file"],
            "line_start": fn["line_start"],
            "line_end": fn["line_end"],
        })

    for call in ast_result["calls"]:
        caller_fn = _find_fn_by_name(fn_index, call["file"], call["caller"])
        callee_fn = _find_fn_by_name(fn_index, call["file"], call["callee"])
        if caller_fn and callee_fn:
            edges["calls"].append({
                "from": caller_fn["id"],
                "to": callee_fn["id"],
            })

    # 4. services.yaml → Service + EXPOSES
    if services_path and os.path.exists(services_path):
        _ingest_services(services_path, project_dir, ast_result, nodes, edges)

    # 5. Semgrep → Function + VULNERABLE_IN (link CVEs via family/CWE)
    _ingest_semgrep(semgrep_report, families, ast_result, nodes, edges, project_dir)

    # 5.5 Ingest cross-file calls using symbol findings
    if symbol_findings:
        _ingest_cross_file_calls(nodes, edges, symbol_findings, project_dir)

    # 6. Derive chain edges: Package → Function → CVE → CWE → Service
    _build_chain_edges(nodes, edges)

    snapshot = {
        "nodes": nodes,
        "edges": edges,
        "meta": {
            "project_dir": project_dir,
            "mode": "snapshot",
        },
    }

    os.makedirs(os.path.dirname(os.path.abspath(snapshot_path)) or ".", exist_ok=True)
    with open(snapshot_path, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2)

    neo4j_ok = False
    uri = neo4j_uri or os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = neo4j_user or os.environ.get("NEO4J_USER", "neo4j")
    password = neo4j_password or os.environ.get("NEO4J_PASSWORD", "demo-password")

    try:
        _upsert_neo4j(snapshot, uri, user, password)
        neo4j_ok = True
        snapshot["meta"]["mode"] = "neo4j"
        with open(snapshot_path, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2)
    except Exception as e:
        print(f"  [!] Neo4j unavailable ({e}); using snapshot only.")

    summary = {
        "snapshot_path": snapshot_path,
        "neo4j_connected": neo4j_ok,
        "packages": len(nodes["packages"]),
        "cves": len(nodes["cves"]),
        "functions": len(nodes["functions"]),
        "services": len(nodes["services"]),
        "edges": sum(len(v) for v in edges.values()),
    }
    return summary, snapshot


# ── Ingestion helpers ────────────────────────────────────────────────

def _ingest_trivy(trivy_path, nodes, edges):
    with open(trivy_path, "r", encoding="utf-8") as f:
        vulns = json.load(f)

    seen_pkg = set()
    seen_cve = set()
    seen_cwe = set()

    for v in vulns:
        pkg_name = v.get("package", "unknown").lower()
        pkg_ver = v.get("installed_version", "unknown")
        pid = _pkg_id(pkg_name, pkg_ver)
        if pid not in seen_pkg:
            seen_pkg.add(pid)
            nodes["packages"].append({
                "id": pid,
                "name": pkg_name,
                "installed_version": pkg_ver,
            })

        cve = v.get("cve", "")
        if not cve:
            continue
        cid = _cve_id(cve)
        cwe_list = v.get("cwe") or []
        if cid not in seen_cve:
            seen_cve.add(cid)
            nodes["cves"].append({
                "id": cid,
                "cve_id": cve,
                "cvss_score": v.get("cvss_score") or 0.0,
                "severity": v.get("severity", ""),
                "cwe_ids": cwe_list,
            })

        edges["affected_by"].append({"from": pid, "to": cid})

        # CWE nodes + HAS_CWE edges (CVE → CWE)
        for cwe in cwe_list:
            cwid = _cwe_id(cwe)
            if cwid not in seen_cwe:
                seen_cwe.add(cwid)
                nodes["cwes"].append({
                    "id": cwid,
                    "cwe_id": cwe,
                    "weakness_name": CWE_NAMES.get(cwe, cwe),
                    "vulnerability_category": CWE_FAMILY_MAP.get(
                        cwe, cwe.lower().replace("-", "_")
                    ),
                })
            edges["has_cwe"].append({"from": cid, "to": cwid})


def _ingest_requirements(project_dir, nodes, edges):
    req_path = os.path.join(project_dir, "requirements.txt")
    if not os.path.exists(req_path):
        req_path = os.path.join(os.path.dirname(project_dir), "requirements.txt")
    if not os.path.exists(req_path):
        return

    pkg_ids = {p["name"].lower(): p["id"] for p in nodes["packages"]}
    with open(req_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "==" in line:
                name, ver = line.split("==", 1)
                name = name.strip().lower()
                ver = ver.strip()
            else:
                name = line.split()[0].strip().lower()
                ver = "unknown"

            child_id = _pkg_id(name, ver)
            if not any(p["id"] == child_id for p in nodes["packages"]):
                nodes["packages"].append({
                    "id": child_id,
                    "name": name,
                    "installed_version": ver,
                })

            # Link root-ish packages (heuristic: first declared dep chain)
            for parent_name, parent_id in pkg_ids.items():
                edges["depends_on"].append({"from": parent_id, "to": child_id})


def _ingest_services(services_path, project_dir, ast_result, nodes, edges):
    with open(services_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    for svc in data.get("services", []):
        route = svc.get("route", "/")
        method = svc.get("method", "GET").upper()
        sid = _svc_id(route, method)
        handler = svc.get("handler", "")
        file_rel = svc.get("file", "").replace("\\", "/")

        nodes["services"].append({
            "id": sid,
            "name": svc.get("name", handler),
            "route": route,
            "method": method,
            "handler": handler,
            "file": file_rel,
        })

        fn = _find_handler_function(ast_result["functions"], file_rel, handler)
        if fn:
            fid = _fn_id(fn["file"], fn["qualified_name"], fn["line_start"])
            if not any(f["id"] == fid for f in nodes["functions"]):
                nodes["functions"].append({
                    "id": fid,
                    "qualified_name": fn["qualified_name"],
                    "file": fn["file"],
                    "line_start": fn["line_start"],
                    "line_end": fn["line_end"],
                })
            edges["exposes"].append({"from": sid, "to": fid})


def _ingest_semgrep(semgrep_report, families, ast_result, nodes, edges, project_dir):
    """Map Semgrep matches to Function nodes and VULNERABLE_IN edges."""
    cve_by_cwe = {}
    for _family, cluster in families.items():
        for v in cluster.cves:
            for cwe in v.get("cwe", []):
                cve_by_cwe.setdefault(cwe, []).append(v.get("cve"))

    for entry in semgrep_report:
        cwe_ids = entry.get("cwe_ids", [])
        cve_ids = entry.get("cves", [])
        if not cve_ids:
            for cwe in cwe_ids:
                cve_ids.extend(cve_by_cwe.get(cwe, []))
        cve_ids = list(dict.fromkeys(cve_ids))

        for match in entry.get("semgrep_matches", []):
            file_rel = _to_rel_path(match.get("file", ""), project_dir)
            line = match.get("line_start", 0)
            fn = find_enclosing_function(ast_result["functions"], file_rel, line)
            if not fn:
                fn = {
                    "qualified_name": f"<module>.line_{line}",
                    "file": file_rel,
                    "line_start": line,
                    "line_end": match.get("line_end", line),
                }

            fid = _fn_id(fn["file"], fn["qualified_name"], fn["line_start"])
            if not any(f["id"] == fid for f in nodes["functions"]):
                nodes["functions"].append({
                    "id": fid,
                    "qualified_name": fn["qualified_name"],
                    "file": fn["file"],
                    "line_start": fn["line_start"],
                    "line_end": fn["line_end"],
                })

            for cve in cve_ids:
                cid = _cve_id(cve)
                if any(c["id"] == cid for c in nodes["cves"]):
                    edge = {"from": cid, "to": fid}
                    if edge not in edges["vulnerable_in"]:
                        edges["vulnerable_in"].append(edge)


def _ingest_cross_file_calls(nodes, edges, symbol_findings, project_dir):
    """Use symbol scanner output to add cross-file CALLS edges."""
    for cve_id, finding in symbol_findings.get("findings_by_cve", {}).items():
        if not finding.get("is_reachable"):
            continue
        vuln_sym = finding.get("vulnerable_symbol", "")
        if not vuln_sym:
            continue

        # 1. Ensure the vulnerable symbol is registered as a Function node
        vuln_fn_id = _fn_id("lib", vuln_sym, 0)
        if not any(f["id"] == vuln_fn_id for f in nodes["functions"]):
            nodes["functions"].append({
                "id": vuln_fn_id,
                "qualified_name": vuln_sym,
                "file": "lib",
                "line_start": 0,
                "line_end": 0,
            })

        # 2. Link the CVE node to the vulnerable function node
        cid = _cve_id(cve_id)
        if any(c["id"] == cid for c in nodes["cves"]):
            edge_v = {"from": cid, "to": vuln_fn_id}
            if edge_v not in edges["vulnerable_in"]:
                edges["vulnerable_in"].append(edge_v)

        # 3. For each reference, link the caller enclosing function to the vulnerable function
        for ref in finding.get("references", []):
            caller_fn = ref.get("enclosing_function")
            if not caller_fn:
                continue

            caller_file = _to_rel_path(ref.get("file", ""), project_dir)
            caller_fn_node = None
            for f in nodes["functions"]:
                if f["file"] == caller_file and f["qualified_name"] == caller_fn:
                    caller_fn_node = f
                    break

            if not caller_fn_node:
                caller_line = ref.get("line", 0)
                caller_fn_id = _fn_id(caller_file, caller_fn, caller_line)
                nodes["functions"].append({
                    "id": caller_fn_id,
                    "qualified_name": caller_fn,
                    "file": caller_file,
                    "line_start": caller_line,
                    "line_end": caller_line,
                })
            else:
                caller_fn_id = caller_fn_node["id"]

            edge_c = {"from": caller_fn_id, "to": vuln_fn_id}
            if edge_c not in edges["calls"]:
                edges["calls"].append(edge_c)


def _find_handler_function(functions, file_rel, handler_name):
    for fn in functions:
        if fn["file"] == file_rel and fn["qualified_name"] == handler_name:
            return fn
    return None


def _find_fn_by_name(fn_index, file_path, qualified_name):
    for fn in fn_index.values():
        if fn["file"] == file_path and fn["qualified_name"] == qualified_name:
            return {"id": _fn_id(fn["file"], fn["qualified_name"], fn["line_start"]), **fn}
    return None


# ── Chain-edge derivation ────────────────────────────────────────────

def _build_chain_edges(nodes, edges):
    """Derive the Package→Function→CVE→CWE→Service chain edges.

    All four edge types are computed from existing ingested data:
      PROVIDES     — Package → Function  (via AFFECTED_BY + VULNERABLE_IN)
      HAS_CVE      — Function → CVE      (reverse of VULNERABLE_IN)
      CLASSIFIED_AS — CVE → CWE          (same direction as HAS_CWE)
      AFFECTS      — CWE → Service       (BFS reachability from entry points)
    """
    # ── PROVIDES: Package → Function ─────────────────────────────────
    # A package "provides" a function if:
    #   Package -[AFFECTED_BY]-> CVE -[VULNERABLE_IN]-> Function
    cve_to_pkgs = {}  # cve_id → set of pkg_ids
    for ab in edges["affected_by"]:
        cve_to_pkgs.setdefault(ab["to"], set()).add(ab["from"])

    seen_provides = set()
    for vi in edges["vulnerable_in"]:
        cve_id = vi["from"]
        fn_id = vi["to"]
        for pkg_id in cve_to_pkgs.get(cve_id, set()):
            key = (pkg_id, fn_id)
            if key not in seen_provides:
                seen_provides.add(key)
                edges["provides"].append({"from": pkg_id, "to": fn_id})

    # ── HAS_CVE: Function → CVE (reverse of VULNERABLE_IN) ──────────
    seen_has_cve = set()
    for vi in edges["vulnerable_in"]:
        key = (vi["to"], vi["from"])  # fn → cve
        if key not in seen_has_cve:
            seen_has_cve.add(key)
            edges["has_cve"].append({"from": vi["to"], "to": vi["from"]})

    # ── CLASSIFIED_AS: CVE → CWE (forward-chain alias of HAS_CWE) ───
    seen_classified = set()
    for hc in edges["has_cwe"]:
        key = (hc["from"], hc["to"])
        if key not in seen_classified:
            seen_classified.add(key)
            edges["classified_as"].append({"from": hc["from"], "to": hc["to"]})

    # ── AFFECTS: CWE → Service ───────────────────────────────────────
    # A CWE "affects" a service if there is a path:
    #   Service -[EXPOSES]-> Function -[CALLS*]-> Function
    #   and that reachable function has VULNERABLE_IN ← CVE → HAS_CWE → CWE
    fn_to_cves = {}  # fn_id → set of cve_ids
    for vi in edges["vulnerable_in"]:
        fn_to_cves.setdefault(vi["to"], set()).add(vi["from"])

    cve_to_cwes = {}  # cve_id → set of cwe_ids
    for hc in edges["has_cwe"]:
        cve_to_cwes.setdefault(hc["from"], set()).add(hc["to"])

    seen_affects = set()
    for exp in edges["exposes"]:
        svc_id = exp["from"]
        entry_fn = exp["to"]
        reachable = _walk_calls(entry_fn, edges["calls"])
        for fn_id in reachable:
            for cve_id in fn_to_cves.get(fn_id, set()):
                for cwe_id in cve_to_cwes.get(cve_id, set()):
                    key = (cwe_id, svc_id)
                    if key not in seen_affects:
                        seen_affects.add(key)
                        edges["affects"].append({
                            "from": cwe_id, "to": svc_id,
                        })


def _walk_calls(start_fn_id, call_edges, max_depth=10):
    """BFS over CALLS edges to find all reachable function IDs."""
    visited = {start_fn_id}
    frontier = [start_fn_id]
    for _ in range(max_depth):
        next_frontier = []
        for fn_id in frontier:
            for ce in call_edges:
                if ce["from"] == fn_id and ce["to"] not in visited:
                    visited.add(ce["to"])
                    next_frontier.append(ce["to"])
        if not next_frontier:
            break
        frontier = next_frontier
    return visited


# ── Neo4j upsert ─────────────────────────────────────────────────────

def _upsert_neo4j(snapshot, uri, user, password):
    os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
    os.environ.setdefault("OMP_NUM_THREADS", "1")
    from neo4j import GraphDatabase

    driver = GraphDatabase.driver(uri, auth=(user, password))
    try:
        driver.verify_connectivity()
        with driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")

            for pkg in snapshot["nodes"]["packages"]:
                session.run(
                    "MERGE (p:Package {id: $id}) SET p.name = $name, "
                    "p.installed_version = $ver",
                    id=pkg["id"], name=pkg["name"],
                    ver=pkg.get("installed_version", ""),
                )
            for cve in snapshot["nodes"]["cves"]:
                session.run(
                    "MERGE (c:CVE {id: $id}) SET c.cve_id = $cve_id, "
                    "c.cvss_score = $cvss, c.severity = $sev, c.cwe_ids = $cwes",
                    id=cve["id"], cve_id=cve["cve_id"],
                    cvss=cve.get("cvss_score", 0.0),
                    sev=cve.get("severity", ""),
                    cwes=cve.get("cwe_ids", []),
                )
            for cwe in snapshot["nodes"].get("cwes", []):
                session.run(
                    "MERGE (w:CWE {id: $id}) SET w.cwe_id = $cwe_id, "
                    "w.weakness_name = $wname, w.vulnerability_category = $vcat",
                    id=cwe["id"], cwe_id=cwe["cwe_id"],
                    wname=cwe.get("weakness_name", ""),
                    vcat=cwe.get("vulnerability_category", ""),
                )
            for fn in snapshot["nodes"]["functions"]:
                session.run(
                    "MERGE (f:Function {id: $id}) SET f.qualified_name = $qn, "
                    "f.file = $file, f.line_start = $ls, f.line_end = $le",
                    id=fn["id"], qn=fn["qualified_name"],
                    file=fn["file"], ls=fn["line_start"], le=fn["line_end"],
                )
            for svc in snapshot["nodes"]["services"]:
                session.run(
                    "MERGE (s:Service {id: $id}) SET s.name = $name, "
                    "s.route = $route, s.method = $method, s.handler = $handler",
                    id=svc["id"], name=svc["name"], route=svc["route"],
                    method=svc["method"], handler=svc.get("handler", ""),
                )

            for e in snapshot["edges"]["depends_on"]:
                session.run(
                    "MATCH (a:Package {id: $from}), (b:Package {id: $to}) "
                    "MERGE (a)-[:DEPENDS_ON]->(b)",
                    **e,
                )
            for e in snapshot["edges"]["affected_by"]:
                session.run(
                    "MATCH (a:Package {id: $from}), (c:CVE {id: $to}) "
                    "MERGE (a)-[:AFFECTED_BY]->(c)",
                    **e,
                )
            for e in snapshot["edges"].get("has_cwe", []):
                session.run(
                    "MATCH (c:CVE {id: $from}), (w:CWE {id: $to}) "
                    "MERGE (c)-[:HAS_CWE]->(w)",
                    **e,
                )
            for e in snapshot["edges"]["vulnerable_in"]:
                session.run(
                    "MATCH (c:CVE {id: $from}), (f:Function {id: $to}) "
                    "MERGE (c)-[:VULNERABLE_IN]->(f)",
                    **e,
                )
            for e in snapshot["edges"]["exposes"]:
                session.run(
                    "MATCH (s:Service {id: $from}), (f:Function {id: $to}) "
                    "MERGE (s)-[:EXPOSES]->(f)",
                    **e,
                )
            for e in snapshot["edges"]["calls"]:
                session.run(
                    "MATCH (a:Function {id: $from}), (b:Function {id: $to}) "
                    "MERGE (a)-[:CALLS]->(b)",
                    **e,
                )

            # ── Chain edges: Package → Function → CVE → CWE → Service
            for e in snapshot["edges"].get("provides", []):
                session.run(
                    "MATCH (p:Package {id: $from}), (f:Function {id: $to}) "
                    "MERGE (p)-[:PROVIDES]->(f)",
                    **e,
                )
            for e in snapshot["edges"].get("has_cve", []):
                session.run(
                    "MATCH (f:Function {id: $from}), (c:CVE {id: $to}) "
                    "MERGE (f)-[:HAS_CVE]->(c)",
                    **e,
                )
            for e in snapshot["edges"].get("classified_as", []):
                session.run(
                    "MATCH (c:CVE {id: $from}), (w:CWE {id: $to}) "
                    "MERGE (c)-[:CLASSIFIED_AS]->(w)",
                    **e,
                )
            for e in snapshot["edges"].get("affects", []):
                session.run(
                    "MATCH (w:CWE {id: $from}), (s:Service {id: $to}) "
                    "MERGE (w)-[:AFFECTS]->(s)",
                    **e,
                )
    finally:
        driver.close()

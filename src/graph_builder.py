"""Phase 5 — Neo4j graph ingestion + JSON snapshot.

Ingests Trivy CVEs, Semgrep findings, services.yaml entry points, and
AST call-graph edges. Writes graph_snapshot.json always; upserts to Neo4j
when available.
"""

import json
import os

import yaml

from src.config import CWE_FAMILY_MAP
from src.static_analyzer import analyze_project, find_enclosing_function

# ── Node / edge ID helpers ───────────────────────────────────────────

def _pkg_id(name, version):
    return f"pkg:{name}@{version or 'unknown'}"


def _cve_id(cve):
    return f"cve:{cve}"


def _fn_id(file_path, qualified_name, line_start):
    return f"fn:{file_path}:{qualified_name}:{line_start}"


def _svc_id(route, method):
    return f"svc:{route}:{method}"


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
):
    """Build the security graph and optionally persist to Neo4j.

    Returns summary dict with counts and ``snapshot_path``.
    """
    project_dir = os.path.abspath(project_dir)
    families = families or {}

    nodes = {"packages": [], "cves": [], "functions": [], "services": []}
    edges = {
        "depends_on": [],
        "affected_by": [],
        "vulnerable_in": [],
        "exposes": [],
        "calls": [],
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
    _ingest_semgrep(semgrep_report, families, ast_result, nodes, edges)

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

    for v in vulns:
        pkg_name = v.get("package", "unknown")
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
        if cid not in seen_cve:
            seen_cve.add(cid)
            cwe_list = v.get("cwe") or []
            nodes["cves"].append({
                "id": cid,
                "cve_id": cve,
                "cvss_score": v.get("cvss_score") or 0.0,
                "severity": v.get("severity", ""),
                "cwe_ids": cwe_list,
            })

        edges["affected_by"].append({"from": pid, "to": cid})


def _ingest_requirements(project_dir, nodes, edges):
    req_path = os.path.join(project_dir, "requirements.txt")
    if not os.path.exists(req_path):
        req_path = os.path.join(os.path.dirname(project_dir), "requirements.txt")
    if not os.path.exists(req_path):
        return

    pkg_ids = {p["name"]: p["id"] for p in nodes["packages"]}
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


def _ingest_semgrep(semgrep_report, families, ast_result, nodes, edges):
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
            file_rel = match.get("file", "").replace("\\", "/")
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
    finally:
        driver.close()

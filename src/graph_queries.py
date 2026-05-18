"""Phase 6 — Graph queries (Neo4j Cypher + snapshot BFS fallback).

Provides reachability, blast-radius, and dependency-chain evidence for
the risk scorer.
"""

from collections import deque

# ── Cypher queries ───────────────────────────────────────────────────

CYPHER_REACHABILITY = """
MATCH (s:Service)-[:EXPOSES]->(entry:Function)
MATCH (v:Function)<-[:VULNERABLE_IN]-(c:CVE)
WHERE ($cve_id IS NULL OR c.cve_id = $cve_id)
  AND EXISTS {
    MATCH p = shortestPath((entry)-[:CALLS*0..10]->(v))
    RETURN p
  }
RETURN s.name AS service, c.cve_id AS cve_id,
       v.qualified_name AS vuln_fn, v.file AS file,
       v.line_start AS line_start,
       length(shortestPath((entry)-[:CALLS*0..10]->(v))) AS hops
"""

CYPHER_BLAST_RADIUS = """
MATCH (c:CVE {cve_id: $cve_id})-[:VULNERABLE_IN]->(v:Function)
MATCH (s:Service)-[:EXPOSES]->(entry:Function)
WHERE EXISTS { MATCH (entry)-[:CALLS*0..10]->(v) RETURN 1 }
   OR EXISTS { MATCH (s)-[:EXPOSES]->(vf:Function)<-[:VULNERABLE_IN]-(c) RETURN 1 }
RETURN count(DISTINCT s) AS impacted_services,
       collect(DISTINCT s.name) AS service_names
"""

CYPHER_DEPENDENCY_CHAIN = """
MATCH (s:Service {name: $service})-[:EXPOSES]->(entry:Function)
MATCH (v:Function)<-[:VULNERABLE_IN]-(c:CVE {cve_id: $cve_id})
MATCH p = shortestPath((entry)-[:CALLS*0..15]->(v))
RETURN s.name AS service, c.cve_id AS cve_id,
       [n IN nodes(p) | n.qualified_name] AS path,
       v.file AS file, v.line_start AS line_start,
       length(p) AS hops
"""


# ── Public API ───────────────────────────────────────────────────────

def query_reachability(driver=None, snapshot=None, cve_id=None):
    """Return rows where a vulnerable function is reachable from an entry."""
    if driver:
        with driver.session() as session:
            rows = session.run(
                CYPHER_REACHABILITY, cve_id=cve_id
            ).data()
            return [_normalize_reach_row(r) for r in rows]
    return _snapshot_reachability(snapshot, cve_id)


def query_blast_radius(driver=None, snapshot=None, cve_id=None):
    """Return impacted service count and names for a CVE."""
    if driver:
        with driver.session() as session:
            row = session.run(CYPHER_BLAST_RADIUS, cve_id=cve_id).single()
            if row:
                return {
                    "cve_id": cve_id,
                    "impacted_services": row["impacted_services"],
                    "service_names": row["service_names"] or [],
                }
            return {"cve_id": cve_id, "impacted_services": 0, "service_names": []}
    return _snapshot_blast_radius(snapshot, cve_id)


def query_dependency_chain(driver=None, snapshot=None, service=None, cve_id=None):
    """Return shortest call-graph path from service entry to vulnerable fn."""
    if driver:
        with driver.session() as session:
            rows = session.run(
                CYPHER_DEPENDENCY_CHAIN, service=service, cve_id=cve_id
            ).data()
            return [_normalize_chain_row(r) for r in rows]
    return _snapshot_dependency_chain(snapshot, service, cve_id)


def run_all_queries(driver=None, snapshot=None, cve_ids=None, services=None):
    """Run all query types for a list of CVEs; return aggregated evidence."""
    cve_ids = cve_ids or []
    services = services or []

    reachability = []
    blast = {}
    chains = []

    for cid in cve_ids:
        reachability.extend(query_reachability(driver, snapshot, cid))
        blast[cid] = query_blast_radius(driver, snapshot, cid)

    svc_names = services or list({
        r["service"] for r in reachability if r.get("service")
    })
    for svc in svc_names:
        for cid in cve_ids:
            chains.extend(
                query_dependency_chain(driver, snapshot, svc, cid)
            )

    return {
        "reachability": reachability,
        "blast_radius": blast,
        "dependency_chains": chains,
    }


def get_neo4j_driver(uri=None, user=None, password=None):
    """Create a Neo4j driver or return None on failure."""
    import os
    try:
        from neo4j import GraphDatabase
        uri = uri or os.environ.get("NEO4J_URI", "bolt://localhost:7687")
        user = user or os.environ.get("NEO4J_USER", "neo4j")
        password = password or os.environ.get("NEO4J_PASSWORD", "demo-password")
        driver = GraphDatabase.driver(uri, auth=(user, password))
        driver.verify_connectivity()
        return driver
    except Exception:
        return None


# ── Snapshot BFS helpers ─────────────────────────────────────────────

def _build_adjacency(snapshot):
    adj = {}
    for e in snapshot.get("edges", {}).get("calls", []):
        adj.setdefault(e["from"], []).append(e["to"])
    return adj


def _fn_lookup(snapshot):
    return {f["id"]: f for f in snapshot.get("nodes", {}).get("functions", [])}


def _cve_lookup(snapshot):
    return {c["id"]: c for c in snapshot.get("nodes", {}).get("cves", [])}


def _shortest_path(adj, start, goal, max_depth=15):
    if start == goal:
        return [start]
    queue = deque([(start, [start])])
    visited = {start}
    while queue:
        node, path = queue.popleft()
        if len(path) > max_depth:
            continue
        for nxt in adj.get(node, []):
            if nxt in visited:
                continue
            new_path = path + [nxt]
            if nxt == goal:
                return new_path
            visited.add(nxt)
            queue.append((nxt, new_path))
    return None


def _snapshot_reachability(snapshot, cve_id=None):
    if not snapshot:
        return []

    adj = _build_adjacency(snapshot)
    fn_by_id = _fn_lookup(snapshot)
    cve_by_id = _cve_lookup(snapshot)

    vuln_fns = set()
    for e in snapshot["edges"].get("vulnerable_in", []):
        cid = e["from"]
        cve_node = cve_by_id.get(cid, {})
        if cve_id and cve_node.get("cve_id") != cve_id:
            continue
        vuln_fns.add(e["to"])

    entry_fns = []
    svc_by_entry = {}
    for e in snapshot["edges"].get("exposes", []):
        entry_fns.append(e["to"])
        for svc in snapshot["nodes"].get("services", []):
            if svc["id"] == e["from"]:
                svc_by_entry[e["to"]] = svc["name"]

    results = []
    for entry in entry_fns:
        for vf in vuln_fns:
            path = _shortest_path(adj, entry, vf)
            if path is None:
                continue
            fn = fn_by_id.get(vf, {})
            cve_node = next(
                (c for c in cve_by_id.values()
                 if _cve_id_match(c, cve_id, snapshot, vf)),
                {},
            )
            results.append({
                "service": svc_by_entry.get(entry, ""),
                "cve_id": cve_node.get("cve_id", cve_id or ""),
                "vuln_fn": fn.get("qualified_name", ""),
                "file": fn.get("file", ""),
                "line_start": fn.get("line_start", 0),
                "hops": len(path) - 1,
                "reachable": True,
            })
    return results


def _cve_id_match(cve_node, cve_id, snapshot, fn_id):
    if cve_id and cve_node.get("cve_id") != cve_id:
        return False
    for e in snapshot["edges"].get("vulnerable_in", []):
        if e["from"] == cve_node["id"] and e["to"] == fn_id:
            return True
    return False


def _snapshot_blast_radius(snapshot, cve_id):
    reach = _snapshot_reachability(snapshot, cve_id)
    direct = set()
    cid = f"cve:{cve_id}" if cve_id and not cve_id.startswith("cve:") else cve_id

    for e in snapshot.get("edges", {}).get("vulnerable_in", []):
        if e["from"] == cid or (cve_id and e["from"].endswith(cve_id)):
            for ex in snapshot["edges"].get("exposes", []):
                if ex["to"] == e["to"]:
                    for svc in snapshot["nodes"].get("services", []):
                        if svc["id"] == ex["from"]:
                            direct.add(svc["name"])

    names = {r["service"] for r in reach} | direct
    names.discard("")
    return {
        "cve_id": cve_id,
        "impacted_services": len(names),
        "service_names": sorted(names),
    }


def _snapshot_dependency_chain(snapshot, service, cve_id):
    if not snapshot:
        return []

    adj = _build_adjacency(snapshot)
    fn_by_id = _fn_lookup(snapshot)

    entry = None
    for svc in snapshot["nodes"].get("services", []):
        if svc["name"] == service:
            for e in snapshot["edges"].get("exposes", []):
                if e["from"] == svc["id"]:
                    entry = e["to"]
                    break

    if not entry:
        return []

    cid = f"cve:{cve_id}"
    results = []
    for e in snapshot["edges"].get("vulnerable_in", []):
        if e["from"] != cid:
            continue
        path_ids = _shortest_path(adj, entry, e["to"])
        if not path_ids:
            continue
        path_names = [fn_by_id.get(pid, {}).get("qualified_name", pid)
                      for pid in path_ids]
        fn = fn_by_id.get(e["to"], {})
        results.append({
            "service": service,
            "cve_id": cve_id,
            "path": path_names,
            "file": fn.get("file", ""),
            "line_start": fn.get("line_start", 0),
            "hops": len(path_ids) - 1,
        })
    return results


def _normalize_reach_row(row):
    return {
        "service": row.get("service", ""),
        "cve_id": row.get("cve_id", ""),
        "vuln_fn": row.get("vuln_fn", ""),
        "file": row.get("file", ""),
        "line_start": row.get("line_start", 0),
        "hops": row.get("hops", 0),
        "reachable": True,
    }


def _normalize_chain_row(row):
    return {
        "service": row.get("service", ""),
        "cve_id": row.get("cve_id", ""),
        "path": row.get("path", []),
        "file": row.get("file", ""),
        "line_start": row.get("line_start", 0),
        "hops": row.get("hops", 0),
    }

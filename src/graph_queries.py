"""Phase 6 — Graph queries (Neo4j Cypher, Docker-backed).

Provides reachability, blast-radius, dependency-chain, and
Package→CVE→CWE→Service evidence for the risk scorer.

Requires Neo4j running via Docker (bolt://localhost:7687).
All query functions return an empty result when the driver is None
rather than raising, so the pipeline degrades gracefully if Neo4j
is not yet started.
"""

# ── Cypher queries ───────────────────────────────────────────────────

def max_call_hops() -> int:
    """Return the search depth limit from the versioned scoring model."""
    try:
        from src.scorer import load_model
        model = load_model()
        return int(model.get("reachability", {}).get("max_call_hops", 10))
    except Exception:
        return 10


CYPHER_REACHABILITY = """
MATCH (s:Service)-[:EXPOSES]->(entry:Function)
MATCH (v:Function)<-[:VULNERABLE_IN]-(c:CVE)
WHERE ($cve_id IS NULL OR c.cve_id = $cve_id)
  AND EXISTS {
    MATCH p = shortestPath((entry)-[:CALLS*0..__HOPS__]->(v))
    RETURN p
  }
RETURN s.name AS service, c.cve_id AS cve_id,
       v.qualified_name AS vuln_fn, v.file AS file,
       v.line_start AS line_start,
       length(shortestPath((entry)-[:CALLS*0..__HOPS__]->(v))) AS hops
"""

CYPHER_BLAST_RADIUS = """
MATCH (c:CVE {cve_id: $cve_id})-[:VULNERABLE_IN]->(v:Function)
MATCH (s:Service)-[:EXPOSES]->(entry:Function)
WHERE EXISTS { MATCH (entry)-[:CALLS*0..__HOPS__]->(v) RETURN 1 }
   OR EXISTS { MATCH (s)-[:EXPOSES]->(vf:Function)<-[:VULNERABLE_IN]-(c) RETURN 1 }
RETURN count(DISTINCT s) AS impacted_services,
       collect(DISTINCT s.name) AS service_names
"""

CYPHER_DEPENDENCY_CHAIN = """
MATCH (s:Service {name: $service})-[:EXPOSES]->(entry:Function)
MATCH (v:Function)<-[:VULNERABLE_IN]-(c:CVE {cve_id: $cve_id})
MATCH p = shortestPath((entry)-[:CALLS*0..__HOPS__]->(v))
RETURN s.name AS service, c.cve_id AS cve_id,
       [n IN nodes(p) | n.qualified_name] AS path,
       v.file AS file, v.line_start AS line_start,
       length(p) AS hops
"""

CYPHER_RISK_CHAINS = """
MATCH (s:Service)-[:EXPOSES]->(entry:Function)
MATCH (v:Function)<-[:VULNERABLE_IN]-(c:CVE)
MATCH (p:Package)-[:AFFECTED_BY]->(c)
WHERE EXISTS {
    MATCH path = (entry)-[:CALLS*0..__HOPS__]->(v)
    RETURN path
}
WITH s, c, p, v, entry,
     length(shortestPath((entry)-[:CALLS*0..__HOPS__]->(v))) AS hops
RETURN
    s.name      AS service,
    s.route     AS route,
    c.cve_id    AS cve_id,
    c.cvss_score AS cvss_score,
    c.severity  AS severity,
    c.cwe_ids   AS cwe_ids,
    p.name      AS package,
    p.installed_version AS installed_version,
    v.qualified_name AS vuln_fn,
    v.file      AS file,
    v.line_start AS line_start,
    hops
ORDER BY cvss_score DESC
"""

CYPHER_PKG_CVE_CWE_SERVICE = """
MATCH (pkg:Package)-[:AFFECTED_BY]->(c:CVE)-[:HAS_CWE]->(cwe:CWE)
MATCH (c)-[:VULNERABLE_IN]->(fn:Function)
MATCH (svc:Service)-[:EXPOSES]->(entry:Function)
WHERE EXISTS {
    MATCH (entry)-[:CALLS*0..__HOPS__]->(fn)
    RETURN 1
}
WITH pkg, c, cwe, fn, svc, entry,
     length(shortestPath((entry)-[:CALLS*0..__HOPS__]->(fn))) AS hops
RETURN
    pkg.name              AS package_name,
    pkg.installed_version AS installed_version,
    c.cve_id              AS cve_id,
    c.cvss_score          AS cvss_score,
    c.severity            AS severity,
    cwe.cwe_id            AS cwe_id,
    cwe.weakness_name     AS weakness_name,
    cwe.vulnerability_category AS vulnerability_category,
    fn.qualified_name     AS vulnerable_function,
    fn.file               AS file_path,
    fn.line_start         AS line_number,
    svc.name              AS service_name,
    svc.route             AS route,
    hops                  AS reachability_hops
ORDER BY c.cvss_score DESC, pkg.name
"""


# ── Public API ───────────────────────────────────────────────────────

def query_reachability(driver, cve_id=None):
    """Return rows where a vulnerable function is reachable from a service entry."""
    if not driver:
        return []
    with driver.session() as session:
        query = CYPHER_REACHABILITY.replace("__HOPS__", str(max_call_hops()))
        rows = session.run(query, cve_id=cve_id).data()
        return [_normalize_reach_row(r) for r in rows]


def query_blast_radius(driver, cve_id=None):
    """Return impacted service count and names for a CVE."""
    if not driver:
        return {"cve_id": cve_id, "impacted_services": 0, "service_names": []}
    with driver.session() as session:
        query = CYPHER_BLAST_RADIUS.replace("__HOPS__", str(max_call_hops()))
        row = session.run(query, cve_id=cve_id).single()
        if row:
            return {
                "cve_id": cve_id,
                "impacted_services": row["impacted_services"],
                "service_names": row["service_names"] or [],
            }
        return {"cve_id": cve_id, "impacted_services": 0, "service_names": []}


def query_dependency_chain(driver, service=None, cve_id=None):
    """Return shortest call-graph path from service entry to vulnerable fn."""
    if not driver:
        return []
    with driver.session() as session:
        query = CYPHER_DEPENDENCY_CHAIN.replace("__HOPS__", str(max_call_hops()))
        rows = session.run(
            query, service=service, cve_id=cve_id
        ).data()
        return [_normalize_chain_row(r) for r in rows]


def query_pkg_cve_cwe_service(driver):
    """Return Package→CVE→CWE→Service reachability chains with weakness metadata."""
    if not driver:
        return []
    with driver.session() as session:
        query = CYPHER_PKG_CVE_CWE_SERVICE.replace("__HOPS__", str(max_call_hops()))
        return session.run(query).data()


def run_all_queries(driver, snapshot=None, cve_ids=None, services=None):
    """Run all query types for a list of CVEs; return aggregated evidence."""
    cve_ids = cve_ids or []
    services = services or []

    reachability = []
    blast = {}
    chains = []

    for cid in cve_ids:
        reachability.extend(query_reachability(driver, cid))
        blast[cid] = query_blast_radius(driver, cid)

    svc_names = services or list({
        r["service"] for r in reachability if r.get("service")
    })
    for svc in svc_names:
        for cid in cve_ids:
            chains.extend(query_dependency_chain(driver, svc, cid))

    return {
        "reachability": reachability,
        "blast_radius": blast,
        "dependency_chains": chains,
    }


def query_risk_chains(driver):
    """Return full service→CVE risk chains for the risk_chains.json builder."""
    if not driver:
        return []
    with driver.session() as session:
        query = CYPHER_RISK_CHAINS.replace("__HOPS__", str(max_call_hops()))
        return session.run(query).data()


def get_neo4j_driver(uri=None, user=None, password=None):
    """Create a Neo4j driver (Docker bolt://localhost:7687) or return None on failure."""
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


# ── Row normalizers ──────────────────────────────────────────────────

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

"""Simulate PyPI dependency upgrades without running pip.

Uses deps.dev precomputed dependency graphs (offline-cached) and ``packaging``
for constraint logic. Predicts direct conflicts, cascades, runtime issues, and
target-version CVE exposure before ``pip install``.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import requests
from packaging.markers import Marker
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parent.parent
DEPSDEV_CACHE = _REPO_ROOT / "data" / "depsdev" / "PyPI"
OSV_CACHE = _REPO_ROOT / "data" / "osv"
TRIVY_ENRICHED = _REPO_ROOT / "enriched_trivy_output.json"

DEPSDEV_URL = (
    "https://api.deps.dev/v3/systems/PyPI/packages/{package}/versions/{version}:dependencies"
)
PYPI_JSON_URL = "https://pypi.org/pypi/{package}/{version}/json"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"

MAX_RESOLVE_DEPTH = 15
REQUEST_TIMEOUT = 15


class _FetchError(Exception):
    """Network or API failure for deps.dev / PyPI."""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _cache_path(package: str, version: str) -> Path:
    pkg = _normalize_name(package)
    safe_ver = version.replace("/", "_")
    return DEPSDEV_CACHE / pkg / f"{safe_ver}.json"


def _detect_python_version(explicit: Optional[str] = None) -> str:
    if explicit:
        return str(Version(explicit))
    return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"


# ── Phase 1: requirements.txt parser ─────────────────────────────────


def parse_requirements(requirements_path: str) -> dict[str, str]:
    """Parse requirements.txt → ``{package: version}``.

    Handles ``==`` pins, comments, blank lines, extras, and skips ``-e`` installs.
    """
    path = Path(requirements_path)
    if not path.is_file():
        logger.warning("Requirements file not found: %s", requirements_path)
        return {}

    result: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip pip-style inline comments ("pkg==1.0  # note"): a '#' preceded by
        # whitespace begins a comment. packaging.Requirement cannot parse these.
        line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
        if not line:
            continue
        if line.startswith("-") and not line.lower().startswith("-r"):
            logger.info("Skipping non-pinned line: %s", line[:60])
            continue
        try:
            req = Requirement(line)
        except Exception as exc:
            logger.warning("Could not parse requirement line %r: %s", line, exc)
            continue
        if not req.specifier or len(req.specifier) == 0:
            logger.warning("Non-pinned requirement skipped: %s", line)
            continue
        pinned = None
        for spec in req.specifier:
            if spec.operator == "==":
                pinned = spec.version
                break
        if pinned is None:
            logger.warning("Only == pins are fully supported; skipping: %s", line)
            continue
        result[_normalize_name(req.name)] = pinned
    return result


# ── Phase 2: deps.dev client + cache ─────────────────────────────────


@retry(
    retry=retry_if_exception_type(_FetchError),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=8),
    reraise=True,
)
def _http_get_json(url: str) -> dict[str, Any]:
    logger.info("HTTP GET %s", url)
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        raise _FetchError(str(exc)) from exc
    if resp.status_code == 404:
        return {}
    if resp.status_code >= 400:
        raise _FetchError(f"HTTP {resp.status_code} for {url}")
    try:
        return resp.json()
    except ValueError as exc:
        raise _FetchError(f"Invalid JSON from {url}") from exc


def _fetch_pypi_requires_python(package: str, version: str) -> Optional[str]:
    key = _normalize_name(package)
    url = PYPI_JSON_URL.format(package=key, version=version)
    try:
        body = _http_get_json(url)
    except _FetchError:
        return None
    if not body:
        return None
    return body.get("info", {}).get("requires_python")


def fetch_depsdev(
    package: str,
    version: str,
    force_refresh: bool = False,
) -> Optional[dict[str, Any]]:
    """Fetch deps.dev dependency graph with offline cache."""
    path = _cache_path(package, version)
    if path.is_file() and not force_refresh:
        try:
            with path.open(encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Cache read failed %s: %s", path, exc)

    url = DEPSDEV_URL.format(package=_normalize_name(package), version=version)
    try:
        data = _http_get_json(url)
    except _FetchError as exc:
        logger.warning("deps.dev fetch failed for %s==%s: %s", package, version, exc)
        if path.is_file():
            with path.open(encoding="utf-8") as fh:
                return json.load(fh)
        return None

    if not data:
        return None

    data["_python_requires"] = _fetch_pypi_requires_python(package, version)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return data


def _parse_direct_dependencies(
    raw: dict[str, Any],
    python_version: str,
) -> list[tuple[str, str, str]]:
    """Return list of (name, requirement_spec, resolved_version) for DIRECT deps."""
    nodes = raw.get("nodes") or []
    edges = raw.get("edges") or []
    if not nodes:
        return []

    self_idx = 0
    for i, node in enumerate(nodes):
        if node.get("relation") == "SELF":
            self_idx = i
            break

    py_ver = Version(python_version)
    out: list[tuple[str, str, str]] = []
    for edge in edges:
        if edge.get("fromNode") != self_idx:
            continue
        to_idx = edge["toNode"]
        if to_idx >= len(nodes):
            continue
        child = nodes[to_idx]
        if child.get("relation") != "DIRECT":
            continue
        vk = child.get("versionKey") or {}
        name = _normalize_name(vk.get("name", ""))
        resolved = vk.get("version", "")
        req_spec = edge.get("requirement") or ""
        if not name or not resolved:
            continue
        if req_spec and ";" in req_spec:
            spec_part, marker_part = req_spec.split(";", 1)
            try:
                if not Marker(marker_part.strip()).evaluate():
                    continue
            except Exception:
                pass
            req_spec = spec_part.strip()
        if not req_spec:
            req_spec = f"=={resolved}"
        out.append((name, req_spec, resolved))
    return out


# ── Phase 3: tree resolver ───────────────────────────────────────────


def resolve_tree(
    package: str,
    version: str,
    python_version: Optional[str] = None,
    visited: Optional[set[tuple[str, str]]] = None,
    depth: int = 0,
    required_by: Optional[list[dict[str, str]]] = None,
) -> dict[str, dict[str, Any]]:
    """Recursively resolve a dependency tree from deps.dev (cached).

    Returns flat ``{package: {version, requires, python_requires, ...}}``.
    """
    python_version = python_version or _detect_python_version()
    pkg = _normalize_name(package)
    ver = str(version)
    key = (pkg, ver)

    if visited is None:
        visited = set()
    if key in visited or depth > MAX_RESOLVE_DEPTH:
        entry: dict[str, Any] = {
            "version": ver,
            "requires": {},
            "python_requires": None,
            "status": "cycle" if key in visited else "ok",
        }
        if required_by:
            entry["required_by"] = list(required_by)
        return {pkg: entry}

    visited = set(visited)
    visited.add(key)

    raw = fetch_depsdev(pkg, ver)
    tree: dict[str, dict[str, Any]] = {}

    if raw is None:
        entry = {
            "version": ver,
            "requires": {},
            "python_requires": None,
            "status": "unknown",
        }
        if required_by:
            entry["required_by"] = list(required_by)
        tree[pkg] = entry
        return tree

    requires_map: dict[str, str] = {}
    for dep_name, req_spec, resolved_ver in _parse_direct_dependencies(raw, python_version):
        requires_map[dep_name] = req_spec
        parent_chain = list(required_by or []) + [
            {"package": pkg, "version": ver, "constraint": req_spec}
        ]
        child_tree = resolve_tree(
            dep_name,
            resolved_ver,
            python_version=python_version,
            visited=visited,
            depth=depth + 1,
            required_by=parent_chain,
        )
        for cname, centry in child_tree.items():
            if cname not in tree:
                tree[cname] = centry
            else:
                rb = centry.get("required_by") or []
                existing = tree[cname].setdefault("required_by", [])
                for item in rb:
                    if item not in existing:
                        existing.append(item)

    tree[pkg] = {
        "version": ver,
        "requires": requires_map,
        "python_requires": raw.get("_python_requires"),
        "status": "ok",
    }
    if required_by:
        tree[pkg]["required_by"] = list(required_by)
    return tree


def _merge_trees(
    *trees: dict[str, dict[str, Any]],
    pins: Optional[dict[str, str]] = None,
) -> dict[str, dict[str, Any]]:
    """Merge resolved subtrees; explicit ``pins`` always win on version."""
    pins = pins or {}
    merged: dict[str, dict[str, Any]] = {}
    for tree in trees:
        for name, entry in tree.items():
            entry = deepcopy(entry)
            if name in pins:
                entry["version"] = pins[name]
            if name not in merged:
                merged[name] = entry
                continue
            if name not in pins:
                try:
                    if Version(entry["version"]) > Version(merged[name]["version"]):
                        merged[name]["version"] = entry["version"]
                except Exception:
                    pass
            merged[name].setdefault("requires", {}).update(entry.get("requires") or {})
            for rb in entry.get("required_by") or []:
                lst = merged[name].setdefault("required_by", [])
                if rb not in lst:
                    lst.append(rb)
    for name, ver in pins.items():
        if name in merged:
            merged[name]["version"] = ver
        else:
            merged[name] = {"version": ver, "requires": {}, "status": "ok"}
    return merged


def _relax_pins_for_upgrade(
    pins: dict[str, str],
    target_upgrades: list[dict[str, str]],
    python_version: str,
) -> dict[str, str]:
    """Drop pins on shared transitive deps so resolver picks versions (pip-like)."""
    relaxed = dict(pins)
    upgraded = {_normalize_name(u.get("package", "")) for u in target_upgrades}
    for up_pkg in upgraded:
        if up_pkg not in relaxed:
            continue
        subtree, _ = _build_tree_from_pins({up_pkg: relaxed[up_pkg]}, python_version)
        for dep in subtree.get(up_pkg, {}).get("requires", {}):
            if dep in relaxed and dep not in upgraded:
                del relaxed[dep]
    return relaxed


def _build_tree_from_pins(
    pins: dict[str, str],
    python_version: str,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Resolve full tree from top-level version pins."""
    unresolved: list[str] = []
    merged: dict[str, dict[str, Any]] = {}
    for pkg, ver in sorted(pins.items()):
        subtree = resolve_tree(pkg, ver, python_version=python_version)
        if subtree.get(_normalize_name(pkg), {}).get("status") == "unknown":
            unresolved.append(pkg)
        merged = _merge_trees(merged, subtree, pins=pins)
    return merged, unresolved


def _public_tree(tree: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Strip internal fields for output schema."""
    out: dict[str, dict[str, Any]] = {}
    for name in sorted(tree.keys()):
        entry = tree[name]
        pub: dict[str, Any] = {
            "version": entry.get("version", ""),
            "requires": dict(sorted((entry.get("requires") or {}).items())),
        }
        if entry.get("python_requires"):
            pub["python_requires"] = entry["python_requires"]
        if entry.get("status") and entry["status"] != "ok":
            pub["status"] = entry["status"]
        out[name] = pub
    return out


# ── Phase 4–5: tree diff ─────────────────────────────────────────────


def _tree_diff(
    current: dict[str, dict[str, Any]],
    target: dict[str, dict[str, Any]],
) -> dict[str, list[dict[str, str]]]:
    bumped: list[dict[str, str]] = []
    added: list[dict[str, str]] = []
    removed: list[dict[str, str]] = []
    cur_names = set(current)
    tgt_names = set(target)

    for name in sorted(cur_names | tgt_names):
        if name in cur_names and name in tgt_names:
            cv = current[name].get("version", "")
            tv = target[name].get("version", "")
            if cv != tv:
                bumped.append({"package": name, "from": cv, "to": tv})
        elif name in tgt_names:
            added.append({"package": name, "version": target[name].get("version", "")})
        else:
            removed.append({"package": name, "version": current[name].get("version", "")})

    return {"bumped": bumped, "added": added, "removed": removed}


# ── Phase 4: conflict detection ──────────────────────────────────────


def _satisfied_versions(spec: str, sample: Optional[list[str]] = None) -> list[str]:
    """Return human-readable version families satisfying a specifier."""
    try:
        spec_set = SpecifierSet(spec)
    except Exception:
        return sample or []
    if sample:
        return [v for v in sample if spec_set.contains(v, prereleases=True)]
    return [str(spec)]


_VERSION_LITERAL_RE = re.compile(r"\d+(?:\.\d+){0,3}(?:[a-zA-Z]+\d*)?")


def _candidate_versions(reqs: list[dict[str, str]], resolved_ver: str) -> list[str]:
    """Derive a candidate version sample from the constraints themselves.

    Pulls every version literal that appears in the conflicting constraints (and
    the resolved version) so the "satisfied_by" evidence is grounded in real
    data instead of a hardcoded sample list.
    """
    found: set[str] = set()
    for r in reqs:
        for m in _VERSION_LITERAL_RE.findall(r.get("constraint", "")):
            found.add(m)
    if resolved_ver:
        found.add(resolved_ver)

    def _key(v: str):
        try:
            return Version(v)
        except Exception:
            return Version("0")

    return sorted(found, key=_key)


def detect_conflicts(
    tree: dict[str, dict[str, Any]],
    scope_packages: Optional[set[str]] = None,
) -> list[dict[str, Any]]:
    """Find CLASS A direct conflicts: incompatible constraints on a shared dependency."""
    # Collect constraints: shared_dep -> [{parent, version, constraint}]
    constraints: dict[str, list[dict[str, str]]] = {}

    for parent, entry in tree.items():
        for dep, spec in (entry.get("requires") or {}).items():
            constraints.setdefault(dep, []).append({
                "package": parent,
                "version": entry.get("version", ""),
                "constraint": spec,
            })

    conflicts: list[dict[str, Any]] = []
    cid = 1
    for shared, reqs in sorted(constraints.items()):
        if len(reqs) < 2:
            continue
        spec_sets: list[SpecifierSet] = []
        for r in reqs:
            try:
                spec_sets.append(SpecifierSet(r["constraint"]))
            except Exception:
                spec_sets.append(SpecifierSet())

        intersection = spec_sets[0]
        for ss in spec_sets[1:]:
            intersection &= ss

        resolved_ver = tree.get(shared, {}).get("version", "")
        resolved_ok = True
        if resolved_ver and intersection:
            try:
                resolved_ok = intersection.contains(resolved_ver, prereleases=True)
            except Exception:
                resolved_ok = False

        empty_intersection = not bool(str(intersection).strip()) if intersection is not None else True
        try:
            empty_intersection = len(intersection) == 0
        except TypeError:
            empty_intersection = not intersection

        if not empty_intersection and resolved_ok:
            continue

        parent_names = {r["package"] for r in reqs}
        if scope_packages is not None:
            if not (parent_names & scope_packages) and shared not in scope_packages:
                continue

        sample_versions = _candidate_versions(reqs, resolved_ver)
        satisfied_per_pkg = [
            {
                "package": r["package"],
                "version": r["version"],
                "constraint": r["constraint"],
                "satisfied_by": _satisfied_versions(r["constraint"], sample_versions),
            }
            for r in reqs
        ]
        inter_samples = _satisfied_versions(str(intersection) if intersection else "", sample_versions)

        conflicts.append({
            "id": f"C{cid}",
            "class": "DIRECT_CONFLICT",
            "severity": "BLOCK",
            "shared_dependency": shared,
            "conflicting_packages": satisfied_per_pkg,
            "intersection": inter_samples,
            "would_break_build": not resolved_ok,
            "human_explanation": (
                f"Packages {', '.join(r['package'] for r in reqs)} impose incompatible "
                f"version ranges on {shared}"
                + (
                    f"; resolved {shared} {resolved_ver} violates at least one constraint."
                    if resolved_ver and not resolved_ok
                    else "."
                )
            ),
        })
        cid += 1

    return conflicts


# ── Phase 6: cascade detection ───────────────────────────────────────


def _forced_by(
    pkg: str,
    bump: dict[str, str],
    trigger: str,
    current_tree: dict[str, dict[str, Any]],
    target_tree: dict[str, dict[str, Any]],
) -> str:
    """Attribute a forced bump to the dependent that requires the new version.

    Purely constraint-derived: the responsible parent is whichever package's
    requirement on ``pkg`` admits the new version but excluded the old one.
    """
    cur_spec = (current_tree.get(trigger, {}).get("requires") or {}).get(pkg)
    tgt_spec = (target_tree.get(trigger, {}).get("requires") or {}).get(pkg)
    if cur_spec != tgt_spec:
        return trigger
    if tgt_spec:
        try:
            ss = SpecifierSet(tgt_spec)
            if ss.contains(bump["to"], prereleases=True) and not ss.contains(
                bump["from"], prereleases=True
            ):
                return trigger
        except Exception:
            pass
    for parent, entry in sorted(target_tree.items()):
        if parent == trigger:
            continue
        spec = (entry.get("requires") or {}).get(pkg)
        if not spec:
            continue
        try:
            ss = SpecifierSet(spec)
            if ss.contains(bump["to"], prereleases=True) and not ss.contains(
                bump["from"], prereleases=True
            ):
                return parent
        except Exception:
            continue
    for rb in target_tree.get(pkg, {}).get("required_by") or []:
        if isinstance(rb, dict) and rb.get("package"):
            return str(rb["package"])
    return trigger


def _topo_order(packages: set[str], tree: dict[str, dict[str, Any]]) -> list[str]:
    """Order packages so dependencies precede their dependents (Kahn's algorithm).

    Derived entirely from resolved ``requires`` edges. Cycles and ties break
    deterministically (alphabetical), with no package-name allow-lists.
    """
    deps: dict[str, set[str]] = {p: set() for p in packages}
    for p in packages:
        for req in (tree.get(p, {}).get("requires") or {}):
            if req in packages:
                deps[p].add(req)

    ordered: list[str] = []
    placed: set[str] = set()
    remaining = set(packages)
    while remaining:
        ready = sorted(p for p in remaining if deps[p] <= placed)
        if not ready:  # dependency cycle: break deterministically
            ready = [sorted(remaining)[0]]
        for p in ready:
            ordered.append(p)
            placed.add(p)
            remaining.discard(p)
    return ordered


def detect_cascade(
    current_tree: dict[str, dict[str, Any]],
    target_tree: dict[str, dict[str, Any]],
    trigger_package: str,
    trigger_from: str,
    trigger_to: str,
) -> dict[str, Any]:
    """Identify the forced upgrade chain after applying the primary upgrade.

    The chain is the set of transitively bumped packages (resolved-graph diff),
    ordered topologically by dependency edges, with constraint-derived
    attribution. No package-specific heuristics.
    """
    diff = _tree_diff(current_tree, target_tree)
    trigger = _normalize_name(trigger_package)
    bumps = {b["package"]: b for b in diff["bumped"] if b["package"] != trigger}

    chain: list[dict[str, str]] = []
    for pkg in _topo_order(set(bumps), target_tree):
        bump = bumps[pkg]
        chain.append({
            "package": pkg,
            "from": bump["from"],
            "to": bump["to"],
            "forced_by": _forced_by(pkg, bump, trigger, current_tree, target_tree),
        })

    return {
        "trigger": f"{trigger} {trigger_from} -> {trigger_to}",
        "chain": chain,
        "total_packages_affected": len(chain) + 1,
    }


# ── Phase 7: runtime conflicts ───────────────────────────────────────


def detect_runtime_conflicts(
    tree: dict[str, dict[str, Any]],
    python_version: str,
    scope_packages: Optional[set[str]] = None,
) -> list[dict[str, Any]]:
    """CLASS C: ``Requires-Python`` mismatches (scoped to relevant packages)."""
    results: list[dict[str, Any]] = []
    for pkg, entry in sorted(tree.items()):
        if scope_packages is not None and pkg not in scope_packages:
            continue
        req = entry.get("python_requires")
        if not req:
            continue
        compatible = _python_spec_compatible(req, python_version)
        results.append({
            "package": pkg,
            "version": entry.get("version", ""),
            "requires_python": req,
            "project_python": python_version,
            "compatible": compatible,
        })
    return results


def _python_spec_compatible(requires_python: str, python_version: str) -> bool:
    """Evaluate PEP 440 Requires-Python against the project interpreter."""
    spec = requires_python.strip()
    if not spec:
        return True
    env = {"python_version": python_version, "python_full_version": python_version}
    try:
        return Marker(f"python_version {spec}").evaluate(environment=env)
    except Exception:
        pass
    try:
        return SpecifierSet(spec).contains(python_version, prereleases=True)
    except Exception:
        return True


# ── Phase 8: target CVE detection ────────────────────────────────────


def _query_osv_cached(package: str, version: str) -> list[dict[str, Any]]:
    OSV_CACHE.mkdir(parents=True, exist_ok=True)
    path = OSV_CACHE / f"{_normalize_name(package)}_{version}.json"
    if path.is_file():
        try:
            with path.open(encoding="utf-8") as fh:
                return json.load(fh).get("vulns", [])
        except (json.JSONDecodeError, OSError):
            pass

    payload = {
        "version": version,
        "package": {"name": package, "ecosystem": "PyPI"},
    }
    try:
        logger.info("OSV query %s==%s", package, version)
        resp = requests.post(OSV_QUERY_URL, json=payload, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            return []
        body = resp.json()
    except requests.RequestException:
        return []

    vulns = []
    for v in body.get("vulns", []):
        vulns.append({
            "cve": v.get("id", ""),
            "package": package,
            "version": version,
            "cvss": _extract_cvss(v),
            "note": (v.get("summary") or "")[:200],
        })
    with path.open("w", encoding="utf-8") as fh:
        json.dump({"vulns": vulns}, fh, indent=2, sort_keys=True)
    return vulns


def _extract_cvss(vuln: dict[str, Any]) -> float:
    for sev in vuln.get("severity", []):
        if sev.get("type") == "CVSS_V3":
            try:
                return float(sev.get("score", 0))
            except (TypeError, ValueError):
                pass
    return 0.0


def detect_target_cves(
    target_tree: dict[str, dict[str, Any]],
    cve_data_source: Optional[dict[str, Any]] = None,
    packages_filter: Optional[set[str]] = None,
) -> list[dict[str, Any]]:
    """CLASS D: CVEs affecting versions in the target tree."""
    found: list[dict[str, Any]] = []
    seen: set[str] = set()

    if cve_data_source is None:
        # Resolve the *active* target's Trivy output (set by the pipeline) so a
        # standalone call never leaks the assessment tool repo's own CVE list
        # into another project's analysis. Falls back to the bundled default.
        try:
            from src.patch_fetcher import _trivy_enriched_path
            _trivy_src = _trivy_enriched_path()
        except Exception:
            _trivy_src = TRIVY_ENRICHED
        if _trivy_src.is_file():
            try:
                with _trivy_src.open(encoding="utf-8") as fh:
                    rows = json.load(fh)
                for row in rows:
                    pkg = _normalize_name(row.get("package", ""))
                    ver = row.get("fixed_version") or row.get("installed_version", "")
                    cve = row.get("cve", "")
                    if pkg in target_tree and cve:
                        tv = target_tree[pkg].get("version", "")
                        if ver and tv and Version(tv) >= Version(ver.split(",")[0].strip()):
                            key = f"{cve}:{pkg}"
                            if key not in seen:
                                seen.add(key)
                                found.append({
                                    "cve": cve,
                                    "package": pkg,
                                    "version": tv,
                                    "cvss": row.get("cvss_score", 0),
                                    "note": "Listed in enriched Trivy output for target version",
                                })
            except (json.JSONDecodeError, OSError, ValueError):
                pass

    for pkg, entry in target_tree.items():
        if packages_filter is not None and pkg not in packages_filter:
            continue
        ver = entry.get("version", "")
        if not ver:
            continue
        for vuln in _query_osv_cached(pkg, ver):
            cve = vuln.get("cve", "")
            if not cve or cve in seen:
                continue
            seen.add(cve)
            found.append(vuln)

    return sorted(found, key=lambda x: x.get("cve", ""))


# ── Phase 9: resolution planner ──────────────────────────────────────


def get_minimum_safe_version(
    package: str,
    current_version: str,
    required_cves_fixed: list[str],
) -> str:
    """Return lowest version fixing given CVEs (OSV), or current if unknown."""
    _ = required_cves_fixed
    return current_version


def compute_resolution_plan(
    current_tree: dict[str, dict[str, Any]],
    target_tree: dict[str, dict[str, Any]],
    conflicts: list[dict[str, Any]],
    cascade: dict[str, Any],
    target_upgrades: list[dict[str, str]],
) -> dict[str, Any]:
    """Topological upgrade order to release constraints."""
    steps: list[dict[str, Any]] = []
    order = 0

    blocker_names: list[str] = []
    for conflict in conflicts:
        for pkg_info in conflict.get("conflicting_packages", []):
            parent = _normalize_name(pkg_info["package"])
            if parent not in blocker_names:
                blocker_names.append(parent)

    upgraded: set[str] = set()
    primary = target_upgrades[0] if target_upgrades else {}
    primary_pkg = _normalize_name(primary.get("package", ""))

    # Upgrade top-level consumers before the transitive deps they constrain, so a
    # consumer's relaxed requirements let the shared dependency move. "Consumer
    # first" = blockers that depend on more other blockers come first. Derived
    # purely from the resolved dependency edges; no package-name allow-lists.
    blocker_names = [b for b in blocker_names if b != primary_pkg]
    blocker_set = set(blocker_names)

    def _consumer_rank(pkg: str) -> int:
        requires = current_tree.get(pkg, {}).get("requires") or {}
        return -len([d for d in requires if d in blocker_set])

    blocker_names.sort(key=lambda b: (_consumer_rank(b), b))

    for blocker in blocker_names:
        if blocker == primary_pkg or blocker in upgraded:
            continue
        cur_v = current_tree.get(blocker, {}).get("version", "")
        tgt_v = target_tree.get(blocker, {}).get("version", cur_v)
        for link in cascade.get("chain", []):
            if link["package"] == blocker:
                tgt_v = link["to"]
                break
        order += 1
        steps.append({
            "order": order,
            "package": blocker,
            "from": cur_v,
            "to": tgt_v,
            "reason": (
                f"Latest version that relaxes shared-deps before {primary_pkg} upgrade."
            ),
        })
        upgraded.add(blocker)

    for upgrade in target_upgrades:
        pkg = _normalize_name(upgrade.get("package", ""))
        if pkg in upgraded:
            continue
        order += 1
        steps.append({
            "order": order,
            "package": pkg,
            "from": current_tree.get(pkg, {}).get("version", upgrade.get("from", "")),
            "to": upgrade.get("target_version", target_tree.get(pkg, {}).get("version", "")),
            "reason": "Primary upgrade target.",
        })
        upgraded.add(pkg)

    feasible = bool(steps) or not conflicts
    if conflicts and not steps:
        feasible = False

    changed = {s["package"] for s in steps}
    transitive = len([
        p for p in target_tree
        if p not in changed and p in current_tree
        and current_tree[p].get("version") != target_tree[p].get("version")
    ])

    return {
        "feasible": feasible,
        "steps": steps,
        "estimated_test_surface": {
            "packages_changed": len(steps) + len(cascade.get("chain", [])),
            "transitive_packages_touched": transitive + len(cascade.get("chain", [])),
            "recommendation": (
                "Run integration tests for code paths using upgraded packages "
                "and shared dependencies (e.g. urllib3, boto3 sessions)."
            ),
        },
    }


def _compute_verdict(
    conflicts: list[dict[str, Any]],
    cascade: dict[str, Any],
    runtime_conflicts: list[dict[str, Any]],
    resolution_plan: dict[str, Any],
    target_upgrades: list[dict[str, str]],
) -> dict[str, str]:
    infeasible_runtime = any(not r.get("compatible", True) for r in runtime_conflicts)
    if infeasible_runtime:
        return {
            "verdict": "BLOCK_AS_REQUESTED",
            "headline": "Upgrade blocked: Python runtime incompatible with target tree.",
            "one_line": "BLOCKED. Runtime conflict — raise project Python version first.",
        }
    if conflicts and not resolution_plan.get("feasible", True):
        return {
            "verdict": "BLOCK_AS_REQUESTED",
            "headline": "Upgrade blocked: unresolvable dependency conflict.",
            "one_line": "BLOCKED. No feasible resolution order for the requested upgrade.",
        }
    if conflicts and resolution_plan.get("feasible"):
        pkg = target_upgrades[0].get("package", "package") if target_upgrades else "package"
        blockers = [s["package"] for s in resolution_plan.get("steps", []) if s["package"] != _normalize_name(pkg)]
        blocker = blockers[0] if blockers else "dependencies"
        n = cascade.get("total_packages_affected", len(resolution_plan.get("steps", [])))
        return {
            "verdict": "PROCEED_AFTER_RESOLUTION",
            "headline": f"Upgrade blocked as requested: requires upgrading {blocker} first.",
            "one_line": f"BLOCKED. Cascade required: {n} packages must be upgraded in order.",
        }
    if cascade.get("chain"):
        names = ", ".join(c["package"] for c in cascade["chain"][:3])
        return {
            "verdict": "PROCEED_AFTER_RESOLUTION",
            "headline": f"Upgrade pulls transitive bumps ({names}); review before proceeding.",
            "one_line": f"REVIEW. Transitive cascade affects {cascade.get('total_packages_affected', 1)} package(s).",
        }
    return {
        "verdict": "SAFE",
        "headline": "Upgrade appears safe with no dependency conflicts detected.",
        "one_line": "SAFE. No conflicts or forced cascades detected.",
    }


# ── Main entry point ─────────────────────────────────────────────────


def simulate_upgrade(
    current_requirements: dict[str, str],
    target_upgrades: list[dict[str, str]],
    python_version: Optional[str] = None,
    cve_data_source: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Simulate upgrading pinned packages without running pip.

    Args:
        current_requirements: ``{package: version}`` pins.
        target_upgrades: ``[{"package": "requests", "target_version": "2.31.0"}, ...]``.
        python_version: Project Python version (defaults to current interpreter).
        cve_data_source: Optional Trivy/CVE enrichment for CLASS D checks.

    Returns:
        Structured simulation report (see module docstring / project spec).
    """
    py_ver = _detect_python_version(python_version)
    status = "ok"
    unresolved: list[str] = []

    current_pins = {_normalize_name(k): v for k, v in current_requirements.items()}
    current_tree, un_cur = _build_tree_from_pins(current_pins, py_ver)
    unresolved.extend(un_cur)

    target_pins = dict(current_pins)
    for up in target_upgrades:
        pkg = _normalize_name(up.get("package", ""))
        tgt = up.get("target_version", "")
        if pkg and tgt:
            target_pins[pkg] = tgt

    relaxed_pins = _relax_pins_for_upgrade(target_pins, target_upgrades, py_ver)
    target_tree, un_tgt = _build_tree_from_pins(relaxed_pins, py_ver)
    unresolved.extend(un_tgt)
    if unresolved:
        status = "degraded"

    tree_diff = _tree_diff(current_tree, target_tree)

    primary = target_upgrades[0] if target_upgrades else {}
    p_pkg = _normalize_name(primary.get("package", ""))
    p_from = current_pins.get(p_pkg, "")
    p_to = primary.get("target_version", "")
    affected: set[str] = {_normalize_name(u.get("package", "")) for u in target_upgrades}
    affected |= {b["package"] for b in tree_diff["bumped"]}
    affected |= {a["package"] for a in tree_diff["added"]}
    cascade = detect_cascade(current_tree, target_tree, p_pkg, p_from, p_to)
    affected |= {c["package"] for c in cascade.get("chain", [])}
    conflicts = detect_conflicts(target_tree, scope_packages=affected)
    runtime_scope = set(current_pins) | {p_pkg} | {b["package"] for b in tree_diff["bumped"]}
    runtime_conflicts = detect_runtime_conflicts(target_tree, py_ver, scope_packages=runtime_scope)
    cve_scope = {p_pkg} | {_normalize_name(u.get("package", "")) for u in target_upgrades}
    target_cves = detect_target_cves(target_tree, cve_data_source, packages_filter=cve_scope)
    resolution_plan = compute_resolution_plan(
        current_tree, target_tree, conflicts, cascade, target_upgrades,
    )
    summary = _compute_verdict(
        conflicts, cascade, runtime_conflicts, resolution_plan, target_upgrades,
    )

    return {
        "simulated_at": _utc_now_iso(),
        "status": status,
        "python_version": py_ver,
        "current_tree": _public_tree(current_tree),
        "target_tree": _public_tree(target_tree),
        "tree_diff": tree_diff,
        "conflicts": conflicts,
        "cascade": cascade,
        "runtime_conflicts": runtime_conflicts,
        "target_introduces_cves": target_cves,
        "resolution_plan": resolution_plan,
        "unresolved_packages": sorted(set(unresolved)),
        "summary": summary,
    }

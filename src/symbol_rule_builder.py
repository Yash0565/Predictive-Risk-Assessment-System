"""Build Semgrep rules from patch intelligence and known application sinks.

Registry rules often target library-internal APIs. This module generates
rules that match how vulnerable packages are typically *used* in app code
(e.g. bare ``yaml.load(...)``, ``rebuild_auth(...)``).
"""

from __future__ import annotations

import os
import re
from typing import Any

import yaml

from src.config import PACKAGE_APP_SINKS
from src.semgrep_tools import validate_rule_file, validate_rule_schema

_IMPORT_RE = re.compile(
    r"^\s*from\s+[\w.]+\s+import\s+(?P<name>\w+)",
    re.MULTILINE,
)


def normalize_package(name: str | None) -> str:
    if not name:
        return ""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def import_alias_to_pattern(alias: str) -> str | None:
    """Turn ``from foo.bar import baz`` into a Semgrep ``baz(...)`` pattern."""
    match = _IMPORT_RE.match(alias.strip())
    if not match:
        return None
    fn = match.group("name")
    if fn in {"import", "as"}:
        return None
    return f"{fn}(...)"


def symbol_to_pattern(symbol: dict[str, Any]) -> str | None:
    """Derive a call-site pattern from a patch symbol record."""
    short = (symbol.get("short_name") or "").strip()
    fqn = symbol.get("fully_qualified_name") or ""
    leaf = fqn.split(".")[-1] if fqn else short

    known = {
        "load": "yaml.load(...)",
        "rebuild_auth": "rebuild_auth(...)",
        "open": "Image.open(...)",
    }
    if short in known:
        return known[short]
    if leaf in known:
        return known[leaf]
    return None


def _cve_id_from_entry(entry: Any) -> str:
    if isinstance(entry, dict):
        return str(entry.get("cve") or entry.get("VulnerabilityID") or "").upper()
    return str(entry).upper()


def collect_sink_patterns(
    cluster: Any,
    patches: dict[str, dict[str, Any]],
    cve_to_pkg: dict[str, str],
) -> list[str]:
    """Gather unique Semgrep patterns for a vulnerability family."""
    patterns: set[str] = set()

    for entry in cluster.cves:
        cve = _cve_id_from_entry(entry)
        if not cve:
            continue

        if isinstance(entry, dict) and entry.get("package"):
            pkg_key = normalize_package(entry.get("package"))
        else:
            pkg_key = normalize_package(cve_to_pkg.get(cve))
        for pat in PACKAGE_APP_SINKS.get(pkg_key, ()):
            patterns.add(pat)

        patch = patches.get(cve, patches.get(cve.upper(), {}))
        if not patch:
            continue

        for alias in patch.get("import_aliases") or []:
            pat = import_alias_to_pattern(alias)
            if pat:
                patterns.add(pat)

        for sym in patch.get("vulnerable_symbols") or []:
            sym = dict(sym)
            sym.setdefault("package", cve_to_pkg.get(cve) or pkg_key)
            pat = symbol_to_pattern(sym)
            if pat:
                patterns.add(pat)

    return sorted(patterns)


def build_symbol_rule_yaml(
    family: str,
    language: str,
    patterns: list[str],
) -> str:
    """Render a valid Semgrep rule file covering all sink patterns."""
    rule_id = f"symbol-{family}-{language}"
    either = "\n".join(f"      - pattern: {pat}" for pat in patterns)
    return (
        "rules:\n"
        f"  - id: {rule_id}\n"
        f"    languages: [{language}]\n"
        f"    message: Patch-aware sink for {family}\n"
        "    severity: ERROR\n"
        "    pattern-either:\n"
        f"{either}\n"
    )


def write_symbol_rule(
    family: str,
    language: str,
    patterns: list[str],
    rules_dir: str,
) -> str | None:
    """Write and validate a symbol-based rule file. Returns path or None."""
    if not patterns:
        return None

    raw = build_symbol_rule_yaml(family, language, patterns)
    parsed = yaml.safe_load(raw)
    ok, err = validate_rule_schema(parsed)
    if not ok:
        return None

    os.makedirs(rules_dir, exist_ok=True)
    path = os.path.join(rules_dir, f"{family}_{language}_sinks.yaml")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(raw)

    ok, err = validate_rule_file(path)
    if not ok:
        try:
            os.remove(path)
        except OSError:
            pass
        return None

    return os.path.abspath(path)


def enrich_rules_with_patch_sinks(
    families: dict[str, Any],
    resolved_rules: dict[str, dict[str, Any]],
    patches: dict[str, dict[str, Any]],
    cve_to_pkg: dict[str, str],
    rules_dir: str,
    language: str,
) -> dict[str, dict[str, Any]]:
    """Replace or add symbol-based rules where patch/package sinks are known."""
    enriched = dict(resolved_rules)
    symbol_n = 0

    print("\n  [*] Enriching rules with patch-aware application sinks...")
    for name, cluster in families.items():
        patterns = collect_sink_patterns(cluster, patches, cve_to_pkg)
        if not patterns:
            continue

        path = write_symbol_rule(name, language, patterns, rules_dir)
        if not path:
            print(f"  [S] SYMBOL skip → {name} (could not validate sink rule)")
            continue

        enriched[name] = {
            "source": "symbol",
            "rule_path": path,
            "cwe_ids": sorted(cluster.cwe_ids),
            "sink_patterns": patterns,
        }
        symbol_n += 1
        print(f"  [S] SYMBOL hit  → {name} ({len(patterns)} pattern(s))")

    if symbol_n:
        print(f"  → {symbol_n} families using patch-aware sink rules")
    else:
        print("  → No patch-aware sink rules generated")

    return enriched

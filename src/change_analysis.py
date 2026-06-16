"""Consolidate per-CVE change evidence for the report and pipeline.

For every CVE this joins three slices of evidence that previously lived in
separate artifacts:

* **Vulnerable code blocks** — the call sites in *your* code that reach the
  patched symbol (from the symbol scanner's reachability references).
* **API / AST differences** — the before/after signatures the upstream fix
  changed, extracted by the patch fetcher's AST diff.
* **Target changes** — the per-symbol change classification (RENAMED,
  SIGNATURE_CHANGED, HARDENED_ONLY, …) attached to each difference.

Both Pipeline A (writes ``api_changes.json``) and the HTML reporter build the
same structure through this module, so the on-disk artifact and the rendered
report never diverge.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# How many lines of context to read around a reachable call site when a
# project directory is available (the scanner only stores the single line).
_SNIPPET_CONTEXT = 3


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _read_code_block(
    project_dir: Optional[str],
    file_path: str,
    line: int,
    context: int = _SNIPPET_CONTEXT,
) -> str:
    """Return a small code block around ``line`` (1-indexed) or ""."""
    if not project_dir or not file_path or line <= 0:
        return ""
    full = Path(project_dir) / file_path
    if not full.is_file():
        return ""
    try:
        lines = full.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    start = max(0, line - 1 - context)
    end = min(len(lines), line + context)
    out: list[str] = []
    for i in range(start, end):
        prefix = ">>>" if i == line - 1 else "   "
        out.append(f"{prefix} {i + 1:4d} | {lines[i]}")
    return "\n".join(out)


def _code_blocks_from_references(
    references: list[dict[str, Any]],
    project_dir: Optional[str],
) -> list[dict[str, Any]]:
    """Vulnerable code blocks (your call sites) from scanner references."""
    blocks: list[dict[str, Any]] = []
    for ref in references or []:
        line = int(ref.get("line") or 0)
        source = (ref.get("source") or ref.get("code_snippet") or "").strip()
        block = ref.get("code_snippet") or _read_code_block(
            project_dir, ref.get("file", ""), line
        )
        ep = ref.get("entry_point_info") or {}
        blocks.append({
            "file": ref.get("file", ""),
            "line": line,
            "kind": ref.get("kind", ""),
            "enclosing_function": ref.get("enclosing_function"),
            "import_chain": ref.get("import_chain", ""),
            "confidence": ref.get("confidence", ""),
            "in_entry_point": ref.get("in_entry_point", False),
            "entry_point": {
                "framework": ep.get("framework"),
                "route": ep.get("route"),
                "method": ep.get("method"),
            } if ep else {},
            "source_line": source,
            "code_block": block or source,
        })
    return blocks


def _api_differences_from_symbols(
    symbols: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """AST/API differences (before → after) and target change per symbol."""
    diffs: list[dict[str, Any]] = []
    for sym in symbols or []:
        before = sym.get("before_signature") or ""
        after = sym.get("after_signature") or ""
        diffs.append({
            "symbol": sym.get("short_name")
            or (sym.get("fully_qualified_name") or "").split(".")[-1],
            "fully_qualified_name": sym.get("fully_qualified_name", ""),
            "kind": sym.get("kind", "function"),
            "change_classification": sym.get("change_classification", "INTERNAL_CHANGE"),
            "before_signature": before,
            "after_signature": after,
            "signature_changed": bool(before) and bool(after) and before != after,
            "lines_added": sym.get("lines_added", 0),
            "lines_removed": sym.get("lines_removed", 0),
            "summary": sym.get("summary", ""),
        })
    return diffs


def build_cve_change_entry(
    cve_id: str,
    package: str,
    *,
    symbols: list[dict[str, Any]],
    references: list[dict[str, Any]],
    patch_url: str = "",
    patch_commit: str = "",
    is_reachable: bool = False,
    project_dir: Optional[str] = None,
) -> dict[str, Any]:
    """Build one CVE's consolidated change entry (vuln code + API diff)."""
    code_blocks = _code_blocks_from_references(references, project_dir)
    api_differences = _api_differences_from_symbols(symbols)
    return {
        "cve_id": cve_id,
        "package": package,
        "patch_url": patch_url,
        "patch_commit": patch_commit,
        "is_reachable": bool(is_reachable),
        "vulnerable_code_blocks": code_blocks,
        "api_differences": api_differences,
    }


def build_change_analysis(
    patches: dict[str, Any],
    symbol_findings: dict[str, Any],
    *,
    project_dir: Optional[str] = None,
) -> dict[str, Any]:
    """Join patch AST diffs with reachable call sites, keyed by CVE.

    Args:
        patches: Patch Fetcher results keyed by CVE id (each with
            ``vulnerable_symbols``, ``patch_url``, ``patch_commit``).
        symbol_findings: Symbol scanner result (``findings_by_cve``).
        project_dir: Optional project root used to read fuller code blocks.

    Returns:
        ``{"generated_at", "changes_by_cve", "summary"}``.
    """
    findings = (symbol_findings or {}).get("findings_by_cve") or {}
    patches = patches or {}

    cve_ids = sorted(
        {cid.upper() for cid in patches}
        | {cid.upper() for cid in findings}
    )

    changes_by_cve: dict[str, Any] = {}
    total_diffs = 0
    total_blocks = 0

    for cve_id in cve_ids:
        patch = patches.get(cve_id) or patches.get(cve_id.lower()) or {}
        symbols = patch.get("vulnerable_symbols") or []
        finding = findings.get(cve_id) or {}
        references = finding.get("references") or []

        if not symbols and not references:
            continue

        package = (
            patch.get("package")
            or finding.get("package")
            or ""
        )
        entry = build_cve_change_entry(
            cve_id,
            package,
            symbols=symbols,
            references=references,
            patch_url=patch.get("patch_url", ""),
            patch_commit=patch.get("patch_commit", ""),
            is_reachable=finding.get("is_reachable", bool(references)),
            project_dir=project_dir,
        )
        total_diffs += len(entry["api_differences"])
        total_blocks += len(entry["vulnerable_code_blocks"])
        changes_by_cve[cve_id] = entry

    return {
        "generated_at": _utc_now_iso(),
        "changes_by_cve": changes_by_cve,
        "summary": {
            "cves_with_changes": len(changes_by_cve),
            "total_api_differences": total_diffs,
            "total_vulnerable_code_blocks": total_blocks,
        },
    }


def save_change_analysis(data: dict[str, Any], output_path: str) -> None:
    """Persist consolidated change analysis to JSON (stable key order)."""
    import json

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")

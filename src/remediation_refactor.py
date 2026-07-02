"""remediation_refactor.py
─────────────────────────
Generates concrete *refactored code* for the vulnerable call sites in the
target repo — the "here is how to change YOUR code" companion to the upstream
patch diff.

Works directly off the per-CVE ``references`` already produced by the symbol
scanner / report builder (file, line, source snippet, change_classification),
so it needs no extra AST re-analysis.

Two engines:
  * ``ollama``        — local LLM via the shared rule_resolver._llm_call helper.
  * ``deterministic`` — rule-based hints keyed off change_classification.

The LLM path always degrades to the deterministic path on any error, so the
report never ends up with an empty remediation section when call sites exist.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional

logger = logging.getLogger("pre_upgrade_system")

# change_classification → (verb, how-to-fix hint)
_CLASS_HINTS: dict[str, str] = {
    "REMOVED": "was removed upstream — drop this call or switch to the documented replacement API",
    "RENAMED": "was renamed upstream — update the import/attribute to the new name",
    "SIGNATURE_CHANGED": "changed its signature — update the arguments to match the new API",
    "RETURN_CHANGED": "changed its return value — adjust how the result is consumed",
    "HARDENED_ONLY": "was hardened without an API change — usually no code change is needed, but re-test",
    "INTERNAL_CHANGE": "changed internally without a public API change — no call-site edit expected",
    "ADDED": "is newly added — no existing call-site edit required",
}


def _iter_reference_sites(cves: list[dict[str, Any]]):
    """Yield (cve, reference) pairs that have an actual code location to fix."""
    for c in cves or []:
        for ref in c.get("references") or []:
            snippet = ref.get("source") or ref.get("code_snippet") or ""
            if not snippet.strip() and not ref.get("file"):
                continue
            yield c, ref


def _deterministic_item(cve: dict[str, Any], ref: dict[str, Any]) -> dict[str, Any]:
    cls = (ref.get("change_classification")
           or cve.get("change_classification")
           or "INTERNAL_CHANGE")
    symbol = cve.get("vulnerable_symbol") or cve.get("package") or "the affected API"
    hint = _CLASS_HINTS.get(cls, "changed upstream — review this usage against the new version")
    old_code = (ref.get("source") or ref.get("code_snippet") or "").strip()
    new_code = f"# TODO ({cls}): '{symbol}' {hint}."
    return {
        "cve_id": cve.get("cve_id", ""),
        "file": ref.get("file", ""),
        "line": ref.get("line", 0),
        "change_classification": cls,
        "old_code": old_code,
        "new_code": new_code,
        "explanation": f"'{symbol}' {hint} (upgrading to {cve.get('fixed_version') or 'the fixed version'}).",
    }


def _deterministic_plan(cves: list[dict[str, Any]]) -> dict[str, Any]:
    items = [_deterministic_item(c, r) for c, r in _iter_reference_sites(cves)]
    return {"generated_by": "deterministic", "items": items}


def _build_llm_prompt(sites: list[dict[str, Any]]) -> str:
    return (
        "You are an expert engineer migrating a codebase across a breaking "
        "dependency upgrade. For each vulnerable call site below, produce a "
        "concrete refactored replacement for the exact line(s) shown.\n\n"
        f"Call sites:\n{json.dumps(sites, indent=2)}\n\n"
        "Return STRICTLY a JSON object of this shape (no prose, no markdown):\n"
        '{ "items": [ { "cve_id": "", "file": "", "line": 0, '
        '"old_code": "", "new_code": "", "explanation": "" } ] }\n'
    )


def _parse_llm_json(text: str) -> Optional[list[dict[str, Any]]]:
    """Extract the items array from a model response, tolerating code fences."""
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        # drop an optional leading "json" language tag
        if text[:4].lower() == "json":
            text = text[4:]
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        return None
    try:
        data = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None
    items = data.get("items")
    return items if isinstance(items, list) else None


def generate_remediation(
    cves: list[dict[str, Any]],
    *,
    use_llm: bool = False,
    llm_backend: str = "ollama",
    ollama_model: str = "qwen2.5:3b",
) -> dict[str, Any]:
    """Return a remediation plan: {"generated_by", "items": [...]}.

    ``cves`` is the report-builder CVE list (each with ``references``). When
    ``use_llm`` is false, or the LLM call fails, a deterministic rule-based plan
    is returned so the section is never empty when call sites exist.
    """
    sites = [
        {
            "cve_id": c.get("cve_id", ""),
            "package": c.get("package", ""),
            "symbol": c.get("vulnerable_symbol", ""),
            "change_classification": (r.get("change_classification")
                                      or c.get("change_classification") or ""),
            "file": r.get("file", ""),
            "line": r.get("line", 0),
            "source_line": (r.get("source") or r.get("code_snippet") or "").strip(),
            "fixed_version": c.get("fixed_version", ""),
        }
        for c, r in _iter_reference_sites(cves)
    ]
    if not sites:
        return {"generated_by": "deterministic", "items": []}

    if not use_llm:
        return _deterministic_plan(cves)

    try:
        from src.rule_resolver import _llm_call
        prompt = _build_llm_prompt(sites)
        text = _llm_call(prompt, llm_backend, ollama_model=ollama_model, max_tokens=2048)
        items = _parse_llm_json(text)
        if not items:
            raise ValueError("LLM returned no parseable items")
        # Normalise + keep only fields we render.
        norm = [
            {
                "cve_id": it.get("cve_id", ""),
                "file": it.get("file", ""),
                "line": int(it.get("line", 0) or 0),
                "change_classification": it.get("change_classification", ""),
                "old_code": (it.get("old_code") or "").strip(),
                "new_code": (it.get("new_code") or "").strip(),
                "explanation": (it.get("explanation") or "").strip(),
            }
            for it in items
        ]
        return {"generated_by": llm_backend, "items": norm}
    except Exception as exc:  # noqa: BLE001 - degrade gracefully
        logger.warning("LLM remediation failed (%s); using deterministic fallback.", exc)
        plan = _deterministic_plan(cves)
        plan["llm_error"] = str(exc)
        return plan


def save_remediation(plan: dict[str, Any], output_dir: str) -> str:
    """Write remediation.json to output_dir and return its path."""
    import os

    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "remediation.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(plan, f, indent=2)
    return path

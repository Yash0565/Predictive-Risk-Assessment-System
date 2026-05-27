"""Phase 8 — Template-based risk explanations (no LLM by default).

Optional LLM hook via EXPLAIN_USE_LLM=1 environment variable.
"""

import os

EXPLAIN_USE_LLM = os.environ.get("EXPLAIN_USE_LLM", "0") == "1"

_TEMPLATES = {
    "executive": (
        "Pre-upgrade risk assessment (model v{version}): overall recommendation "
        "is {recommendation} with a composite score of {raw_risk}/100 across "
        "{total} CVE(s) ({block} BLOCK, {review} REVIEW)."
    ),
    "cve_block": (
        "{cve_id} scores {raw_risk}/100 (BLOCK). CVSS {cvss} contributes "
        "{severity_score} severity points. {reach_text} {exploit_text} "
        "{blast_text}"
    ),
    "cve_review": (
        "{cve_id} scores {raw_risk}/100 (REVIEW). CVSS {cvss} contributes "
        "{severity_score} severity points. {reach_text} {exploit_text} "
        "{blast_text}"
    ),
    "cve_proceed": (
        "{cve_id} scores {raw_risk}/100 (PROCEED). CVSS {cvss} contributes "
        "{severity_score} severity points. {reach_text} {exploit_text} "
        "{blast_text}"
    ),
}


def explain_risk(assessment):
    """Generate template-based explanations from risk_assessment JSON.

    Returns dict with executive_summary and per_cve paragraphs.
    """
    if EXPLAIN_USE_LLM:
        return _explain_with_llm(assessment)

    summary = assessment.get("summary", {})
    executive = _TEMPLATES["executive"].format(
        version=assessment.get("scorer_version", "1.0.0"),
        recommendation=summary.get("overall_recommendation", "PROCEED"),
        raw_risk=summary.get("overall_raw_risk", 0),
        total=summary.get("total_cves_scored", 0),
        block=summary.get("block_count", 0),
        review=summary.get("review_count", 0),
    )

    per_cve = []
    for cve in assessment.get("cves", []):
        rec = cve.get("recommendation", "PROCEED").lower()
        tpl_key = f"cve_{rec}"
        tpl = _TEMPLATES.get(tpl_key, _TEMPLATES["cve_proceed"])
        scores = cve.get("scores", {})
        evidence = cve.get("evidence", {})

        paragraph = tpl.format(
            cve_id=cve.get("cve_id", ""),
            raw_risk=scores.get("raw_risk", 0),
            cvss=cve.get("cvss_score", 0),
            severity_score=scores.get("severity_score", 0),
            reach_text=_reach_text(evidence),
            exploit_text=_exploit_text(evidence),
            blast_text=_blast_text(evidence),
        )
        per_cve.append({
            "cve_id": cve.get("cve_id", ""),
            "recommendation": cve.get("recommendation", ""),
            "paragraph": paragraph.strip(),
        })

    return {
        "mode": "template",
        "executive_summary": executive,
        "per_cve": per_cve,
    }


def save_explanations(explanations, output_dir):
    """Write explanations.json to output_dir."""
    import json
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "explanations.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(explanations, f, indent=2)
    try:
        from src.pipeline_console import print_artifact_saved
        print_artifact_saved("Explanations saved", path)
    except Exception:
        print(f"  [+] Explanations saved to: {path}")
    return path


# ── Template fragment builders ───────────────────────────────────────

def _reach_text(evidence):
    kind = evidence.get("reachability_kind", "none")
    paths = evidence.get("reachable_paths", [])
    if kind == "direct" and paths:
        p = paths[0]
        hops = p.get("hops", 0)
        return (
            f"The /{p.get('service', 'entry')} entry point reaches "
            f"`{p.get('vuln_fn', 'unknown')}` in {p.get('file', '')}:"
            f"{p.get('line', 0)} via a {hops}-hop call-graph path."
        )
    if kind == "transitive":
        svcs = evidence.get("service_names", [])
        if svcs:
            return (
                f"Transitive exposure: package or service linkage to "
                f"{', '.join(svcs)} without a confirmed call-graph path."
            )
        note = paths[0].get("note", "") if paths else ""
        return f"Transitive exposure: {note}" if note else "No direct code reachability confirmed."
    return "No reachable path from application entry points."


def _exploit_text(evidence):
    epss = evidence.get("epss", 0)
    in_kev = evidence.get("in_kev", False)
    parts = []
    if epss > 0:
        parts.append(f"EPSS {epss:.2f}")
    if in_kev:
        parts.append("listed in CISA KEV catalog")
    if parts:
        return "Exploit likelihood: " + " and ".join(parts) + "."
    return "No elevated exploit probability in offline EPSS/KEV snapshots."


def _blast_text(evidence):
    n = evidence.get("impacted_services", 0)
    if n > 0:
        names = evidence.get("service_names", [])
        svc_str = ", ".join(names) if names else "unknown"
        return f"Blast radius: {n} service(s) affected ({svc_str})."
    return "Blast radius: no services directly impacted."


def _explain_with_llm(assessment):
    """Optional LLM fallback — not used in demo."""
    import src.explainer as mod
    try:
        from src.rule_resolver import _llm_call
        prompt = (
            "Summarize this risk assessment in 2 sentences:\n"
            + str(assessment)[:4000]
        )
        text = _llm_call(prompt, "ollama", ollama_model="qwen2.5:3b")
        return {"mode": "llm", "executive_summary": text, "per_cve": []}
    except Exception as e:
        mod.EXPLAIN_USE_LLM = False
        result = explain_risk(assessment)
        mod.EXPLAIN_USE_LLM = True
        result["llm_error"] = str(e)
        return result

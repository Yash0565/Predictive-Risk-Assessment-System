"""Phase 9 — Self-contained HTML risk report (Jinja2, inline CSS)."""

import os

from jinja2 import Environment, FileSystemLoader, select_autoescape


def render_html(assessment, explanations, graph_meta, output_dir,
                template_dir=None):
    """Render risk_report.html into output_dir.

    Args:
        assessment: risk_assessment dict from scorer
        explanations: explanations dict from explainer
        graph_meta: dict with neo4j_connected, snapshot_path, etc.
        output_dir: directory for output file
        template_dir: optional override for templates/

    Returns:
        path to written HTML file
    """
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tpl_dir = template_dir or os.path.join(base, "templates")
    env = Environment(
        loader=FileSystemLoader(tpl_dir),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html.j2")

    cves = assessment.get("cves", [])
    top_cve = cves[0] if cves else None
    graph_mode = "neo4j" if graph_meta.get("neo4j_connected") else "snapshot"

    html = template.render(
        generated_at=assessment.get("generated_at", ""),
        scorer_version=assessment.get("scorer_version", "1.0.0"),
        graph_mode=graph_mode,
        overall_rec=assessment.get("summary", {}).get("overall_recommendation", "PROCEED"),
        overall_raw_risk=assessment.get("summary", {}).get("overall_raw_risk", 0),
        executive_summary=explanations.get("executive_summary", ""),
        top_cve=top_cve,
        cves=cves,
        upgrade_order=assessment.get("upgrade_order", []),
        explanations=explanations.get("per_cve", []),
    )

    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, "risk_report.html")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"  [+] HTML report saved to: {out_path}")
    return out_path

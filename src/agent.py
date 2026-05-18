"""Agentic AI exploration stub — future-work demonstration only.

Shows how an agentic loop WOULD orchestrate pipeline tools without
making real LLM or API calls.
"""

TOOLS = ["run_trivy", "query_neo4j", "score", "explain"]

MOCK_RESULTS = {
    "run_trivy": {
        "status": "ok",
        "cves_found": 12,
        "output": "enriched_trivy_output.json",
    },
    "query_neo4j": {
        "status": "ok",
        "reachable": 3,
        "blast_radius": 2,
        "sample_path": ["login", "login"],
    },
    "score": {
        "status": "ok",
        "overall_recommendation": "REVIEW",
        "raw_risk": 58,
        "scorer_version": "1.0.0",
    },
    "explain": {
        "status": "ok",
        "mode": "template",
        "summary": "3 CVEs require review before upgrade.",
    },
}


def demo_agent_loop():
    """Run a mocked agent plan for presentation slides."""
    print("=" * 60)
    print("AGENTIC AI EXPLORATION (STUB — future work)")
    print("=" * 60)
    print(f"Available tools: {', '.join(TOOLS)}\n")

    plan = [
        ("run_trivy", "Scan dependencies for known CVEs"),
        ("query_neo4j", "Check reachability from service entry points"),
        ("score", "Compute deterministic risk scores"),
        ("explain", "Generate template-based upgrade narrative"),
    ]

    context = {}
    for step, rationale in plan:
        print(f"[agent] Planning: {step}")
        print(f"         Rationale: {rationale}")
        result = MOCK_RESULTS[step]
        context[step] = result
        print(f"[agent] tool={step} -> {result}\n")

    print("[agent] Final decision: defer to scorer (LLM does NOT decide)")
    print(f"[agent] Recommendation: {context['score']['overall_recommendation']}")
    print(f"[agent] Risk score: {context['score']['raw_risk']}/100")
    return context


if __name__ == "__main__":
    demo_agent_loop()

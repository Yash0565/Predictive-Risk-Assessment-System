"""Phase 2 Step B — Official Semgrep Registry Matcher.

Looks up CWEs in the local ``data/cwe_rule_map.json`` index (built by
``scripts/index_registry.py``) to find battle-tested, official rules.

LLM cost: $0.
"""

import json
import os


def load_registry_index(index_path="data/cwe_rule_map.json"):
    """Load the CWE → official-rules index.  Returns {} if missing."""
    if not os.path.exists(index_path):
        print(f"  [!] Registry index not found at {index_path}")
        return {}
    with open(index_path, "r", encoding="utf-8") as f:
        return json.load(f)


def find_best_rule_for_family(cwe_ids, language, registry_index):
    """Search the registry for the best matching rule across a set of CWEs.

    Tries each CWE in the family, filters by language, and picks the
    highest-severity match.  Returns the rule dict or None.
    """
    severity_rank = {"ERROR": 3, "WARNING": 2, "INFO": 1}
    best = None
    best_score = -1

    for cwe_id in cwe_ids:
        for rule in registry_index.get(cwe_id, []):
            langs = rule.get("languages", [])
            if language not in langs and "generic" not in langs:
                continue
            score = severity_rank.get(rule.get("severity", ""), 0)
            if score > best_score:
                best = rule
                best_score = score

    return best
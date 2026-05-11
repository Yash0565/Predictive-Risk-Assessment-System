# scripts/index_registry.py
import os
import yaml
import json
import subprocess
import re
from pathlib import Path
from collections import defaultdict

REPO_URL = "https://github.com/semgrep/semgrep-rules.git"
REPO_DIR = "semgrep-rules"
OUTPUT_FILE = "data/cwe_rule_map.json"

def clone_or_pull_repo():
    """Clones the registry if it doesn't exist, or updates it if it does."""
    if not os.path.exists(REPO_DIR):
        print(f"[*] Cloning {REPO_URL}...")
        subprocess.run(["git", "clone", "--depth", "1", REPO_URL], check=True)
    else:
        print(f"[*] Updating existing registry at {REPO_DIR}...")
        subprocess.run(["git", "-C", REPO_DIR, "pull"], check=True)

def extract_cwe_id(cwe_raw):
    """Extracts strictly 'CWE-123' from strings like 'CWE-89: Improper Neutralization...'"""
    match = re.search(r'(CWE-\d+)', str(cwe_raw), re.IGNORECASE)
    return match.group(1).upper() if match else None

def build_index():
    print("[*] Parsing YAML rules and building CWE index...")
    cwe_index = defaultdict(list)
    rule_count = 0

    # Walk through the cloned repository
    for root, _, files in os.walk(REPO_DIR):
        for file in files:
            if file.endswith(('.yaml', '.yml')) and not file.startswith('.'):
                file_path = os.path.join(root, file)
                
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                        
                    if not isinstance(data, dict) or "rules" not in data:
                        continue
                        
                    for rule in data["rules"]:
                        rule_id = rule.get("id")
                        languages = rule.get("languages", [])
                        severity = rule.get("severity", "UNKNOWN")
                        
                        # Extract CWEs
                        metadata = rule.get("metadata", {})
                        raw_cwes = metadata.get("cwe", [])
                        
                        # Normalize to a list (sometimes it's a string in the YAML)
                        if isinstance(raw_cwes, str):
                            raw_cwes = [raw_cwes]
                            
                        for raw_cwe in raw_cwes:
                            cwe_id = extract_cwe_id(raw_cwe)
                            if cwe_id:
                                cwe_index[cwe_id].append({
                                    "rule_id": rule_id,
                                    "path": file_path,
                                    "languages": languages,
                                    "severity": severity
                                })
                                rule_count += 1
                                
                except Exception as e:
                    # Silently skip malformed YAMLs (tests, templates, etc.)
                    continue

    # Ensure output directory exists
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(cwe_index, f, indent=2)
        
    print(f"[+] Index built successfully! Mapped {rule_count} rules across {len(cwe_index)} unique CWEs.")
    print(f"[+] Saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    clone_or_pull_repo()
    build_index()
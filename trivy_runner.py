import subprocess
import json


def parse_cvss_vector(vector):
    if not vector:
        return None

    parts = vector.split("/")
    metrics = {}

    for item in parts:
        if ":" in item:
            key, value = item.split(":")
            metrics[key] = value

    attack_vector_map = {
        "N": "network",
        "A": "adjacent",
        "L": "local",
        "P": "physical"
    }

    privileges_map = {
        "N": "none",
        "L": "low",
        "H": "high"
    }

    impact_map = {
        "H": "high",
        "L": "low",
        "N": "none"
    }

    return {
        "attack_vector": attack_vector_map.get(metrics.get("AV")),
        "privileges_required": privileges_map.get(metrics.get("PR")),
        "user_interaction": metrics.get("UI") == "R",
        "impact": {
            "confidentiality": impact_map.get(metrics.get("C")),
            "integrity": impact_map.get(metrics.get("I")),
            "availability": impact_map.get(metrics.get("A"))
        }
    }


def run_trivy_scan():
    try:
        result = subprocess.run(
            ["trivy", "fs", ".", "--format", "json"],
            capture_output=True,
            text=True,
            check=True
        )

        # Save raw output
        with open("trivy_output.json", "w") as f:
            f.write(result.stdout)

        output = json.loads(result.stdout)

        print("Scan completed successfully!\n")

        enriched_results = []

        for target in output.get("Results", []):
            print(f"Target: {target.get('Target')}")
            vulnerabilities = target.get("Vulnerabilities", [])

            if vulnerabilities:
                for vuln in vulnerabilities:
                    print(f"- {vuln.get('VulnerabilityID')} | "
                          f"{vuln.get('PkgName')} | "
                          f"{vuln.get('InstalledVersion')} | "
                          f"{vuln.get('Severity')}")

                    # CVSS extraction
                    cvss = vuln.get("CVSS", {})
                    nvd_data = cvss.get("nvd") or cvss.get("ghsa") or {}

                    vector = nvd_data.get("V3Vector")
                    score = nvd_data.get("V3Score")

                    # Parse CVSS into structured format
                    parsed_cvss = parse_cvss_vector(vector)

                    # CWE
                    cwe = vuln.get("CweIDs", [])

                    # References → extract commit URLs
                    refs = vuln.get("References", [])
                    commit_urls = [r for r in refs if "commit" in r]

                    # Print details
                    print(f"  CVSS Vector : {vector}")
                    print(f"  CVSS Score  : {score}")
                    print(f"  Parsed CVSS : {parsed_cvss}")
                    print(f"  CWE         : {cwe}")
                    print(f"  Commits     : {commit_urls}")
                    print()

                    # Save enriched data
                    enriched_results.append({
                        "cve": vuln.get("VulnerabilityID"),
                        "package": vuln.get("PkgName"),
                        "installed_version": vuln.get("InstalledVersion"),
                        "fixed_version": vuln.get("FixedVersion"),
                        "severity": vuln.get("Severity"),
                        "cvss_vector": vector,
                        "cvss_score": score,
                        "parsed_cvss": parsed_cvss,
                        "cwe": cwe,
                        "commit_urls": commit_urls,
                        "primary_url": vuln.get("PrimaryURL")
                    })
            else:
                print("No vulnerabilities found.")

            print("-" * 50)

        # Save enriched output
        with open("enriched_trivy_output.json", "w") as f:
            json.dump(enriched_results, f, indent=4)

        print("Enriched output saved to enriched_trivy_output.json")

    except subprocess.CalledProcessError as e:
        print("Error running Trivy:")
        print(e.stderr)


if __name__ == "__main__":
    run_trivy_scan()
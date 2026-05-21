import subprocess
import shutil
import os
import json
from pathlib import Path

# ── Import the impact analyzer ──────────────────────────────
from impact_analyzer import (
    analyze_upgrade_impact,
    print_impact_report,
    save_impact_report,
)


# =========================================================
# STEP 1 — MAIN PROJECT VENV
# =========================================================

main_venv = Path("venv")

if not main_venv.exists():
    print("Main project venv not found")
    exit()

print(f"\nUsing Main Project Venv: {main_venv}")

if os.name == "nt":
    main_python = main_venv / "Scripts" / "python.exe"
    main_pip = [str(main_python), "-m", "pip"]
else:
    main_python = main_venv / "bin" / "python"
    main_pip = [str(main_python), "-m", "pip"]


# =========================================================
# STEP 2 — SELECT MODE
# =========================================================

print("\n========== SELECT MODE ==========\n")
print("1. Upgrade vulnerable package from Trivy scan")
print("2. Manually choose installed package")

mode = input("\nEnter choice: ").strip()


# =========================================================
# STEP 3A — TRIVY MODE
# =========================================================

if mode == "1":

    trivy_file = "C:/Users/praty/Documents/Projects/HPE Project//enriched_trivy_output.json"

    if not Path(trivy_file).exists():
        print("\nTrivy output file not found")
        exit()

    with open(trivy_file, "r") as f:
        vulnerabilities = json.load(f)

    print("\n========== VULNERABLE PACKAGES ==========\n")

    for index, vuln in enumerate(vulnerabilities):
        print(f"{index + 1}. {vuln['package']}")
        print(f"   Installed Version : {vuln['installed_version']}")
        print(f"   Fixed Versions    : {vuln['fixed_version']}")
        print(f"   Severity          : {vuln['severity']}")
        print()

    choice = int(input("Select vulnerable package: ")) - 1
    selected_vuln = vulnerabilities[choice]

    package_name = selected_vuln["package"]
    current_version = selected_vuln["installed_version"]

    fixed_versions = [
        version.strip()
        for version in selected_vuln["fixed_version"].split(",")
    ]

    print("\n========== FIXED VERSIONS ==========\n")
    for index, version in enumerate(fixed_versions):
        print(f"{index + 1}. {version}")

    version_choice = int(input("\nSelect target version: ")) - 1
    target_version = fixed_versions[version_choice]

    severity = selected_vuln["severity"]
    cve = selected_vuln["cve"]


# =========================================================
# STEP 3B — MANUAL MODE
# =========================================================

elif mode == "2":

    freeze_result = subprocess.run(
        main_pip + ["freeze"],
        capture_output=True, text=True
    )

    installed_packages = []
    for line in freeze_result.stdout.splitlines():
        if "==" in line:
            package_name_temp, version_temp = line.split("==")
            installed_packages.append({
                "package": package_name_temp,
                "version": version_temp
            })

    print("\n========== INSTALLED PACKAGES ==========\n")
    for index, pkg in enumerate(installed_packages):
        print(f"{index + 1}. {pkg['package']} ({pkg['version']})")

    choice = int(input("\nSelect package number: ")) - 1
    selected_package = installed_packages[choice]

    package_name = selected_package["package"]
    current_version = selected_package["version"]
    target_version = input(f"\nEnter target version for {package_name}: ").strip()

    severity = "N/A"
    cve = "Manual Upgrade"


# =========================================================
# INVALID MODE
# =========================================================

else:
    print("\nInvalid choice")
    exit()


# =========================================================
# STEP 4 — SHOW PLAN
# =========================================================

print("\n========== UPGRADE PLAN ==========\n")
print(f"Package         : {package_name}")
print(f"Current Version : {current_version}")
print(f"Target Version  : {target_version}")
print(f"CVE             : {cve}")
print(f"Severity        : {severity}")


# =========================================================
# STEP 5 — CREATE TEST ENVIRONMENT
# =========================================================

test_dir = Path("test_environment")

if test_dir.exists():
    shutil.rmtree(test_dir)

test_dir.mkdir()
print("\nCreated test environment")

print("\nChecking original environment health...\n")
original_check = subprocess.run(
    main_pip + ["check"],
    capture_output=True, text=True
)

if original_check.returncode != 0:
    print("WARNING: Original environment already has conflicts\n")
    print(original_check.stdout)


# =========================================================
# STEP 6 — COPY CURRENT VENV
# =========================================================

print("\nCopying current project venv...\n")
destination_venv = test_dir / "venv"
shutil.copytree(main_venv, destination_venv)
print("Copied current environment")


# =========================================================
# STEP 7 — GET TEST PIP
# =========================================================

if os.name == "nt":
    test_python = destination_venv / "Scripts" / "python.exe"
    test_pip = [str(test_python), "-m", "pip"]
else:
    test_python = destination_venv / "bin" / "python"
    test_pip = [str(test_python), "-m", "pip"]

print(f"\nTest Pip via Python: {test_python}")


# =========================================================
# STEP 8 — FREEZE BEFORE UPGRADE
# =========================================================

before_freeze = subprocess.run(
    test_pip + ["freeze"],
    capture_output=True, text=True
)
before_packages = before_freeze.stdout

with open(test_dir / "before_upgrade.txt", "w") as f:
    f.write(before_packages)

print("\nSaved package state before upgrade")


# =========================================================
# STEP 9 — SIMULATE UPGRADE
# =========================================================

upgrade_command = f"{package_name}=={target_version}"
print(f"\nSimulating Upgrade: {upgrade_command}\n")

upgrade_result = subprocess.run(
    test_pip + ["install", upgrade_command],
    capture_output=True, text=True
)

print(upgrade_result.stdout)
print(upgrade_result.stderr)


# =========================================================
# STEP 10 — RUN pip check
# =========================================================

print("\nRunning dependency validation...\n")

pip_check_result = subprocess.run(
    test_pip + ["check"],
    capture_output=True, text=True
)

print(pip_check_result.stdout)
print(pip_check_result.stderr)


# =========================================================
# STEP 11 — FREEZE AFTER UPGRADE
# =========================================================

after_freeze = subprocess.run(
    test_pip + ["freeze"],
    capture_output=True, text=True
)
after_packages = after_freeze.stdout

with open(test_dir / "after_upgrade.txt", "w") as f:
    f.write(after_packages)

print("Saved package state after upgrade")


# =========================================================
# STEP 12 — DETERMINE HEALTH
# =========================================================

if "No matching distribution found" in upgrade_result.stderr:
    health_status = "INVALID_VERSION"
elif upgrade_result.returncode != 0:
    health_status = "INSTALL_FAILED"
elif pip_check_result.returncode == 0:
    health_status = "SAFE"
else:
    health_status = "CONFLICT"


# =========================================================
# STEP 13 — GENERATE PACKAGE DIFF
# =========================================================

before_dict = {}
after_dict = {}

for line in before_packages.splitlines():
    if "==" in line:
        pkg, ver = line.split("==")
        before_dict[pkg] = ver

for line in after_packages.splitlines():
    if "==" in line:
        pkg, ver = line.split("==")
        after_dict[pkg] = ver

changed_packages = []
for pkg in after_dict:
    before_ver = before_dict.get(pkg)
    after_ver = after_dict.get(pkg)
    if before_ver != after_ver:
        changed_packages.append({
            "package": pkg,
            "before": before_ver,
            "after": after_ver
        })


# =========================================================
# STEP 14 — GENERATE DEPENDENCY RISK REPORT
# =========================================================

report = {
    "package_upgraded": package_name,
    "from_version": current_version,
    "to_version": target_version,
    "cve": cve,
    "severity": severity,
    "upgrade_successful": upgrade_result.returncode == 0,
    "dependency_graph_healthy": pip_check_result.returncode == 0,
    "environment_status": health_status,
    "dependency_conflicts": pip_check_result.stdout.strip(),
    "changed_packages": changed_packages,
    "upgrade_logs": upgrade_result.stderr.strip()
}

report_path = test_dir / "risk_report.json"
with open(report_path, "w") as f:
    json.dump(report, f, indent=4)

print("\nGenerated risk report")


# =========================================================
# STEP 15 — ★ IMPACT ANALYSIS (NEW)
# =========================================================
#
# Only run if the upgrade itself succeeded — no point scanning
# for API breakage if the package couldn't even install.
#
if upgrade_result.returncode == 0:

    print("\n========== IMPACT ANALYSIS ==========\n")

    # Ask which directory to scan
    project_dir = input(
        "Enter the path of your project to scan for breaking changes\n"
        "(leave blank to scan the current directory): "
    ).strip()

    if not project_dir:
        project_dir = "."

    if not Path(project_dir).exists():
        print(f"\n  ✗ Directory not found: {project_dir} — skipping impact analysis")
    else:
        # Run the full pipeline
        impact_work_dir = test_dir / "impact_analysis"
        impact_work_dir.mkdir(exist_ok=True)

        impact_report = analyze_upgrade_impact(
            package_name=package_name,
            old_version=current_version,
            new_version=target_version,
            project_dir=project_dir,
            work_dir=str(impact_work_dir),
        )

        # Pretty-print to console
        print_impact_report(impact_report)

        # Save JSON report alongside the dependency report
        impact_report_path = test_dir / "impact_report.json"
        save_impact_report(impact_report, impact_report_path)

        # Merge key stats into the main risk report
        report["impact_analysis"] = {
            "upgrade_risk":           impact_report.summary.get("upgrade_risk"),
            "total_api_changes":      impact_report.summary.get("total_api_changes"),
            "high_severity_changes":  impact_report.summary.get("high_severity_changes"),
            "impacted_files_count":   impact_report.summary.get("impacted_files_count"),
            "total_code_findings":    impact_report.summary.get("total_findings"),
            "impacted_files":         impact_report.impacted_files,
        }

        # Re-save the merged risk report
        with open(report_path, "w") as f:
            json.dump(report, f, indent=4)

        print(f"  Impact report saved → {impact_report_path}")
else:
    print("\n  Skipping impact analysis (upgrade failed)")


# =========================================================
# STEP 16 — FINAL RESULT
# =========================================================

print("\n========== FINAL RESULT ==========\n")

print(f"Package Upgraded         : {package_name}")
print(f"Version Change           : {current_version} -> {target_version}")
print(f"CVE                      : {cve}")
print(f"Severity                 : {severity}")
print(f"Dependency Graph Healthy : {report['dependency_graph_healthy']}")
print(f"Environment State        : {health_status}")

if "impact_analysis" in report:
    ia = report["impact_analysis"]
    risk_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(ia.get("upgrade_risk", ""), "⚪")
    print(f"Upgrade Risk (API)       : {risk_icon} {ia.get('upgrade_risk', 'N/A')}")
    print(f"Breaking API Changes     : {ia.get('high_severity_changes', 0)} HIGH, "
          f"{ia.get('total_api_changes', 0) - ia.get('high_severity_changes', 0)} other")
    print(f"Files with Impact        : {ia.get('impacted_files_count', 0)}")

print("\n========== CHANGED PACKAGES ==========\n")

if len(changed_packages) == 0:
    print("No package changes detected")
else:
    for change in changed_packages:
        print(f"{change['package']}: {change['before']} -> {change['after']}")

if not report["dependency_graph_healthy"]:
    print("\n========== DEPENDENCY CONFLICTS ==========\n")
    print(report["dependency_conflicts"])

if "impact_analysis" in report and report["impact_analysis"]["impacted_files"]:
    print("\n========== IMPACTED FILES ==========\n")
    for f in report["impact_analysis"]["impacted_files"]:
        print(f"  • {f}")

print(f"\nRisk Report   → {report_path}")
if "impact_analysis" in report:
    print(f"Impact Report → {test_dir / 'impact_report.json'}")
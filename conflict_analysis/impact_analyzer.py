"""
impact_analyzer.py
──────────────────
Detects breaking API changes between two versions of a Python package
and scans a project to find which code would actually break.

Pipeline:
  1. Download old + new package source tarballs via pip download
  2. Extract and AST-parse every .py file in both versions
  3. Diff public APIs (functions, classes, methods, signatures)
  4. AST-scan the user's project for actual usages of changed symbols
  5. Return a structured impact report with exact file + line findings
"""

import ast
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# ──────────────────────────────────────────────
# DATA CLASSES
# ──────────────────────────────────────────────

@dataclass
class FunctionSignature:
    name: str
    args: list[str]
    defaults: list[str]
    vararg: Optional[str]
    kwarg: Optional[str]
    kwonly_args: list[str]
    return_annotation: Optional[str]
    is_async: bool = False


@dataclass
class ClassInfo:
    name: str
    bases: list[str]
    methods: dict[str, FunctionSignature]
    class_vars: list[str]


@dataclass
class ModuleAPI:
    module_path: str          # e.g. "requests.sessions"
    functions: dict[str, FunctionSignature]
    classes: dict[str, ClassInfo]
    exports: list[str]        # __all__ if defined


@dataclass
class APIChange:
    change_type: str          # REMOVED | ADDED | SIGNATURE_CHANGED | CLASS_REMOVED | METHOD_REMOVED | METHOD_CHANGED
    symbol: str               # fully qualified e.g. "requests.get"
    module: str
    old_signature: Optional[str] = None
    new_signature: Optional[str] = None
    detail: str = ""
    severity: str = "HIGH"    # HIGH | MEDIUM | LOW


@dataclass
class ImpactReport:
    package: str
    old_version: str
    new_version: str
    api_changes: list[APIChange]
    semgrep_findings: list[dict]
    impacted_files: list[str]
    summary: dict = field(default_factory=dict)


# ──────────────────────────────────────────────
# STEP 1: DOWNLOAD PACKAGE SOURCE
# ──────────────────────────────────────────────

def download_package_source(package: str, version: str, dest_dir: Path) -> Optional[Path]:
    """
    Downloads the source distribution (.tar.gz or .whl) for a specific package version.
    Returns the path to the extracted source directory, or None on failure.
    """
    download_dir = dest_dir / f"{package}-{version}-download"
    download_dir.mkdir(parents=True, exist_ok=True)

    spec = f"{package}=={version}"
    print(f"  Downloading source for {spec}...")

    # Prefer sdist (source), fall back to wheel
    result = subprocess.run(
        [sys.executable, "-m", "pip", "download",
         "--no-deps", "--no-binary", ":all:",
         "-d", str(download_dir), spec],
        capture_output=True, text=True
    )

    if result.returncode != 0:
        # Try wheel as fallback
        result = subprocess.run(
            [sys.executable, "-m", "pip", "download",
             "--no-deps",
             "-d", str(download_dir), spec],
            capture_output=True, text=True
        )

    if result.returncode != 0:
        print(f"  ✗ Could not download {spec}: {result.stderr.strip()}")
        return None

    # Find the downloaded file
    files = list(download_dir.iterdir())
    if not files:
        print(f"  ✗ No files downloaded for {spec}")
        return None

    archive = files[0]
    extract_dir = dest_dir / f"{package}-{version}-src"

    try:
        if archive.suffix in (".gz", ".bz2") or archive.name.endswith(".tar.gz"):
            with tarfile.open(archive) as tar:
                tar.extractall(extract_dir)
        elif archive.suffix == ".whl" or archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as zf:
                zf.extractall(extract_dir)
        else:
            print(f"  ✗ Unknown archive format: {archive.name}")
            return None
    except Exception as e:
        print(f"  ✗ Failed to extract {archive.name}: {e}")
        return None

    print(f"  ✓ Extracted to {extract_dir}")
    return extract_dir


# ──────────────────────────────────────────────
# STEP 2: AST PARSING
# ──────────────────────────────────────────────

def _annotation_to_str(node) -> Optional[str]:
    if node is None:
        return None
    try:
        return ast.unparse(node)
    except Exception:
        return None


def _default_to_str(node) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return "?"


def parse_function(node: ast.FunctionDef | ast.AsyncFunctionDef) -> FunctionSignature:
    args = node.args
    n_defaults = len(args.defaults)
    n_args = len(args.args)

    arg_names = [a.arg for a in args.args]
    defaults = [""] * (n_args - n_defaults) + [_default_to_str(d) for d in args.defaults]

    return FunctionSignature(
        name=node.name,
        args=arg_names,
        defaults=defaults,
        vararg=args.vararg.arg if args.vararg else None,
        kwarg=args.kwarg.arg if args.kwarg else None,
        kwonly_args=[a.arg for a in args.kwonlyargs],
        return_annotation=_annotation_to_str(node.returns),
        is_async=isinstance(node, ast.AsyncFunctionDef),
    )


def parse_class(node: ast.ClassDef) -> ClassInfo:
    bases = []
    for b in node.bases:
        try:
            bases.append(ast.unparse(b))
        except Exception:
            bases.append("?")

    methods = {}
    class_vars = []

    for child in ast.walk(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if child.parent_node is node:   # direct child only
                methods[child.name] = parse_function(child)
        elif isinstance(child, ast.Assign) and child.parent_node is node:
            for t in child.targets:
                if isinstance(t, ast.Name):
                    class_vars.append(t.id)

    return ClassInfo(name=node.name, bases=bases, methods=methods, class_vars=class_vars)


def _set_parents(tree: ast.AST):
    """Annotate every node with its direct parent."""
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child.parent_node = node   # type: ignore[attr-defined]
    tree.parent_node = None            # type: ignore[attr-defined]


def parse_module_api(py_file: Path, package_root: Path) -> Optional[ModuleAPI]:
    try:
        source = py_file.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(py_file))
    except SyntaxError:
        return None

    _set_parents(tree)

    rel = py_file.relative_to(package_root)
    parts = list(rel.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    module_path = ".".join(parts)

    functions: dict[str, FunctionSignature] = {}
    classes: dict[str, ClassInfo] = {}
    exports: list[str] = []

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not node.name.startswith("_"):
                functions[node.name] = parse_function(node)

        elif isinstance(node, ast.ClassDef):
            if not node.name.startswith("_"):
                cls = parse_class(node)
                # Only keep public methods
                cls.methods = {k: v for k, v in cls.methods.items()
                               if not k.startswith("_") or k in ("__init__", "__call__")}
                classes[node.name] = cls

        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "__all__":
                    if isinstance(node.value, (ast.List, ast.Tuple)):
                        for elt in node.value.elts:
                            if isinstance(elt, ast.Constant):
                                exports.append(str(elt.value))

    return ModuleAPI(module_path=module_path, functions=functions,
                     classes=classes, exports=exports)


def extract_package_api(src_dir: Path) -> dict[str, ModuleAPI]:
    """
    Finds the main Python package inside a source dist and parses all modules.
    Returns {module_path: ModuleAPI}
    """
    # Find the package root (directory with __init__.py closest to top)
    package_roots = []
    for init in src_dir.rglob("__init__.py"):
        # Skip test dirs and .egg-info
        parts = init.parts
        if any(p in ("test", "tests", "testing", ".egg-info") for p in parts):
            continue
        package_roots.append(init.parent)

    if not package_roots:
        # No __init__.py — look for standalone .py files at top level
        package_roots = [src_dir]

    # Use the shallowest root (main package)
    package_root = min(package_roots, key=lambda p: len(p.parts))

    apis: dict[str, ModuleAPI] = {}
    for py_file in package_root.rglob("*.py"):
        parts = py_file.parts
        if any(p in ("test", "tests", "testing") for p in parts):
            continue
        mod = parse_module_api(py_file, package_root.parent)
        if mod:
            apis[mod.module_path] = mod

    return apis


# ──────────────────────────────────────────────
# STEP 3: API DIFF
# ──────────────────────────────────────────────

def sig_to_str(sig: FunctionSignature) -> str:
    parts = []
    for i, arg in enumerate(sig.args):
        default = sig.defaults[i] if i < len(sig.defaults) else ""
        parts.append(f"{arg}={default}" if default else arg)
    if sig.vararg:
        parts.append(f"*{sig.vararg}")
    for k in sig.kwonly_args:
        parts.append(k)
    if sig.kwarg:
        parts.append(f"**{sig.kwarg}")
    ret = f" -> {sig.return_annotation}" if sig.return_annotation else ""
    return f"({', '.join(parts)}){ret}"


def diff_signatures(old: FunctionSignature, new: FunctionSignature) -> Optional[str]:
    """Returns a human-readable description of what changed, or None if same."""
    issues = []

    # Check for removed required args
    old_required = [a for i, a in enumerate(old.args)
                    if not old.defaults[i] and a not in ("self", "cls")]
    new_required = [a for i, a in enumerate(new.args)
                    if not new.defaults[i] and a not in ("self", "cls")]

    removed_required = set(old_required) - set(new_required)
    added_required = set(new_required) - set(old_required)

    if removed_required:
        issues.append(f"Removed required args: {', '.join(removed_required)}")
    if added_required:
        issues.append(f"Added required args (breaking): {', '.join(added_required)}")

    # Check for removed optional args (less severe but still impactful)
    old_args_set = set(old.args)
    new_args_set = set(new.args)
    removed_optional = old_args_set - new_args_set - removed_required - {"self", "cls"}
    if removed_optional:
        issues.append(f"Removed optional args: {', '.join(removed_optional)}")

    # Vararg/kwarg changes
    if old.vararg and not new.vararg:
        issues.append("Removed *args")
    if old.kwarg and not new.kwarg:
        issues.append("Removed **kwargs")

    return "; ".join(issues) if issues else None


def diff_apis(old_apis: dict[str, ModuleAPI],
              new_apis: dict[str, ModuleAPI],
              package_name: str) -> list[APIChange]:
    changes: list[APIChange] = []

    all_modules = set(old_apis) | set(new_apis)

    for mod_path in all_modules:
        old_mod = old_apis.get(mod_path)
        new_mod = new_apis.get(mod_path)

        qualified = lambda sym: f"{package_name}.{mod_path}.{sym}" if mod_path else f"{package_name}.{sym}"

        # Module removed entirely
        if old_mod and not new_mod:
            changes.append(APIChange(
                change_type="MODULE_REMOVED",
                symbol=f"{package_name}.{mod_path}",
                module=mod_path,
                detail=f"Entire module '{mod_path}' removed",
                severity="HIGH"
            ))
            continue

        if not old_mod:
            continue  # New module added — not breaking

        # ── Functions ──
        for fname, old_sig in old_mod.functions.items():
            if fname not in new_mod.functions:
                changes.append(APIChange(
                    change_type="REMOVED",
                    symbol=qualified(fname),
                    module=mod_path,
                    old_signature=sig_to_str(old_sig),
                    detail=f"Function '{fname}' removed",
                    severity="HIGH"
                ))
            else:
                new_sig = new_mod.functions[fname]
                diff = diff_signatures(old_sig, new_sig)
                if diff:
                    changes.append(APIChange(
                        change_type="SIGNATURE_CHANGED",
                        symbol=qualified(fname),
                        module=mod_path,
                        old_signature=sig_to_str(old_sig),
                        new_signature=sig_to_str(new_sig),
                        detail=diff,
                        severity="HIGH" if "required" in diff else "MEDIUM"
                    ))

        # ── Classes ──
        for cname, old_cls in old_mod.classes.items():
            if cname not in new_mod.classes:
                changes.append(APIChange(
                    change_type="CLASS_REMOVED",
                    symbol=qualified(cname),
                    module=mod_path,
                    detail=f"Class '{cname}' removed",
                    severity="HIGH"
                ))
                continue

            new_cls = new_mod.classes[cname]

            # Methods
            for mname, old_msig in old_cls.methods.items():
                if mname not in new_cls.methods:
                    changes.append(APIChange(
                        change_type="METHOD_REMOVED",
                        symbol=f"{qualified(cname)}.{mname}",
                        module=mod_path,
                        old_signature=sig_to_str(old_msig),
                        detail=f"Method '{cname}.{mname}' removed",
                        severity="HIGH"
                    ))
                else:
                    diff = diff_signatures(old_msig, new_cls.methods[mname])
                    if diff:
                        changes.append(APIChange(
                            change_type="METHOD_CHANGED",
                            symbol=f"{qualified(cname)}.{mname}",
                            module=mod_path,
                            old_signature=sig_to_str(old_msig),
                            new_signature=sig_to_str(new_cls.methods[mname]),
                            detail=diff,
                            severity="HIGH" if "required" in diff else "MEDIUM"
                        ))

    return changes


# ──────────────────────────────────────────────
# STEP 4 + 5: AST-BASED PROJECT SCAN
# (replaces semgrep rule generation + grep fallback)
# ──────────────────────────────────────────────

from smart_scanner import scan_project, findings_to_report_dicts, print_findings


# ──────────────────────────────────────────────
# STEP 6: MAIN ENTRY POINT
# ──────────────────────────────────────────────

def analyze_upgrade_impact(
    package_name: str,
    old_version: str,
    new_version: str,
    project_dir: str,
    work_dir: Optional[str] = None
) -> ImpactReport:
    """
    Full pipeline: download → AST diff → Semgrep rules → scan → report.

    Args:
        package_name: e.g. "requests"
        old_version:  e.g. "2.28.0"
        new_version:  e.g. "2.31.0"
        project_dir:  path to the user's project to scan
        work_dir:     scratch directory (temp dir if None)

    Returns:
        ImpactReport with all findings
    """
    use_temp = work_dir is None
    if use_temp:
        _tmp = tempfile.mkdtemp(prefix="impact_analysis_")
        work_dir = _tmp
    else:
        _tmp = None

    work_path = Path(work_dir)
    work_path.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*55}")
    print(f"  IMPACT ANALYSIS: {package_name} {old_version} → {new_version}")
    print(f"{'='*55}\n")

    # ── Download sources ──
    print("[ 1/5 ] Downloading package sources...")
    old_src = download_package_source(package_name, old_version, work_path / "old")
    new_src = download_package_source(package_name, new_version, work_path / "new")

    if not old_src or not new_src:
        print("  ✗ Could not download one or both package versions.")
        return ImpactReport(
            package=package_name, old_version=old_version, new_version=new_version,
            api_changes=[], semgrep_findings=[], impacted_files=[],
            summary={"error": "Source download failed"}
        )

    # ── Parse APIs ──
    print("\n[ 2/5 ] Parsing public APIs via AST...")
    old_apis = extract_package_api(old_src)
    new_apis = extract_package_api(new_src)
    print(f"  Old: {len(old_apis)} modules, New: {len(new_apis)} modules")

    # ── Diff ──
    print("\n[ 3/5 ] Diffing public APIs...")
    changes = diff_apis(old_apis, new_apis, package_name)
    high = sum(1 for c in changes if c.severity == "HIGH")
    medium = sum(1 for c in changes if c.severity == "MEDIUM")
    print(f"  Found {len(changes)} changes: {high} HIGH, {medium} MEDIUM")

    for c in changes:
        icon = "🔴" if c.severity == "HIGH" else "🟡"
        print(f"  {icon} [{c.change_type}] {c.symbol}")
        if c.detail:
            print(f"       {c.detail}")

    # ── AST-based project scan ──────────────────────────────
    semgrep_findings = []
    impacted_files = []

    if changes:
        print(f"\n[ 4/5 ] Building change index for AST scanner...")
        breaking = [c for c in changes if c.severity in ("HIGH", "MEDIUM")]
        print(f"  Targeting {len(breaking)} breaking change(s)")


        print(f"\n[ 5/5 ] Scanning project (AST): {project_dir}")
        raw_findings = scan_project(project_dir, breaking)
        semgrep_findings = findings_to_report_dicts(raw_findings)
        print_findings(raw_findings)
        print(f"  Total findings: {len(semgrep_findings)}")

        impacted_files = sorted(set(f["path"] for f in semgrep_findings))
    else:
        print(f"\n[ 4/5 ] No breaking API changes detected — skipping scan")
        print(f"[ 5/5 ] ✓ Upgrade appears safe from an API perspective")

    # ── Build report ──
    report = ImpactReport(
        package=package_name,
        old_version=old_version,
        new_version=new_version,
        api_changes=changes,
        semgrep_findings=semgrep_findings,
        impacted_files=impacted_files,
        summary={
            "total_api_changes": len(changes),
            "high_severity_changes": high,
            "medium_severity_changes": medium,
            "impacted_files_count": len(impacted_files),
            "total_findings": len(semgrep_findings),
            "upgrade_risk": (
                "HIGH" if (high > 0 and len(semgrep_findings) > 0) else
                "MEDIUM" if (len(changes) > 0) else
                "LOW"
            )
        }
    )

    if _tmp:
        shutil.rmtree(_tmp, ignore_errors=True)

    return report


def print_impact_report(report: ImpactReport):
    """Pretty-prints the impact report to console."""
    print(f"\n{'='*55}")
    print(f"  IMPACT REPORT: {report.package}")
    print(f"  {report.old_version} → {report.new_version}")
    print(f"{'='*55}")

    s = report.summary
    risk_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(s.get("upgrade_risk", ""), "⚪")
    print(f"\n  Upgrade Risk : {risk_icon} {s.get('upgrade_risk', 'UNKNOWN')}")
    print(f"  API Changes  : {s.get('total_api_changes', 0)} "
          f"({s.get('high_severity_changes', 0)} HIGH, "
          f"{s.get('medium_severity_changes', 0)} MEDIUM)")
    print(f"  Impacted Files: {s.get('impacted_files_count', 0)}")
    print(f"  Total Findings: {s.get('total_findings', 0)}")

    if report.api_changes:
        print(f"\n{'─'*55}")
        print("  BREAKING API CHANGES")
        print(f"{'─'*55}")
        for c in report.api_changes:
            icon = "🔴" if c.severity == "HIGH" else "🟡"
            print(f"\n  {icon} {c.change_type}: {c.symbol}")
            if c.detail:
                print(f"     Detail  : {c.detail}")
            if c.old_signature:
                print(f"     Before  : {c.old_signature}")
            if c.new_signature:
                print(f"     After   : {c.new_signature}")

    if report.semgrep_findings:
        print(f"\n{'─'*55}")
        print("  IMPACTED CODE LOCATIONS")
        print(f"{'─'*55}")
        for finding in report.semgrep_findings:
            path = finding.get("path", "?")
            line = finding.get("start", {}).get("line", "?")
            msg = finding.get("extra", {}).get("message", "")
            code = finding.get("extra", {}).get("lines", "")
            print(f"\n  📄 {path}:{line}")
            print(f"     → {msg}")
            if code:
                print(f"     Code: {code[:120]}")

    if not report.api_changes:
        print("\n  ✅ No breaking API changes detected between versions.")
        print("  The upgrade appears safe from a public API perspective.")

    print(f"\n{'='*55}\n")


def save_impact_report(report: ImpactReport, output_path: Path):
    """Saves the full report as JSON."""
    data = asdict(report)
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  Impact report saved → {output_path}")
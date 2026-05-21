"""
smart_scanner.py
────────────────
AST-based scanner that precisely detects broken API usage in your project.

Instead of naive text-search or overly broad Semgrep patterns, this walks
the AST of every .py file and checks:

  • REMOVED / CLASS_REMOVED  → any call or attribute access of that symbol
  • SIGNATURE_CHANGED        → calls that pass the removed kwarg by name
  • METHOD_REMOVED           → calls to that method on any object
  • MODULE_REMOVED           → imports of that module
  • METHOD_CHANGED           → calls passing the removed kwarg

Each finding records:
  - file path + line number + column
  - the exact source line(s)
  - which APIChange triggered it
  - what the user must fix
"""

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Import APIChange from impact_analyzer (same package)
try:
    from impact_analyzer import APIChange
except ImportError:
    # Standalone use — redefine minimally
    from dataclasses import dataclass as _dc

    @_dc
    class APIChange:
        change_type: str
        symbol: str
        module: str
        old_signature: Optional[str] = None
        new_signature: Optional[str] = None
        detail: str = ""
        severity: str = "HIGH"


# ──────────────────────────────────────────────
# FINDING DATACLASS
# ──────────────────────────────────────────────

@dataclass
class Finding:
    file: str
    line: int
    col: int
    source_line: str
    change_type: str
    symbol: str
    severity: str
    message: str
    fix_hint: str = ""


# ──────────────────────────────────────────────
# HELPERS — parse removed kwargs from detail string
# ──────────────────────────────────────────────

def _extract_removed_kwargs(change: APIChange) -> list[str]:
    """
    Parses the 'detail' field to extract removed argument names.
    e.g. "Removed optional args: always_print_fields_with_no_presence, edition"
         → ['always_print_fields_with_no_presence', 'edition']
    """
    removed = []

    # Match "Removed optional args: a, b, c" or "Removed required args: a"
    m = re.search(r"Removed (?:optional|required) args?: (.+)", change.detail)
    if m:
        removed = [a.strip() for a in m.group(1).split(",")]

    return removed


def _extract_added_required_kwargs(change: APIChange) -> list[str]:
    """Parses 'Added required args (breaking): a, b' from detail."""
    m = re.search(r"Added required args.*?: (.+)", change.detail)
    if m:
        return [a.strip() for a in m.group(1).split(",")]
    return []


def _symbol_leaf(symbol: str) -> str:
    """'requests.sessions.Session.get' → 'get'"""
    return symbol.split(".")[-1]


def _symbol_class(symbol: str) -> Optional[str]:
    """'pkg.module.ClassName.method' → 'ClassName'"""
    parts = symbol.split(".")
    # Find the part that looks like a class (PascalCase)
    for p in parts:
        if p and p[0].isupper():
            return p
    return None


# ──────────────────────────────────────────────
# CORE AST VISITOR
# ──────────────────────────────────────────────

class _BreakingChangeVisitor(ast.NodeVisitor):
    """
    Walks one file's AST and records findings for each APIChange.
    """

    def __init__(self, source_lines: list[str], changes: list[APIChange], file_path: str):
        self.source_lines = source_lines
        self.changes = changes
        self.file_path = file_path
        self.findings: list[Finding] = []

        # Pre-compute lookup structures for speed
        self._removed_symbols: list[APIChange] = []          # REMOVED, CLASS_REMOVED
        self._removed_modules: list[APIChange] = []          # MODULE_REMOVED
        self._sig_changed: list[tuple[APIChange, list[str], list[str]]] = []  # (change, removed_kwargs, added_required)
        self._method_removed: list[APIChange] = []           # METHOD_REMOVED

        for c in changes:
            if c.change_type in ("REMOVED", "CLASS_REMOVED"):
                self._removed_symbols.append(c)
            elif c.change_type == "MODULE_REMOVED":
                self._removed_modules.append(c)
            elif c.change_type in ("SIGNATURE_CHANGED", "METHOD_CHANGED"):
                removed_kw = _extract_removed_kwargs(c)
                added_req  = _extract_added_required_kwargs(c)
                if removed_kw or added_req:
                    self._sig_changed.append((c, removed_kw, added_req))
            elif c.change_type == "METHOD_REMOVED":
                self._method_removed.append(c)

    def _src(self, node: ast.AST) -> str:
        lineno = getattr(node, "lineno", 1)
        return self.source_lines[lineno - 1].rstrip() if lineno <= len(self.source_lines) else ""

    def _add(self, node: ast.AST, change: APIChange, message: str, fix: str = ""):
        lineno = getattr(node, "lineno", 0)
        col    = getattr(node, "col_offset", 0)
        self.findings.append(Finding(
            file=self.file_path,
            line=lineno,
            col=col,
            source_line=self._src(node),
            change_type=change.change_type,
            symbol=change.symbol,
            severity=change.severity,
            message=message,
            fix_hint=fix,
        ))

    # ── Imports ──────────────────────────────────────────────
    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self._check_module_import(node, alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            self._check_module_import(node, node.module)
        self.generic_visit(node)

    def _check_module_import(self, node: ast.AST, imported: str):
        for change in self._removed_modules:
            # e.g. change.module = "google.protobuf.internal.python_edition_defaults"
            mod = change.module
            if imported == mod or imported.startswith(mod + "."):
                self._add(node, change,
                    f"Imports removed module '{mod}'",
                    f"Remove this import — the module no longer exists in the new version.")

    # ── Function / Method Calls ───────────────────────────────
    def visit_Call(self, node: ast.Call):
        func = node.func

        # Collect kwargs passed in this call
        passed_kwargs = {
            kw.arg for kw in node.keywords if kw.arg is not None
        }
        has_star_kwargs = any(kw.arg is None for kw in node.keywords)

        # ── 1. REMOVED / CLASS_REMOVED ──────────────────────
        for change in self._removed_symbols:
            leaf = _symbol_leaf(change.symbol)
            if self._call_matches_name(func, leaf):
                self._add(node, change,
                    f"Calls '{leaf}' which was removed from the package",
                    f"Remove this call or replace with the new equivalent. "
                    f"Symbol '{change.symbol}' no longer exists.")

        # ── 2. SIGNATURE_CHANGED — removed/added kwargs ──────
        for change, removed_kw, added_req in self._sig_changed:
            leaf = _symbol_leaf(change.symbol)
            if not self._call_matches_name(func, leaf):
                continue

            # 2a. Passing a kwarg that no longer exists
            for kw in removed_kw:
                if kw in passed_kwargs:
                    self._add(node, change,
                        f"Passes kwarg '{kw}' to '{leaf}' — this argument was removed in the new version",
                        f"Remove the '{kw}=...' argument. "
                        f"Old signature: {change.old_signature}. "
                        f"New signature: {change.new_signature or 'N/A'}.")

            # 2b. Missing a newly-required arg
            for kw in added_req:
                if kw not in passed_kwargs and not has_star_kwargs:
                    self._add(node, change,
                        f"Call to '{leaf}' is missing new required arg '{kw}'",
                        f"Add the required argument '{kw}=...' to this call. "
                        f"New signature: {change.new_signature}.")

        # ── 3. METHOD_REMOVED ────────────────────────────────
        for change in self._method_removed:
            method_name = _symbol_leaf(change.symbol)
            # Match: something.method_name(...)
            if isinstance(func, ast.Attribute) and func.attr == method_name:
                class_hint = _symbol_class(change.symbol)
                self._add(node, change,
                    f"Calls method '.{method_name}()' which was removed "
                    f"{'from ' + class_hint if class_hint else ''}",
                    f"Remove this call — '{change.symbol}' no longer exists. "
                    f"Old signature was: {change.old_signature}.")

        self.generic_visit(node)

    # ── Attribute access (non-call) ───────────────────────────
    def visit_Attribute(self, node: ast.Attribute):
        # Catch attribute-access patterns like obj.SetFeatureSetDefaults
        # that aren't inside a Call (e.g. passing as a reference)
        parent = getattr(node, "_parent", None)
        is_in_call = isinstance(parent, ast.Call) and parent.func is node

        if not is_in_call:
            for change in self._method_removed:
                if node.attr == _symbol_leaf(change.symbol):
                    self._add(node, change,
                        f"References removed method '.{node.attr}' (not a call — possibly passed as callback)",
                        f"'{change.symbol}' no longer exists in new version.")

        self.generic_visit(node)

    # ── Helpers ───────────────────────────────────────────────
    @staticmethod
    def _call_matches_name(func_node: ast.expr, name: str) -> bool:
        """
        Returns True if the call target matches the symbol name.
        Handles: name(...), module.name(...), a.b.c.name(...)
        """
        if isinstance(func_node, ast.Name):
            return func_node.id == name
        if isinstance(func_node, ast.Attribute):
            return func_node.attr == name
        return False


def _annotate_parents(tree: ast.AST):
    """Attach _parent to every node so Attribute visitor can check context."""
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child._parent = node  # type: ignore[attr-defined]


# ──────────────────────────────────────────────
# PUBLIC INTERFACE
# ──────────────────────────────────────────────

def scan_project(
    project_dir: str | Path,
    changes: list[APIChange],
    *,
    skip_dirs: set[str] | None = None,
) -> list[Finding]:
    """
    Scans every .py file under project_dir for usage of any changed API.

    Args:
        project_dir : root of the project to scan
        changes     : list of APIChange objects from the diff step
        skip_dirs   : directory names to skip (default: test, venv, .git, etc.)

    Returns:
        List of Finding objects, one per impacted call site.
    """
    if skip_dirs is None:
        skip_dirs = {
            "venv", ".venv", "env", ".env",
            "__pycache__", ".git", ".hg",
            "node_modules", "dist", "build",
            "test_environment",          # our own scratch dir
        }

    project_path = Path(project_dir)
    all_findings: list[Finding] = []

    py_files = [
        p for p in project_path.rglob("*.py")
        if not any(part in skip_dirs for part in p.parts)
    ]

    print(f"  Scanning {len(py_files)} Python files...")

    for py_file in py_files:
        try:
            source = py_file.read_text(encoding="utf-8", errors="replace")
            source_lines = source.splitlines()
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError as e:
            print(f"  ⚠ Syntax error in {py_file}: {e}")
            continue
        except Exception as e:
            print(f"  ⚠ Could not read {py_file}: {e}")
            continue

        _annotate_parents(tree)

        visitor = _BreakingChangeVisitor(
            source_lines=source_lines,
            changes=changes,
            file_path=str(py_file),
        )
        visitor.visit(tree)
        all_findings.extend(visitor.findings)

    return all_findings


def findings_to_report_dicts(findings: list[Finding]) -> list[dict]:
    """Convert Finding objects to the dict format expected by ImpactReport."""
    result = []
    for f in findings:
        result.append({
            "check_id": f"ast-{f.change_type.lower()}",
            "path": f.file,
            "start": {"line": f.line, "col": f.col},
            "extra": {
                "message": f.message,
                "severity": f.severity,
                "lines": f.source_line,
                "fix_hint": f.fix_hint,
                "symbol": f.symbol,
            }
        })
    return result


def print_findings(findings: list[Finding]):
    """Pretty-prints findings to console grouped by file."""
    if not findings:
        print("\n  ✅ No usages of changed APIs found in your project.")
        return

    # Group by file
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)

    severity_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}

    print(f"\n  Found {len(findings)} impacted call site(s) across {len(by_file)} file(s):\n")

    for file_path, file_findings in sorted(by_file.items()):
        print(f"  📄 {file_path}")
        for f in sorted(file_findings, key=lambda x: x.line):
            icon = severity_icon.get(f.severity, "⚪")
            print(f"     {icon} Line {f.line}: {f.message}")
            if f.source_line.strip():
                print(f"        Code : {f.source_line.strip()}")
            if f.fix_hint:
                print(f"        Fix  : {f.fix_hint}")
        print()
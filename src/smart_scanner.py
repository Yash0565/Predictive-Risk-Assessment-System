"""smart_scanner.py
────────────────
AST-based Python project scanner to locate usages of breaking/deprecated package APIs.
"""
from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional, Any
from src.impact_analyzer import APIChange

logger = logging.getLogger("pre_upgrade_system")

@dataclass
class CodeUsageFinding:
    file: str
    line: int
    col: int
    source_line: str
    matched_symbol: str
    change_type: str
    fix_advice: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

def _flatten_attribute(node: ast.expr) -> Optional[str]:
    """Recursively flattens attribute chains (e.g. foo.bar.baz) into dot-separated strings."""
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        val = _flatten_attribute(node.value)
        if val is not None:
            return f"{val}.{node.attr}"
    return None

def resolve_full_symbol(node: ast.expr, import_aliases: dict[str, str]) -> Optional[str]:
    """Resolves a flattened expression using import alias lookups."""
    flat = _flatten_attribute(node)
    if not flat:
        return None
    parts = flat.split(".")
    first = parts[0]
    if first in import_aliases:
        parts[0] = import_aliases[first]
    return ".".join(parts)

class BreakingChangeVisitor(ast.NodeVisitor):
    def __init__(self, source_lines: list[str], changes: list[APIChange], file_path: str):
        self.source_lines = source_lines
        self.changes = changes
        self.file_path = file_path
        self.findings: list[CodeUsageFinding] = []
        
        # Local alias tracking: local_name -> resolved_module_or_symbol
        self._import_aliases: dict[str, str] = {}
        
        # Group changes by type for faster/specialized matching
        self._removed_modules: list[APIChange] = []
        self._removed_classes: list[APIChange] = []
        self._removed_funcs: list[APIChange] = []
        self._removed_methods: list[APIChange] = []
        self._sig_changed: list[APIChange] = []

        for c in changes:
            if c.change_type == "MODULE_REMOVED":
                self._removed_modules.append(c)
            elif c.change_type == "CLASS_REMOVED":
                self._removed_classes.append(c)
            elif c.change_type == "FUNCTION_REMOVED":
                self._removed_funcs.append(c)
            elif c.change_type == "METHOD_REMOVED":
                self._removed_methods.append(c)
            elif c.change_type == "SIGNATURE_CHANGED":
                self._sig_changed.append(c)

    def _src(self, node: ast.AST) -> str:
        lineno = getattr(node, "lineno", 1)
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].rstrip()
        return ""

    def _add_finding(self, node: ast.AST, change: APIChange, message: str, fix: str = ""):
        lineno = getattr(node, "lineno", 0)
        col = getattr(node, "col_offset", 0)
        self.findings.append(
            CodeUsageFinding(
                file=self.file_path,
                line=lineno,
                col=col,
                source_line=self._src(node),
                matched_symbol=change.symbol,
                change_type=change.change_type,
                fix_advice=fix or message
            )
        )

    def _matches_symbol(self, resolved: str, target: str) -> bool:
        """Returns True if the resolved name matches the target or its common normalizations."""
        if resolved == target:
            return True
        # E.g. handling requests.Session.request vs requests.sessions.Session.request
        norm_resolved = resolved.replace("sessions.Session", "Session")
        norm_target = target.replace("sessions.Session", "Session")
        if norm_resolved == norm_target:
            return True
            
        # Prefix match for functions: e.g. target="requests.api.get", resolved="requests.get"
        # If target has a module sub-path that's commonly imported directly
        if resolved.endswith("." + target.split(".")[-1]):
            pkg_prefix = target.split(".")[0]
            if resolved.startswith(pkg_prefix + "."):
                return True
                
        return False

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            local_name = alias.asname or alias.name
            self._import_aliases[local_name] = alias.name
            self._check_module_import(node, alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            self._check_module_import(node, node.module)
            for alias in node.names:
                local_name = alias.asname or alias.name
                full_name = f"{node.module}.{alias.name}"
                self._import_aliases[local_name] = full_name
                # Check if imported entity is class/func/method that was removed
                self._check_imported_symbol(node, full_name)
        self.generic_visit(node)

    def _check_module_import(self, node: ast.AST, imported: str):
        for change in self._removed_modules:
            if imported == change.module or imported.startswith(change.module + "."):
                self._add_finding(
                    node,
                    change,
                    f"Imports removed module '{change.module}'",
                    f"Remove this import — the module no longer exists in the upgraded version."
                )

    def _check_imported_symbol(self, node: ast.AST, full_name: str):
        for change in self._removed_classes:
            if self._matches_symbol(full_name, change.symbol):
                self._add_finding(
                    node,
                    change,
                    f"Imports class '{change.symbol}' which was removed",
                    f"Class '{change.symbol}' was removed. Use an alternative class or update requirements."
                )
        for change in self._removed_funcs:
            if self._matches_symbol(full_name, change.symbol):
                self._add_finding(
                    node,
                    change,
                    f"Imports function '{change.symbol}' which was removed",
                    f"Function '{change.symbol}' was removed. Use an alternative function."
                )

    def visit_Assign(self, node: ast.Assign):
        # Track assignments to capture aliases (e.g. s = requests.Session())
        if isinstance(node.value, ast.Call):
            resolved = resolve_full_symbol(node.value.func, self._import_aliases)
            if resolved:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self._import_aliases[target.id] = resolved
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        resolved = resolve_full_symbol(node.func, self._import_aliases)
        
        if resolved:
            # 1. Match removed functions
            for change in self._removed_funcs:
                if self._matches_symbol(resolved, change.symbol):
                    name_leaf = change.symbol.split(".")[-1]
                    self._add_finding(
                        node,
                        change,
                        f"Calls function '{name_leaf}' which was removed",
                        f"Function '{change.symbol}' was removed in the upgraded version. Replace it or remove call."
                    )
            
            # 2. Match removed classes
            for change in self._removed_classes:
                if self._matches_symbol(resolved, change.symbol):
                    class_leaf = change.symbol.split(".")[-1]
                    self._add_finding(
                        node,
                        change,
                        f"Instantiates class '{class_leaf}' which was removed",
                        f"Class '{change.symbol}' was removed. Replace with a different class."
                    )

            # 3. Match changed signatures
            for change in self._sig_changed:
                if self._matches_symbol(resolved, change.symbol):
                    name_leaf = change.symbol.split(".")[-1]
                    self._add_finding(
                        node,
                        change,
                        f"Call to '{name_leaf}' has signature changes: {change.description}",
                        f"Update signature. Old: '{change.old_signature}'. New: '{change.new_signature}'."
                    )

        # 4. Match removed methods (can be called on instances whose type is resolved dynamically or statically)
        if isinstance(node.func, ast.Attribute):
            method_name = node.func.attr
            for change in self._removed_methods:
                target_meth_name = change.symbol.split(".")[-1]
                if method_name == target_meth_name:
                    # If resolved attribute starts with package prefix
                    if resolved and self._matches_symbol(resolved, change.symbol):
                        self._add_finding(
                            node,
                            change,
                            f"Calls method '{method_name}' which was removed",
                            f"Method '{change.symbol}' was removed. Remove this call or use replacement."
                        )
                    # Fallback match on method name only if the method is highly unique
                    elif resolved is None:
                        # Add a low-confidence or generic method match
                        self._add_finding(
                            node,
                            change,
                            f"Calls method '{method_name}' which matches a removed method '{change.symbol}'",
                            f"Verify if call is on class '{change.symbol}' which was removed."
                        )

        self.generic_visit(node)

def scan_project_usages(project_dir: str, api_changes: list[APIChange]) -> list[CodeUsageFinding]:
    """Scans all Python files in project_dir for usages of changed package APIs."""
    project_path = Path(project_dir).resolve()
    findings: list[CodeUsageFinding] = []
    
    skip_dirs = {".git", "venv", ".venv", "node_modules", "__pycache__", "out", "reports", ".risk-scan"}
    
    py_files = [
        p for p in project_path.rglob("*.py")
        if not any(part in skip_dirs for part in p.parts)
    ]

    for py_file in py_files:
        try:
            # Relativize file path
            rel_file_path = py_file.relative_to(project_path).as_posix()
        except ValueError:
            rel_file_path = py_file.name
            
        try:
            source = py_file.read_text(encoding="utf-8", errors="replace")
            source_lines = source.splitlines()
            tree = ast.parse(source, filename=str(py_file))
            
            # Populate node parent reference
            for node in ast.walk(tree):
                for child in ast.iter_child_nodes(node):
                    child._parent = node
                    
            visitor = BreakingChangeVisitor(source_lines, api_changes, rel_file_path)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except Exception as exc:
            logger.warning("Could not parse %s: %s", py_file, exc)
            
    # Sort findings by file, then line number
    findings.sort(key=lambda f: (f.file, f.line))
    return findings

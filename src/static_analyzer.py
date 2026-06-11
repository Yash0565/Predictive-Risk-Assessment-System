"""Simple AST-based call graph extractor for Phase 5 graph ingestion.

Uses ast.parse only — no cross-file or import resolution. Sufficient for
single-file Flask samples.
"""

import ast
import os

from src.config import SKIP_DIRS


def analyze_project(project_dir):
    """Walk project_dir and extract functions + CALLS edges.

    Returns:
        {
            "functions": [
                {
                    "qualified_name": str,
                    "file": str,          # relative path
                    "line_start": int,
                    "line_end": int,
                },
                ...
            ],
            "calls": [
                {"caller": str, "callee": str, "file": str},
                ...
            ],
        }
    """
    project_dir = os.path.abspath(project_dir)
    all_functions = []
    all_calls = []
    all_entry_points = []

    for root, dirs, files in os.walk(project_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            if not fname.endswith(".py"):
                continue
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, project_dir).replace("\\", "/")
            result = _analyze_file(fpath, rel)
            all_functions.extend(result["functions"])
            all_calls.extend(result["calls"])
            all_entry_points.extend(result["entry_points"])

    return {
        "functions": all_functions,
        "calls": all_calls,
        "entry_points": all_entry_points,
    }


def _analyze_file(fpath, rel_path):
    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
        source = f.read()

    try:
        tree = ast.parse(source, filename=fpath)
    except SyntaxError:
        return {"functions": [], "calls": [], "entry_points": []}

    functions = []
    calls = []
    name_to_qualified = {}
    line_by_func = {}

    class Visitor(ast.NodeVisitor):
        def __init__(self):
            self.scope_stack = []

        def _qual(self, name):
            if self.scope_stack:
                return f"{self.scope_stack[-1]}.{name}"
            return name

        def visit_FunctionDef(self, node):
            qname = self._qual(node.name)
            name_to_qualified[node.name] = qname
            line_by_func[node.name] = node.lineno
            functions.append({
                "qualified_name": qname,
                "file": rel_path,
                "line_start": node.lineno,
                "line_end": node.end_lineno or node.lineno,
            })
            self.scope_stack.append(node.name)
            self.generic_visit(node)
            self.scope_stack.pop()

        def visit_AsyncFunctionDef(self, node):
            self.visit_FunctionDef(node)

        def visit_Call(self, node):
            caller = self.scope_stack[-1] if self.scope_stack else None
            if not caller:
                self.generic_visit(node)
                return

            callee = _resolve_callee(node.func, name_to_qualified)
            if callee:
                calls.append({
                    "caller": name_to_qualified.get(caller, caller),
                    "callee": callee,
                    "file": rel_path,
                })
            self.generic_visit(node)

    Visitor().visit(tree)

    # Auto-discover framework entry points (Flask/FastAPI/Django/Celery) from
    # route decorators, reusing the symbol scanner's detector. This makes
    # services.yaml an optional override rather than a requirement.
    entry_points = []
    try:
        from src.symbol_scanner import detect_entry_points

        for fn_name, ep in detect_entry_points(rel_path, tree).items():
            entry_points.append({
                "function": name_to_qualified.get(fn_name, fn_name),
                "short_name": fn_name,
                "file": rel_path,
                "line_start": line_by_func.get(fn_name, 0),
                "framework": ep.framework,
                "route": ep.route,
                "method": ep.method,
            })
    except Exception:
        pass

    return {"functions": functions, "calls": calls, "entry_points": entry_points}


def _resolve_callee(func_node, name_to_qualified):
    """Resolve a Call's func to a qualified name in the same file."""
    if isinstance(func_node, ast.Name):
        return name_to_qualified.get(func_node.id)
    if isinstance(func_node, ast.Attribute):
        if isinstance(func_node.value, ast.Name):
            base = func_node.value.id
            attr = func_node.attr
            if base in name_to_qualified:
                return f"{name_to_qualified[base]}.{attr}"
            return name_to_qualified.get(attr)
    return None


def find_enclosing_function(functions, file_path, line):
    """Return the function dict whose line range contains ``line``."""
    norm = file_path.replace("\\", "/")
    best = None
    for fn in functions:
        if fn["file"] != norm:
            continue
        if fn["line_start"] <= line <= fn["line_end"]:
            if best is None or fn["line_start"] > best["line_start"]:
                best = fn
    return best

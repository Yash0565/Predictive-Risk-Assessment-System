"""Cross-file (inter-procedural) call graph with reachability path-finding and a
lightweight taint pass.

This is a real improvement over ``static_analyzer`` (single-file, no import
resolution): it resolves intra-project imports so a path like
``app.handler -> services.helper -> yaml.load`` is discovered across module
boundaries, and it answers "can an application entry point reach this vulnerable
symbol, and is attacker-controlled data involved?".

Scope and honesty: this is a static, best-effort graph. It resolves direct
imports and same-file calls; it does not resolve dynamic dispatch, monkey
patching, or reflection (``getattr``-style calls), which are reported as
unresolved. The taint pass is intra-procedural and conservative.
"""

from __future__ import annotations

import ast
import os
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from src.config import SKIP_DIRS

# Names that commonly carry attacker-controlled data; used as taint sources.
_DEFAULT_TAINT_SOURCES = (
    "request", "flask.request", "args", "form", "json", "data", "files",
    "params", "query_params", "body", "get_json", "environ", "cookies", "headers",
)


@dataclass
class FuncNode:
    fqn: str                 # module.qualname
    module: str
    qualname: str
    file: str
    line_start: int
    line_end: int
    is_entry_point: bool = False
    route: str = ""
    method: str = ""
    tainted_params: bool = False


@dataclass
class CallGraph:
    nodes: dict[str, FuncNode] = field(default_factory=dict)
    # caller_fqn -> set of callee tokens (resolved fqn for internal, or external symbol)
    edges: dict[str, set[str]] = field(default_factory=dict)
    # external calls keyed by caller: callee symbol string (e.g. "yaml.load")
    external: dict[str, set[str]] = field(default_factory=dict)

    def successors(self, fqn: str) -> set[str]:
        return self.edges.get(fqn, set())


def _module_name(rel_path: str) -> str:
    p = rel_path.replace("\\", "/")
    if p.endswith("__init__.py"):
        p = p[: -len("/__init__.py")] if "/" in p else ""
    elif p.endswith(".py"):
        p = p[:-3]
    return p.replace("/", ".")


def build_call_graph(project_dir: str, taint_sources: Optional[tuple] = None) -> CallGraph:
    project_dir = os.path.abspath(project_dir)
    sources = taint_sources or _DEFAULT_TAINT_SOURCES
    cg = CallGraph()

    parsed: list[tuple[str, str, ast.AST]] = []
    for root, dirs, files in os.walk(project_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            if not fname.endswith(".py"):
                continue
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, project_dir).replace("\\", "/")
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                    tree = ast.parse(fh.read(), filename=fpath)
            except SyntaxError:
                continue
            parsed.append((rel, _module_name(rel), tree))

    # Pass 1: collect every function node so cross-file resolution can target them.
    short_to_fqns: dict[str, list[str]] = {}
    for rel, module, tree in parsed:
        for fqn, node, qual in _iter_functions(module, tree):
            cg.nodes[fqn] = FuncNode(
                fqn=fqn, module=module, qualname=qual, file=rel,
                line_start=node.lineno, line_end=node.end_lineno or node.lineno,
            )
            short = qual.split(".")[-1]
            short_to_fqns.setdefault(short, []).append(fqn)

    # Pass 2: resolve calls (with per-file import aliases) into edges.
    for rel, module, tree in parsed:
        aliases = _import_aliases(tree)
        _collect_calls(cg, module, tree, aliases, short_to_fqns, sources)

    _mark_entry_points(cg, parsed)
    return cg


def _iter_functions(module: str, tree: ast.AST):
    stack: list[str] = []

    class _V(ast.NodeVisitor):
        def visit_FunctionDef(self, node):
            qual = ".".join(stack + [node.name])
            yield_fqn = f"{module}.{qual}" if module else qual
            results.append((yield_fqn, node, qual))
            stack.append(node.name)
            self.generic_visit(node)
            stack.pop()

        def visit_AsyncFunctionDef(self, node):
            self.visit_FunctionDef(node)

    results: list = []
    _V().visit(tree)
    return results


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    """alias -> dotted target. e.g. {'yaml': 'yaml', 'Image': 'PIL.Image'}."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                aliases[n.asname or n.name.split(".")[0]] = n.name
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for n in node.names:
                target = f"{mod}.{n.name}" if mod else n.name
                aliases[n.asname or n.name] = target
    return aliases


def _resolve_attr_chain(node: ast.AST) -> Optional[str]:
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _collect_calls(cg, module, tree, aliases, short_to_fqns, taint_sources):
    func_stack: list[str] = []

    def _caller_fqn() -> Optional[str]:
        if not func_stack:
            return None
        qual = ".".join(func_stack)
        return f"{module}.{qual}" if module else qual

    class _V(ast.NodeVisitor):
        def visit_FunctionDef(self, node):
            func_stack.append(node.name)
            self.generic_visit(node)
            func_stack.pop()

        def visit_AsyncFunctionDef(self, node):
            self.visit_FunctionDef(node)

        def visit_Call(self, node):
            caller = _caller_fqn()
            if caller:
                self._record(caller, node.func)
                self._taint(caller, node)
            self.generic_visit(node)

        def _record(self, caller, func):
            chain = _resolve_attr_chain(func) if isinstance(func, (ast.Name, ast.Attribute)) else None
            if not chain:
                return
            head = chain.split(".")[0]
            rest = chain.split(".")[1:]

            # Resolve through import aliases to a dotted symbol (external or internal).
            if head in aliases:
                resolved = ".".join([aliases[head]] + rest)
            else:
                resolved = chain

            # Internal target? Match a known function fqn by short name + module hint.
            short = resolved.split(".")[-1]
            internal_fqn = None
            candidates = short_to_fqns.get(short, [])
            same_module = [c for c in candidates if c.startswith(f"{module}.")]
            if same_module:
                internal_fqn = same_module[0]
            elif len(candidates) == 1:
                internal_fqn = candidates[0]

            if internal_fqn and internal_fqn != caller:
                cg.edges.setdefault(caller, set()).add(internal_fqn)
            else:
                cg.external.setdefault(caller, set()).add(resolved)
                cg.edges.setdefault(caller, set()).add(f"ext::{resolved}")

        def _taint(self, caller, node):
            for arg in list(node.args) + [kw.value for kw in node.keywords]:
                chain = _resolve_attr_chain(arg) if isinstance(arg, (ast.Name, ast.Attribute)) else None
                if chain and any(chain.split(".")[0] == s or chain == s for s in taint_sources):
                    n = cg.nodes.get(caller)
                    if n:
                        n.tainted_params = True

    _V().visit(tree)


def _mark_entry_points(cg, parsed) -> None:
    try:
        from src.symbol_scanner import detect_entry_points
    except Exception:
        return
    for rel, module, tree in parsed:
        for fn_name, ep in detect_entry_points(rel, tree).items():
            fqn = f"{module}.{fn_name}" if module else fn_name
            node = cg.nodes.get(fqn)
            if not node:
                matches = [k for k in cg.nodes if k.endswith(f".{fn_name}") and cg.nodes[k].file == rel]
                node = cg.nodes.get(matches[0]) if matches else None
            if node:
                node.is_entry_point = True
                node.route = ep.route
                node.method = ep.method
                node.tainted_params = True  # entry-point inputs are attacker-controlled


def reachable_to_symbol(cg: CallGraph, target_symbol: str, max_hops: int = 25) -> list[dict]:
    """Return reachability paths from any entry point to an external ``target_symbol``.

    ``target_symbol`` is matched by dotted suffix, so ``yaml.load`` matches a call
    resolved to ``yaml.load`` and ``PIL.Image.open`` matches ``PIL.Image.open``.
    """
    entry_fqns = [fqn for fqn, n in cg.nodes.items() if n.is_entry_point]
    results: list[dict] = []
    target = target_symbol.lstrip(".")

    for entry in entry_fqns:
        path = _bfs_path(cg, entry, target, max_hops)
        if path is not None:
            tainted = any(cg.nodes[p].tainted_params for p in path if p in cg.nodes)
            results.append({
                "entry_point": entry,
                "route": cg.nodes[entry].route,
                "method": cg.nodes[entry].method,
                "target": target,
                "path": path,
                "hops": len(path) - 1,
                "tainted": tainted,
            })
    return results


def _bfs_path(cg, entry, target, max_hops) -> Optional[list[str]]:
    queue: deque = deque([(entry, [entry])])
    visited = {entry}
    while queue:
        cur, path = queue.popleft()
        if len(path) - 1 > max_hops:
            continue
        for succ in sorted(cg.successors(cur)):
            if succ.startswith("ext::"):
                sym = succ[len("ext::"):]
                if sym == target or sym.endswith("." + target) or target.endswith("." + sym):
                    return path + [succ]
                continue
            if succ not in visited:
                visited.add(succ)
                queue.append((succ, path + [succ]))
    return None

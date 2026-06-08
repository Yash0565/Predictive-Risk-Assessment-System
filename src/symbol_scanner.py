"""AST-based scanner for references to patch-identified vulnerable symbols.

Bridges Patch Fetcher output with user code: finds imports, calls, and attribute
accesses that resolve to the same symbols fixed in security patches.
"""

from __future__ import annotations

import ast
import fnmatch
import json
import logging
import os
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

logger = logging.getLogger(__name__)

DEFAULT_IGNORE_PATTERNS = (
    "__pycache__",
    ".venv",
    "venv",
    ".git",
    "node_modules",
    ".mypy_cache",
    ".pytest_cache",
    "site-packages",
)

MAX_FILE_BYTES = 2 * 1024 * 1024

# Bounded LRU AST cache: abs_path -> (mtime_ns, tree, source_lines).
# Capped so long-running / monorepo scans do not grow memory without limit.
_AST_CACHE_MAX = 2048
_AST_CACHE: "OrderedDict[str, tuple[int, ast.AST, list[str]]]" = OrderedDict()


def _ast_cache_get(abs_path: str, mtime: int) -> Optional[tuple[ast.AST, list[str]]]:
    cached = _AST_CACHE.get(abs_path)
    if cached and cached[0] == mtime:
        _AST_CACHE.move_to_end(abs_path)
        return cached[1], cached[2]
    return None


def _ast_cache_put(abs_path: str, mtime: int, tree: ast.AST, lines: list[str]) -> None:
    _AST_CACHE[abs_path] = (mtime, tree, lines)
    _AST_CACHE.move_to_end(abs_path)
    while len(_AST_CACHE) > _AST_CACHE_MAX:
        _AST_CACHE.popitem(last=False)


@dataclass(frozen=True)
class SymbolTarget:
    """One vulnerable symbol from the Patch Fetcher."""

    cve_id: str
    package: str
    fully_qualified_name: str
    short_name: str
    kind: str
    change_classification: str


@dataclass
class Binding:
    """Maps a local name to a resolved fully qualified symbol path."""

    fqn: str
    import_stmt: str
    confidence: str  # HIGH | MEDIUM | LOW
    is_module: bool = False
    note: Optional[str] = None


@dataclass
class EntryPointInfo:
    """Framework entry point attached to a function."""

    framework: str
    route: Optional[str] = None
    method: Optional[str] = None


@dataclass
class SymbolIndex:
    """Fast lookup structures built from Patch Fetcher input."""

    by_short: dict[str, list[SymbolTarget]] = field(default_factory=dict)
    by_fqn: dict[str, list[SymbolTarget]] = field(default_factory=dict)
    cve_packages: dict[str, str] = field(default_factory=dict)
    cve_symbols: dict[str, list[SymbolTarget]] = field(default_factory=dict)
    cve_primary_fqn: dict[str, str] = field(default_factory=dict)
    cve_classification: dict[str, str] = field(default_factory=dict)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _source_line(lines: list[str], lineno: int) -> str:
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1].strip()
    return ""


def _col_offset(node: ast.AST) -> int:
    return getattr(node, "col_offset", 0) or 0


def build_symbol_index(vulnerable_symbols_by_cve: dict[str, Any]) -> SymbolIndex:
    """Pre-process vulnerable symbols into lookup-friendly structures.

    Returns:
        SymbolIndex with ``by_short``, ``by_fqn``, and per-CVE metadata.
    """
    index = SymbolIndex()
    for cve_id, record in sorted(vulnerable_symbols_by_cve.items()):
        cve_id = cve_id.upper()
        package = (record.get("package") or "").lower()
        symbols = record.get("vulnerable_symbols") or []
        if not symbols and "vulnerable_symbol" in record:
            symbols = [record]

        targets: list[SymbolTarget] = []
        for sym in symbols:
            fqn = sym.get("fully_qualified_name") or sym.get("vulnerable_symbol", "")
            short = sym.get("short_name") or (fqn.split(".")[-1] if fqn else "")
            if not fqn or not short:
                continue
            if short.endswith((".c", ".h")):
                continue
            target = SymbolTarget(
                cve_id=cve_id,
                package=package,
                fully_qualified_name=fqn,
                short_name=short,
                kind=sym.get("kind", "function"),
                change_classification=sym.get("change_classification", "INTERNAL_CHANGE"),
            )
            targets.append(target)
            index.by_short.setdefault(short, []).append(target)
            index.by_fqn.setdefault(fqn, []).append(target)

        if not targets:
            continue
        index.cve_packages[cve_id] = package
        index.cve_symbols[cve_id] = targets
        index.cve_primary_fqn[cve_id] = targets[0].fully_qualified_name
        index.cve_classification[cve_id] = targets[0].change_classification

    return index


def _match_targets(resolved_fqn: str, index: SymbolIndex) -> list[SymbolTarget]:
    """Return all CVE targets matching a resolved FQN."""
    if not resolved_fqn:
        return []
    exact = index.by_fqn.get(resolved_fqn, [])
    if exact:
        return exact

    matches: list[SymbolTarget] = []
    short = resolved_fqn.split(".")[-1]
    for target in index.by_short.get(short, []):
        if target.fully_qualified_name == resolved_fqn:
            matches.append(target)
            continue
        if target.short_name != short:
            continue
        pkg = target.package
        if pkg and pkg in resolved_fqn.lower():
            matches.append(target)
            continue
        if resolved_fqn.endswith("." + target.short_name):
            matches.append(target)
    return matches


def _absolute_module(
    module: Optional[str],
    level: int,
    package: Optional[str],
) -> Optional[str]:
    """Resolve ImportFrom module string (PEP 328 relative imports)."""
    if level == 0:
        return module
    if not package:
        return module
    parts = package.split(".")
    if level > len(parts):
        base: list[str] = []
    else:
        base = parts[: len(parts) - level + 1]
    if module:
        return ".".join(base + [module]) if base else module
    return ".".join(base) if base else package


def _infer_package(rel_path: str, project_root: str) -> Optional[str]:
    """Infer dotted package name from file path under project root."""
    rel = rel_path.replace("\\", "/")
    parts = rel.split("/")
    if len(parts) < 2:
        return None
    if parts[-1] == "__init__.py":
        return ".".join(parts[:-1])[:-0] or None
    if parts[-1].endswith(".py"):
        return ".".join(parts[:-1] + [parts[-1][:-3]])
    return None


def _literal_str(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _literal_method(node: ast.AST) -> Optional[str]:
    val = _literal_str(node)
    if val:
        return val.upper()
    if isinstance(node, ast.List):
        for elt in node.elts:
            s = _literal_str(elt)
            if s:
                return s.upper()
    return None


def detect_entry_points(file_path: str, tree: ast.AST) -> dict[str, EntryPointInfo]:
    """Return entry-point metadata keyed by function name in this file."""
    entry_points: dict[str, EntryPointInfo] = {}
    rel = file_path.replace("\\", "/")

    class Visitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._handle_function(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._handle_function(node)

        def _handle_function(self, node: ast.AST) -> None:
            for dec in getattr(node, "decorator_list", []):
                info = _entry_point_from_decorator(dec)
                if info:
                    entry_points[node.name] = info
                    break
            self.generic_visit(node)

    Visitor().visit(tree)

    if rel.endswith("urls.py"):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                is_path = (
                    (isinstance(func, ast.Name) and func.id == "path")
                    or (isinstance(func, ast.Attribute) and func.attr == "path")
                )
                if is_path:
                    route = _literal_str(node.args[0]) if node.args else None
                    if len(node.args) > 1:
                        arg1 = node.args[1]
                        view_name: Optional[str] = None
                        if isinstance(arg1, ast.Attribute):
                            view_name = arg1.attr
                        elif isinstance(arg1, ast.Name):
                            view_name = arg1.id
                        if view_name:
                            entry_points.setdefault(
                                view_name,
                                EntryPointInfo(framework="django", route=route, method="GET"),
                            )
    return entry_points


def _entry_point_from_decorator(dec: ast.AST) -> Optional[EntryPointInfo]:
    """Parse Flask/FastAPI/Celery-style route decorators."""
    if not isinstance(dec, ast.Call):
        if isinstance(dec, ast.Attribute) and dec.attr in ("task", "shared_task"):
            return EntryPointInfo(framework="celery")
        return None

    func = dec.func
    route: Optional[str] = None
    method: Optional[str] = None
    framework: Optional[str] = None

    if isinstance(func, ast.Attribute):
        attr = func.attr
        if attr == "route":
            framework = "flask"
            if dec.args:
                route = _literal_str(dec.args[0])
            method = "GET"
            for kw in dec.keywords:
                if kw.arg == "methods" and kw.value:
                    method = _literal_method(kw.value) or method
        elif attr in ("get", "post", "put", "delete", "patch", "head", "options"):
            framework = "fastapi"
            route = _literal_str(dec.args[0]) if dec.args else None
            method = attr.upper()
        elif attr in ("task", "shared_task"):
            return EntryPointInfo(framework="celery")
        elif attr in ("command", "group"):
            return EntryPointInfo(framework="click")
    elif isinstance(func, ast.Name) and func.id in ("route",):
        framework = "flask"
        route = _literal_str(dec.args[0]) if dec.args else None
        method = "GET"

    if framework:
        return EntryPointInfo(framework=framework, route=route, method=method)
    return None


class _Scope:
    """Lexical scope for import bindings."""

    def __init__(self, parent: Optional[_Scope] = None) -> None:
        self.parent = parent
        self.bindings: dict[str, Binding] = {}
        self.star_modules: list[str] = []

    def get(self, name: str) -> Optional[Binding]:
        if name in self.bindings:
            return self.bindings[name]
        if self.parent:
            return self.parent.get(name)
        return None

    def set(self, name: str, binding: Binding) -> None:
        self.bindings[name] = binding

    def child(self) -> _Scope:
        return _Scope(parent=self)

    def iter_star_modules(self) -> Iterator[str]:
        scope: Optional[_Scope] = self
        while scope:
            yield from scope.star_modules
            scope = scope.parent


class _FileAnalyzer:
    """Single-pass AST visitor for one Python file."""

    def __init__(
        self,
        rel_path: str,
        source: str,
        index: SymbolIndex,
        package: Optional[str],
        tree: ast.AST,
    ) -> None:
        self.rel_path = rel_path.replace("\\", "/")
        self.lines = source.splitlines()
        self.index = index
        self.package = package
        self.findings: list[dict[str, Any]] = []
        self.scope = _Scope()
        self.func_stack: list[str] = []
        # Reuse the already-parsed tree (no second ast.parse of the same source).
        self.entry_points = detect_entry_points(rel_path, tree)

    def analyze(self, tree: ast.AST) -> list[dict[str, Any]]:
        self._visit_scope(tree, self.scope)
        return self.findings

    def _visit_scope(self, node: ast.AST, scope: _Scope) -> None:
        if isinstance(node, ast.Module):
            for child in node.body:
                self._visit_stmt(child, scope)
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._visit_function(node, scope)
            return

    def _visit_function(self, node: ast.AST, parent: _Scope) -> None:
        name = getattr(node, "name", "")
        self.func_stack.append(name)
        scope = parent.child()
        for child in node.body:
            self._visit_stmt(child, scope)
        self.func_stack.pop()

    def _visit_stmt(self, stmt: ast.AST, scope: _Scope) -> None:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._visit_function(stmt, scope)
            return
        if isinstance(stmt, ast.Import):
            self._handle_import(stmt, scope)
        elif isinstance(stmt, ast.ImportFrom):
            self._handle_import_from(stmt, scope)
        elif isinstance(stmt, ast.Try):
            for s in stmt.body + stmt.handlers + stmt.orelse + stmt.finalbody:
                self._visit_stmt(s, scope)
        elif isinstance(stmt, ast.If):
            for s in stmt.body + stmt.orelse:
                self._visit_stmt(s, scope)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            for s in stmt.body:
                self._visit_stmt(s, scope)
        else:
            self._visit_node(stmt, scope)

    def _handle_import(self, node: ast.Import, scope: _Scope) -> None:
        for alias in node.names:
            name = alias.asname or alias.name.split(".")[0]
            fqn = alias.name
            is_module = True
            binding = Binding(
                fqn=fqn,
                import_stmt=f"import {alias.name}" + (f" as {alias.asname}" if alias.asname else ""),
                confidence="HIGH",
                is_module=is_module,
            )
            scope.set(name, binding)
            self._record_import(node, name, binding)

    def _handle_import_from(self, node: ast.ImportFrom, scope: _Scope) -> None:
        module = _absolute_module(node.module, node.level or 0, self.package)
        import_prefix = f"from {module or ''} import"
        for alias in node.names:
            if alias.name == "*":
                if module:
                    scope.star_modules.append(module)
                continue
            local = alias.asname or alias.name
            fqn = f"{module}.{alias.name}" if module else alias.name
            stmt = f"{import_prefix} {alias.name}"
            if alias.asname:
                stmt += f" as {alias.asname}"
            binding = Binding(
                fqn=fqn,
                import_stmt=stmt.strip(),
                confidence="HIGH",
                is_module=False,
            )
            scope.set(local, binding)
            self._record_import(node, local, binding)

    def _record_import(self, node: ast.AST, local: str, binding: Binding) -> None:
        targets = _match_targets(binding.fqn, self.index)
        if not targets:
            return
        for target in targets:
            self.findings.append({
                "target": target,
                "matched_fqn": target.fully_qualified_name,
                "kind": "import",
                "file": self.rel_path,
                "line": node.lineno,
                "col": _col_offset(node),
                "source": binding.import_stmt,
                "enclosing_function": self.func_stack[-1] if self.func_stack else None,
                "in_entry_point": False,
                "import_chain": binding.fqn,
                "confidence": binding.confidence,
            })

    def _visit_node(self, node: ast.AST, scope: _Scope) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.Call):
                self._handle_call(child, scope)
            elif isinstance(child, ast.Attribute):
                self._handle_attribute(child, scope)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            else:
                self._visit_node(child, scope)

    def _resolve_expr(self, node: ast.AST, scope: _Scope) -> tuple[Optional[str], str, str]:
        """Return (fqn, confidence, import_chain_description)."""
        if isinstance(node, ast.Name):
            binding = scope.get(node.id)
            if binding:
                chain = f"{node.id} ({binding.import_stmt})"
                return binding.fqn, binding.confidence, chain
            for mod in scope.iter_star_modules():
                fqn = f"{mod}.{node.id}"
                return fqn, "MEDIUM", f"{node.id} (from {mod} import *)"
            return None, "LOW", node.id

        if isinstance(node, ast.Attribute):
            base_fqn, conf, chain = self._resolve_expr(node.value, scope)
            attr = node.attr
            if base_fqn:
                return f"{base_fqn}.{attr}", conf, f"{chain}.{attr}"
            return None, "LOW", f"?.{attr}"

        return None, "LOW", "?"

    def _handle_call(self, node: ast.Call, scope: _Scope) -> None:
        fqn, conf, chain = self._resolve_expr(node.func, scope)
        if not fqn:
            return
        targets = _match_targets(fqn, self.index)
        if not targets:
            return
        enclosing = self.func_stack[-1] if self.func_stack else None
        in_ep = enclosing in self.entry_points if enclosing else False
        ref: dict[str, Any] = {
            "target": targets[0],
            "matched_fqn": targets[0].fully_qualified_name,
            "kind": "call",
            "file": self.rel_path,
            "line": node.lineno,
            "col": _col_offset(node.func),
            "source": _source_line(self.lines, node.lineno),
            "enclosing_function": enclosing,
            "in_entry_point": in_ep,
            "import_chain": chain,
            "confidence": conf,
        }
        if in_ep and enclosing:
            ep = self.entry_points[enclosing]
            ref["entry_point_info"] = {
                "framework": ep.framework,
                "route": ep.route,
                "method": ep.method,
            }
        self.findings.append(ref)
        self._visit_node(node, scope)

    def _handle_attribute(self, node: ast.Attribute, scope: _Scope) -> None:
        fqn, conf, chain = self._resolve_expr(node, scope)
        if not fqn:
            return
        targets = _match_targets(fqn, self.index)
        if not targets:
            return
        if conf == "HIGH":
            return
        self.findings.append({
            "target": targets[0],
            "matched_fqn": targets[0].fully_qualified_name,
            "kind": "attribute",
            "file": self.rel_path,
            "line": node.lineno,
            "col": _col_offset(node),
            "source": _source_line(self.lines, node.lineno),
            "enclosing_function": self.func_stack[-1] if self.func_stack else None,
            "in_entry_point": False,
            "import_chain": chain,
            "confidence": "MEDIUM",
        })


def scan_file(
    file_path: str,
    symbol_index: SymbolIndex,
    *,
    project_root: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Scan a single file for references to vulnerable symbols.

    Returns raw finding dicts (internal shape with ``target`` key).
    """
    path = Path(file_path)
    if project_root:
        rel = path.resolve().relative_to(Path(project_root).resolve()).as_posix()
    else:
        rel = path.name

    try:
        data = path.read_bytes()
    except OSError as exc:
        logger.warning("Cannot read %s: %s", file_path, exc)
        return []

    if len(data) > MAX_FILE_BYTES:
        logger.warning("Skipping large file %s", file_path)
        return []

    if b"\x00" in data[:8192]:
        logger.warning("Skipping binary file %s", file_path)
        return []

    try:
        source = data.decode("utf-8")
    except UnicodeDecodeError:
        logger.warning("Skipping non-UTF-8 file %s", file_path)
        return []

    package = _infer_package(rel, project_root or str(path.parent))
    abs_path = str(path.resolve())
    mtime = path.stat().st_mtime_ns

    cached = _ast_cache_get(abs_path, mtime)
    if cached is not None:
        tree, lines = cached
    else:
        try:
            tree = ast.parse(source, filename=abs_path)
        except SyntaxError as exc:
            logger.warning("Syntax error in %s: %s", rel, exc)
            return []
        lines = source.splitlines()
        _ast_cache_put(abs_path, mtime, tree, lines)

    analyzer = _FileAnalyzer(rel, source, symbol_index, package, tree)
    return analyzer.analyze(tree)


def _should_ignore(path: str, ignore_patterns: tuple[str, ...]) -> bool:
    norm = path.replace("\\", "/")
    parts = norm.split("/")
    for part in parts:
        for pat in ignore_patterns:
            if fnmatch.fnmatch(part, pat):
                return True
    return False


def _iter_py_files(target_dir: str, ignore_patterns: tuple[str, ...]) -> Iterator[str]:
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [
            d for d in dirs
            if not _should_ignore(os.path.join(root, d), ignore_patterns)
        ]
        for fname in files:
            if not fname.endswith(".py"):
                continue
            fpath = os.path.join(root, fname)
            if _should_ignore(fpath, ignore_patterns):
                continue
            yield fpath


def _aggregate_findings(
    raw: list[dict[str, Any]],
    index: SymbolIndex,
) -> dict[str, dict[str, Any]]:  # noqa: C901 — aggregation is intentionally explicit
    """Group raw findings by CVE and build output records."""
    by_cve: dict[str, list[dict[str, Any]]] = {cve: [] for cve in index.cve_symbols}

    for item in raw:
        target: SymbolTarget = item["target"]
        cve = target.cve_id
        if cve not in by_cve:
            by_cve[cve] = []
        ref = {
            "kind": item["kind"],
            "file": item["file"],
            "line": item["line"],
            "col": item["col"],
            "source": item["source"],
            "enclosing_function": item.get("enclosing_function"),
            "in_entry_point": item.get("in_entry_point", False),
            "import_chain": item.get("import_chain", ""),
            "confidence": item.get("confidence", "LOW"),
        }
        if item.get("entry_point_info"):
            ref["entry_point_info"] = item["entry_point_info"]
        if item.get("note"):
            ref["note"] = item["note"]
        by_cve.setdefault(cve, []).append(ref)

    findings_by_cve: dict[str, dict[str, Any]] = {}
    for cve_id in sorted(index.cve_symbols.keys()):
        refs = sorted(
            by_cve.get(cve_id, []),
            key=lambda r: (r["file"], r["line"], r["col"], r["kind"]),
        )
        targets = index.cve_symbols[cve_id]
        primary = index.cve_primary_fqn[cve_id]
        for ref in refs:
            pass
        confidences = [r.get("confidence", "LOW") for r in refs if r["kind"] != "import"]
        if not confidences:
            confidences = [r.get("confidence", "LOW") for r in refs]
        overall_conf = "HIGH"
        if refs and all(c == "LOW" for c in confidences):
            overall_conf = "LOW"
        elif refs and any(c == "MEDIUM" for c in confidences):
            overall_conf = "MEDIUM" if not any(c == "HIGH" for c in confidences) else "HIGH"

        call_fqns = [
            item.get("matched_fqn", item["target"].fully_qualified_name)
            for item in raw
            if item.get("target") and item["target"].cve_id == cve_id and item.get("kind") == "call"
        ]
        best_fqn = call_fqns[0] if call_fqns else primary

        findings_by_cve[cve_id] = {
            "package": index.cve_packages.get(cve_id, ""),
            "vulnerable_symbol": best_fqn,
            "change_classification": index.cve_classification.get(cve_id, "INTERNAL_CHANGE"),
            "is_reachable": len(refs) > 0,
            "confidence": overall_conf if refs else "HIGH",
            "reference_count": len(refs),
            "references": refs,
        }
    return findings_by_cve


def scan_symbols(
    target_dir: str,
    vulnerable_symbols_by_cve: dict[str, Any],
    ignore_patterns: Optional[list[str]] = None,
    *,
    cache_dir: Optional[str] = None,
) -> dict[str, Any]:
    """Scan target_dir for all references to vulnerable symbols.

    Args:
        target_dir: Path to the user's project root.
        vulnerable_symbols_by_cve: Dict keyed by CVE ID (Patch Fetcher output).
        ignore_patterns: Glob patterns for directories/files to skip.

    Returns:
        Full scan result matching the documented JSON schema.
    """
    start = time.perf_counter()
    target_dir = os.path.abspath(target_dir)
    patterns = tuple(ignore_patterns or DEFAULT_IGNORE_PATTERNS)

    index = build_symbol_index(vulnerable_symbols_by_cve)
    files_scanned = 0
    files_parsed_ok = 0
    files_failed = 0
    cache_hits = 0
    all_raw: list[dict[str, Any]] = []

    scan_cache = None
    if cache_dir:
        try:
            from src.scan_cache import ScanCache
            scan_cache = ScanCache(cache_dir)
        except Exception:
            scan_cache = None

    def _scan_one(fpath: str) -> list[dict[str, Any]]:
        return scan_file(fpath, index, project_root=target_dir) or []

    if scan_cache:
        paths = list(_iter_py_files(target_dir, patterns))
        files_scanned = len(paths)
        report = scan_cache.scan_incremental(
            paths, "symbol_scanner", "2.0.0", _scan_one,
        )
        cache_hits = report.get("stats", {}).get("cache_hits", 0)
        for findings in report.get("results", {}).values():
            if findings is not None:
                files_parsed_ok += 1
                all_raw.extend(findings)
    else:
        for fpath in _iter_py_files(target_dir, patterns):
            files_scanned += 1
            try:
                findings = _scan_one(fpath)
                if findings is not None:
                    files_parsed_ok += 1
                    all_raw.extend(findings)
            except Exception as exc:
                files_failed += 1
                logger.warning("Failed to scan %s: %s", fpath, exc)

    findings_by_cve = _aggregate_findings(all_raw, index)
    reachable = sorted([c for c, v in findings_by_cve.items() if v["is_reachable"]])
    unreachable = sorted([c for c, v in findings_by_cve.items() if not v["is_reachable"]])
    total_cves = len(findings_by_cve)
    noise_pct = round((len(unreachable) / total_cves) * 100, 1) if total_cves else 0.0

    duration_ms = int((time.perf_counter() - start) * 1000)
    return {
        "scanned_at": _utc_now_iso(),
        "target_dir": target_dir,
        "stats": {
            "files_scanned": files_scanned,
            "files_parsed_ok": files_parsed_ok,
            "files_failed": files_failed,
            "cache_hits": cache_hits,
            "total_findings": sum(v["reference_count"] for v in findings_by_cve.values()),
            "duration_ms": duration_ms,
        },
        "findings_by_cve": findings_by_cve,
        "summary": {
            "reachable_cves": reachable,
            "unreachable_cves": unreachable,
            "noise_reduction_percent": noise_pct,
        },
    }


def save_findings(findings: dict[str, Any], output_path: str) -> None:
    """Persist scan results to JSON (sorted keys for stable diffs)."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2, sort_keys=True)
        fh.write("\n")


def load_patches_from_cache(cache_dir: Optional[str] = None) -> dict[str, Any]:
    """Load all Patch Fetcher JSON files into vulnerable_symbols_by_cve."""
    base = Path(cache_dir or Path(__file__).resolve().parent.parent / "data" / "patches")
    out: dict[str, Any] = {}
    if not base.is_dir():
        return out
    for path in sorted(base.glob("CVE-*.json")):
        try:
            with path.open(encoding="utf-8") as fh:
                record = json.load(fh)
            cve_id = record.get("cve_id", path.stem).upper()
            out[cve_id] = record
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Skipping patch cache %s: %s", path, exc)
    return out

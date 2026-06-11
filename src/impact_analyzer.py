"""impact_analyzer.py
───────────────────
AST-based Python package interface diff engine.
"""
from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional, Any

logger = logging.getLogger("pre_upgrade_system")

@dataclass
class APIChange:
    change_type: str  # MODULE_REMOVED | CLASS_REMOVED | FUNCTION_REMOVED | METHOD_REMOVED | SIGNATURE_CHANGED
    module: str
    symbol: str       # fully qualified: module.ClassName.method_name
    old_signature: Optional[str]
    new_signature: Optional[str]
    description: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

class PackageASTVisitor(ast.NodeVisitor):
    def __init__(self, module_rel_path: str):
        self.module_rel_path = module_rel_path
        self.current_class: Optional[str] = None
        self.functions: dict[str, dict] = {}
        self.classes: dict[str, dict[str, dict]] = {}

    def visit_ClassDef(self, node: ast.ClassDef):
        # Ignore private classes (except if specifically referenced)
        if node.name.startswith("_"):
            return
            
        prev_class = self.current_class
        self.current_class = node.name
        self.classes[node.name] = {}
        
        # Walk class body
        self.generic_visit(node)
        
        self.current_class = prev_class

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Ignore private functions/methods (except __init__)
        if node.name.startswith("_") and node.name != "__init__":
            return
            
        sig = self._parse_arguments(node.args)
        
        if self.current_class:
            self.classes[self.current_class][node.name] = sig
        else:
            self.functions[node.name] = sig
            
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        # Treat async functions identically to standard functions
        if node.name.startswith("_") and node.name != "__init__":
            return
            
        sig = self._parse_arguments(node.args)
        
        if self.current_class:
            self.classes[self.current_class][node.name] = sig
        else:
            self.functions[node.name] = sig
            
        self.generic_visit(node)

    def _parse_arguments(self, args: ast.arguments) -> dict:
        # Positional arguments
        pos_args = [arg.arg for arg in args.args]
        
        # Positional-only args (Python 3.8+)
        posonly_args = [arg.arg for arg in getattr(args, "posonlyargs", [])]
        
        # Keyword-only args
        kwonly_args = [arg.arg for arg in args.kwonlyargs]
        
        # Determine defaults
        defaults_count = len(args.defaults)
        pos_defaults = {}
        # Defaults are applied from right to left to pos_args
        for i, val_node in enumerate(args.defaults):
            arg_idx = len(pos_args) - defaults_count + i
            if arg_idx >= 0:
                pos_defaults[pos_args[arg_idx]] = True

        kw_defaults = {}
        for arg, val in zip(kwonly_args, args.kw_defaults):
            if val is not None:
                kw_defaults[arg] = True

        return {
            "args": posonly_args + pos_args,
            "kwonly": kwonly_args,
            "pos_defaults": pos_defaults,
            "kw_defaults": kw_defaults,
            "has_varargs": args.vararg is not None,
            "has_kwargs": args.kwarg is not None,
        }

def build_api_map(source_dir: str) -> dict:
    """Walks all .py files in source_dir, uses PackageASTVisitor to record public API."""
    source_path = Path(source_dir).resolve()
    
    api_map = {
        "modules": [],
        "functions": {},
        "classes": {}
    }
    
    if not source_path.exists():
        logger.warning("Package directory %s does not exist for AST mapping.", source_dir)
        return api_map
        
    for path in source_path.rglob("*.py"):
        # Relativize path from source root
        try:
            rel_path = path.relative_to(source_path).as_posix().replace(".py", "")
        except ValueError:
            rel_path = path.name.replace(".py", "")
            
        # Ignore private sub-modules (except __init__)
        if any(part.startswith("_") and part != "__init__" for part in Path(rel_path).parts):
            continue
            
        # Convert path delimiters to dot notation for modules
        module_name = rel_path.replace("/", ".")
        # If ends in __init__, normalize it
        if module_name.endswith(".__init__"):
            module_name = module_name[:-9]
        if module_name == "__init__":
            module_name = source_path.name
            
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(path))
            visitor = PackageASTVisitor(module_name)
            visitor.visit(tree)
            
            api_map["modules"].append(module_name)
            api_map["functions"][module_name] = visitor.functions
            api_map["classes"][module_name] = visitor.classes
        except Exception as exc:
            logger.debug("Failed to parse module %s: %s", path, exc)
            
    return api_map

def _compare_signatures(old_sig: dict, new_sig: dict) -> tuple[bool, str]:
    """Helper to detect breaking signature changes (returns: changed, description)."""
    # 1. Check for removed positional arguments
    removed_pos_args = []
    for arg in old_sig["args"]:
        if arg not in new_sig["args"] and not new_sig["has_varargs"] and not new_sig["has_kwargs"]:
            removed_pos_args.append(arg)
            
    # 2. Check for removed keyword-only arguments
    removed_kw_args = []
    for kw in old_sig["kwonly"]:
        if kw not in new_sig["kwonly"] and not new_sig["has_kwargs"]:
            removed_kw_args.append(kw)

    # 3. Check for newly added required positional arguments (no defaults)
    added_required_pos = []
    for arg in new_sig["args"]:
        if arg not in old_sig["args"] and arg not in old_sig["kwonly"] and arg not in ("self", "cls"):
            if arg not in new_sig["pos_defaults"]:
                added_required_pos.append(arg)
                
    # 4. Check for newly added required keyword-only arguments (no defaults)
    added_required_kw = []
    for kw in new_sig["kwonly"]:
        if kw not in old_sig["args"] and kw not in old_sig["kwonly"]:
            if kw not in new_sig["kw_defaults"]:
                added_required_kw.append(kw)

    # 5. Check for removed **kwargs
    removed_kwargs_block = old_sig["has_kwargs"] and not new_sig["has_kwargs"]

    details = []
    if removed_pos_args:
        details.append(f"Removed positional arguments: {', '.join(removed_pos_args)}")
    if removed_kw_args:
        details.append(f"Removed keyword arguments: {', '.join(removed_kw_args)}")
    if added_required_pos:
        details.append(f"Added required positional arguments: {', '.join(added_required_pos)}")
    if added_required_kw:
        details.append(f"Added required keyword arguments: {', '.join(added_required_kw)}")
    if removed_kwargs_block:
        details.append("Removed variable keyword arguments (**kwargs)")

    if details:
        return True, "; ".join(details)
    return False, ""

def _format_sig_str(sig: dict) -> str:
    parts = []
    if sig["args"]:
        parts.append(f"args: {sig['args']}")
    if sig["kwonly"]:
        parts.append(f"kwonly: {sig['kwonly']}")
    if sig["has_varargs"]:
        parts.append("*args")
    if sig["has_kwargs"]:
        parts.append("**kwargs")
    return ", ".join(parts) if parts else "()"

def diff_packages(old_map: dict, new_map: dict) -> list[APIChange]:
    """Compares two PackageAPIMaps to identify breaking API changes."""
    changes: list[APIChange] = []
    
    # Track removed modules
    for old_mod in old_map["modules"]:
        if old_mod not in new_map["modules"]:
            changes.append(
                APIChange(
                    change_type="MODULE_REMOVED",
                    module=old_mod,
                    symbol=old_mod,
                    old_signature=None,
                    new_signature=None,
                    description=f"Module '{old_mod}' was completely removed.",
                )
            )
            continue
            
        # Check for removed classes
        old_classes = old_map["classes"].get(old_mod, {})
        new_classes = new_map["classes"].get(old_mod, {})
        
        for old_cls in old_classes:
            if old_cls not in new_classes:
                changes.append(
                    APIChange(
                        change_type="CLASS_REMOVED",
                        module=old_mod,
                        symbol=f"{old_mod}.{old_cls}",
                        old_signature=None,
                        new_signature=None,
                        description=f"Class '{old_cls}' was removed from module '{old_mod}'.",
                    )
                )
                continue
                
            # Check for removed class methods and signature changes
            old_methods = old_classes[old_cls]
            new_methods = new_classes[old_cls]
            
            for old_meth, old_sig in old_methods.items():
                if old_meth not in new_methods:
                    changes.append(
                        APIChange(
                            change_type="METHOD_REMOVED",
                            module=old_mod,
                            symbol=f"{old_mod}.{old_cls}.{old_meth}",
                            old_signature=_format_sig_str(old_sig),
                            new_signature=None,
                            description=f"Method '{old_meth}' of class '{old_cls}' was removed.",
                        )
                    )
                else:
                    new_sig = new_methods[old_meth]
                    sig_changed, details = _compare_signatures(old_sig, new_sig)
                    if sig_changed:
                        changes.append(
                            APIChange(
                                change_type="SIGNATURE_CHANGED",
                                module=old_mod,
                                symbol=f"{old_mod}.{old_cls}.{old_meth}",
                                old_signature=_format_sig_str(old_sig),
                                new_signature=_format_sig_str(new_sig),
                                description=details,
                            )
                        )
                        
        # Check for removed module-level functions and signature changes
        old_funcs = old_map["functions"].get(old_mod, {})
        new_funcs = new_map["functions"].get(old_mod, {})
        
        for old_fn, old_sig in old_funcs.items():
            if old_fn not in new_funcs:
                changes.append(
                    APIChange(
                        change_type="FUNCTION_REMOVED",
                        module=old_mod,
                        symbol=f"{old_mod}.{old_fn}",
                        old_signature=_format_sig_str(old_sig),
                        new_signature=None,
                        description=f"Function '{old_fn}' was removed from module '{old_mod}'.",
                    )
                )
            else:
                new_sig = new_funcs[old_fn]
                sig_changed, details = _compare_signatures(old_sig, new_sig)
                if sig_changed:
                    changes.append(
                        APIChange(
                            change_type="SIGNATURE_CHANGED",
                            module=old_mod,
                            symbol=f"{old_mod}.{old_fn}",
                            old_signature=_format_sig_str(old_sig),
                            new_signature=_format_sig_str(new_sig),
                            description=details,
                        )
                    )
                    
    return changes

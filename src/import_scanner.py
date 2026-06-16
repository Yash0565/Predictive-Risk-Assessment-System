"""import_scanner.py
──────────────────
Language-agnostic scanner to detect active dependency imports and usage.
Supports Python, JS/TS, Java, Go, Ruby, and generic config file matching.
"""
from __future__ import annotations

import os
import re
import logging
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

logger = logging.getLogger("pre_upgrade_system")

@dataclass
class PackageUsageResult:
    is_used: bool
    usage_count: int
    usages: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

def scan_package_usage(project_dir: str, package_name: str) -> PackageUsageResult:
    """Scans the project directory to check if package_name is actively imported or referenced.
    
    Checks code files (.py, .js, .ts, .java, .go, .rb) and common config files.
    """
    project_path = Path(project_dir).resolve()
    usages = []
    
    skip_dirs = {".git", "venv", ".venv", "node_modules", "dist", "build", ".risk-scan", "out", "reports"}
    config_files = {"package.json", "gemfile", "go.mod", "pom.xml", "build.gradle"}
    
    # Pre-compile regex patterns for each language
    pkg_esc = re.escape(package_name)
    
    patterns = {
        ".py": [
            re.compile(rf"^\s*import\s+.*\b{pkg_esc}\b", re.IGNORECASE),
            re.compile(rf"^\s*from\s+\b{pkg_esc}\b", re.IGNORECASE)
        ],
        ".js": [
            re.compile(rf"require\(['\"]{pkg_esc}(?:/.*)?['\"]\)", re.IGNORECASE),
            re.compile(rf"\bfrom\s+['\"]{pkg_esc}(?:/.*)?['\"]", re.IGNORECASE),
            re.compile(rf"\bimport\s+['\"]{pkg_esc}(?:/.*)?['\"]", re.IGNORECASE)
        ],
        ".ts": [
            re.compile(rf"require\(['\"]{pkg_esc}(?:/.*)?['\"]\)", re.IGNORECASE),
            re.compile(rf"\bfrom\s+['\"]{pkg_esc}(?:/.*)?['\"]", re.IGNORECASE),
            re.compile(rf"\bimport\s+['\"]{pkg_esc}(?:/.*)?['\"]", re.IGNORECASE)
        ],
        ".java": [
            re.compile(rf"^\s*import\s+.*\b{pkg_esc}\b", re.IGNORECASE)
        ],
        ".go": [
            re.compile(rf"[\"\'](?:.*/)?{pkg_esc}[\"\']")
        ],
        ".rb": [
            re.compile(rf"\brequire\s+['\"]{pkg_esc}['\"]", re.IGNORECASE),
            re.compile(rf"\bgem\s+['\"]{pkg_esc}['\"]", re.IGNORECASE)
        ]
    }

    # Configuration file scanner (fallback search)
    config_regex = re.compile(rf"\b{pkg_esc}\b", re.IGNORECASE)

    for root, dirs, files in os.walk(project_path):
        # Prune search directories in-place
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        
        for file in files:
            file_path = Path(root) / file
            
            # Relativize path for output readability
            try:
                rel_path = file_path.relative_to(project_path).as_posix()
            except ValueError:
                rel_path = file_path.name
                
            ext = file_path.suffix.lower()
            
            # Check code files matching language patterns
            if ext in patterns:
                try:
                    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
                    for idx, line in enumerate(lines):
                        for regex in patterns[ext]:
                            if regex.search(line):
                                usages.append({
                                    "file": rel_path,
                                    "line": idx + 1,
                                    "match_text": line.strip()
                                })
                                break # Stop checking other patterns for same line
                except Exception as exc:
                    logger.debug("Failed to read file %s: %s", file_path, exc)
                    
            # Check configuration files
            elif file.lower() in config_files:
                try:
                    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
                    for idx, line in enumerate(lines):
                        if config_regex.search(line):
                            usages.append({
                                    "file": rel_path,
                                    "line": idx + 1,
                                    "match_text": line.strip()
                            })
                except Exception as exc:
                    logger.debug("Failed to read config file %s: %s", file_path, exc)

    return PackageUsageResult(
        is_used=len(usages) > 0,
        usage_count=len(usages),
        usages=usages
    )

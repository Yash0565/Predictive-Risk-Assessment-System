from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import httpx
import yaml
from packaging.version import InvalidVersion, Version

from cve_scanner.config import get_settings


def _parse_failed_tests(output: str) -> list[str]:
    import re

    return re.findall(r"FAILED\s+([\w/.:]+)", output)


def _parse_semver(value: str) -> Version | None:
    try:
        return Version(value)
    except InvalidVersion:
        return None


async def get_breaking_changes(
    package_name: str,
    from_version: str,
    to_version: str,
    ecosystem: str = "npm",
) -> list[str]:
    if ecosystem == "npm":
        url = f"https://registry.npmjs.org/{package_name}"
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                response = await client.get(url)
                response.raise_for_status()
                data = response.json()
                version_info = data.get("versions", {}).get(to_version, {})
                deprecated_msg = version_info.get("deprecated", "")
                return [deprecated_msg] if deprecated_msg else []
            except (httpx.HTTPError, ValueError):
                return []

    if ecosystem == "pypi":
        url = f"https://pypi.org/pypi/{package_name}/{to_version}/json"
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                response = await client.get(url)
                response.raise_for_status()
                data = response.json()
                info = data.get("info", {})
                description = info.get("description", "")
                return [description] if description else []
            except (httpx.HTTPError, ValueError):
                return []

    return []


def build_api_compat_rules(package_name: str, to_version: str) -> list[dict]:
    settings = get_settings()
    db_path = Path(settings.BREAKING_CHANGES_DB)
    if not db_path.exists():
        return []

    db = yaml.safe_load(db_path.read_text(encoding="utf-8")) or {}
    pkg_data = db.get(package_name, {})
    target_version = _parse_semver(to_version)
    if target_version is None:
        return []

    rules: list[dict] = []
    for version, changes in pkg_data.items():
        version_obj = _parse_semver(version)
        if version_obj is None or target_version < version_obj:
            continue

        for removed_symbol in changes.get("removed", []):
            rules.append(
                {
                    "id": f"compat-{package_name}-{removed_symbol.replace('.', '-')}" ,
                    "pattern": removed_symbol,
                    "message": f"REMOVED in {package_name} {version}: `{removed_symbol}` no longer exists",
                    "languages": ["python", "javascript", "typescript"],
                    "severity": "ERROR",
                }
            )
        for rename in changes.get("renamed", []):
            rules.append(
                {
                    "id": f"compat-renamed-{package_name}-{rename['from'].replace('.', '-')}" ,
                    "pattern": rename["from"],
                    "message": (
                        f"RENAMED in {package_name} {version}: use `{rename['to']}` instead"
                    ),
                    "languages": ["python", "javascript", "typescript"],
                    "severity": "WARNING",
                }
            )

    return rules


async def run_tests_in_sandbox(tmpdir: str | None, repo_path: str, ecosystem: str) -> dict:
    repo = Path(repo_path)
    if ecosystem == "python":
        if not (repo / "pytest.ini").exists() and not (repo / "pyproject.toml").exists():
            return {"skipped": True, "reason": "No test runner detected"}
        if not tmpdir:
            return {"skipped": True, "reason": "No sandbox directory"}
        python_path = Path(tmpdir) / "env" / ("Scripts" if sys.platform.startswith("win") else "bin") / "python"
        cmd = [
            str(python_path),
            "-m",
            "pytest",
            repo_path,
            "--tb=short",
            "-q",
            "--no-header",
        ]
    elif ecosystem == "npm":
        if not (repo / "package.json").exists():
            return {"skipped": True, "reason": "No test runner detected"}
        cmd = ["npm", "test", "--prefix", repo_path]
    else:
        return {"skipped": True, "reason": "No test runner detected"}

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
    output = (stdout.decode(errors="ignore") + stderr.decode(errors="ignore"))

    return {
        "passed": proc.returncode == 0,
        "exit_code": proc.returncode,
        "output": output[-3000:],
        "failed_tests": _parse_failed_tests(output),
    }

"""Discover pinned Python dependencies from common project layouts."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from packaging.requirements import Requirement

from src.upgrade_simulator import _normalize_name, parse_requirements

logger = logging.getLogger(__name__)

try:
    import tomllib
except ImportError:  # Python < 3.11
    import tomli as tomllib  # type: ignore[no-redef]


class DependencyDiscoveryError(Exception):
    """Raised when no pinned dependencies can be read from the repository."""


def _toml_load(path: Path) -> dict[str, Any]:
    with path.open("rb") as fh:
        return tomllib.load(fh)


def _pins_from_requirement_strings(lines: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            req = Requirement(line)
        except Exception:
            logger.debug("Skipping unparsable dependency line: %s", line[:80])
            continue
        if not req.specifier:
            continue
        for spec in req.specifier:
            if spec.operator == "==":
                out[_normalize_name(req.name)] = str(spec.version)
                break
    return out


def _coerce_poetry_spec(name: str, raw: Any) -> str | None:
    if name.lower() == "python":
        return None
    if isinstance(raw, dict):
        ver = raw.get("version")
        if isinstance(ver, str):
            raw = ver
        else:
            return None
    if not isinstance(raw, str):
        return None
    spec = raw.strip().strip('"').strip("'")
    if not spec or spec == "*":
        return None
    if spec.startswith(("==", ">=", "<=", "~=", "!=", "<", ">", "@", "^")):
        if spec.startswith("^"):
            return None
        return f"{name}{spec}"
    return f"{name}=={spec}"


def _parse_pyproject_toml(path: Path) -> dict[str, str]:
    data = _toml_load(path)
    project = data.get("project") or {}
    deps = project.get("dependencies")
    if isinstance(deps, list) and deps:
        return _pins_from_requirement_strings([str(d) for d in deps])

    poetry = data.get("tool", {}).get("poetry", {})
    pdeps = poetry.get("dependencies")
    if isinstance(pdeps, dict):
        lines: list[str] = []
        for name, spec in pdeps.items():
            line = _coerce_poetry_spec(name, spec)
            if line:
                lines.append(line)
        if lines:
            return _pins_from_requirement_strings(lines)
    return {}


def _parse_pipfile(path: Path) -> dict[str, str]:
    data = _toml_load(path)
    packages = data.get("packages") or {}
    if not isinstance(packages, dict):
        return {}
    lines: list[str] = []
    for name, raw in packages.items():
        if name.lower() == "python":
            continue
        if isinstance(raw, str):
            spec = raw.strip()
            if spec.startswith("==") or spec.startswith(">="):
                lines.append(f"{name}{spec}")
            elif spec and spec != "*":
                lines.append(f"{name}=={spec}")
        elif isinstance(raw, dict):
            ver = raw.get("version")
            if isinstance(ver, str) and ver.strip():
                v = ver.strip()
                lines.append(f"{name}{v}" if v.startswith(("==", ">=", "<")) else f"{name}=={v}")
    return _pins_from_requirement_strings(lines)


def discover_dependency_pins(repo_path: str | Path) -> tuple[dict[str, str], str]:
    """Return ``({package_normalized: version}, source_label)`` for the first usable source.

    Resolution order:

    1. ``requirements.txt`` at repo root (``==`` pins only, same rules as ``parse_requirements``).
    2. ``pyproject.toml`` — ``[project].dependencies`` or ``[tool.poetry.dependencies]``.
    3. ``Pipfile`` — ``[packages]`` with pinned versions.

    Raises:
        DependencyDiscoveryError: if no pins could be extracted from any file.
    """
    repo = Path(repo_path).resolve()

    req_file = repo / "requirements.txt"
    if req_file.is_file():
        pins = parse_requirements(str(req_file))
        if pins:
            return pins, "requirements.txt"

    pyproject = repo / "pyproject.toml"
    if pyproject.is_file():
        try:
            pins = _parse_pyproject_toml(pyproject)
            if pins:
                return pins, "pyproject.toml"
        except Exception as exc:
            logger.warning("Could not parse pyproject.toml: %s", exc)

    pipfile = repo / "Pipfile"
    if pipfile.is_file():
        try:
            pins = _parse_pipfile(pipfile)
            if pins:
                return pins, "Pipfile"
        except Exception as exc:
            logger.warning("Could not parse Pipfile: %s", exc)

    tried = ", ".join(
        p.name
        for p in (req_file, pyproject, pipfile)
        if p.is_file()
    ) or "requirements.txt, pyproject.toml, Pipfile (none present)"

    raise DependencyDiscoveryError(
        f"No pinned dependencies found under {repo}. "
        f"Tried: {tried}. "
        "Add a requirements.txt with == pins, or [project].dependencies in pyproject.toml, "
        "or pinned [packages] in a Pipfile."
    )

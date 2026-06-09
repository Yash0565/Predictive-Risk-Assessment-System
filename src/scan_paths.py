"""Repo-scoped path resolution for Pipeline A.

Artifacts and inputs are anchored to ``--project-dir`` and ``--output-dir``
so scanning an external repository never accidentally reuses the assessment
tooling repo's Trivy output or ``services.yaml``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

TRIVY_INPUT_NAME = "enriched_trivy_output.json"
SERVICES_FILE_NAME = "services.yaml"
DEFAULT_OUTPUT_SUBDIR = ".risk-scan"


def default_output_dir(project_dir: str | Path) -> str:
    """Per-target artifact directory: ``<project>/.risk-scan``."""
    return str(Path(project_dir).resolve() / DEFAULT_OUTPUT_SUBDIR)


def resolve_existing_path(
    raw: str,
    *,
    project_dir: str | Path,
    output_dir: str | Path,
) -> Optional[Path]:
    """Locate an existing file; prefer project/output dirs over cwd."""
    project = Path(project_dir).resolve()
    output = Path(output_dir).resolve()
    candidate = Path(raw)

    if candidate.is_absolute() and candidate.is_file():
        return candidate

    for base in (output, project, Path.cwd()):
        resolved = (base / raw).resolve()
        if resolved.is_file():
            return resolved

    return None


def resolve_trivy_input(
    raw: Optional[str],
    *,
    project_dir: str | Path,
    output_dir: str | Path,
) -> str:
    """Return path to Trivy JSON for this target (existing or to be created).

    Default (``raw`` is None/empty): ``<output_dir>/enriched_trivy_output.json`` only.
    Explicit ``raw``: search output dir, project dir, then cwd.
    """
    output = Path(output_dir).resolve()
    name = raw.strip() if raw and raw.strip() else TRIVY_INPUT_NAME

    if raw and raw.strip():
        found = resolve_existing_path(name, project_dir=project_dir, output_dir=output_dir)
        if found:
            return str(found)

    if not raw or not raw.strip():
        default_path = output / TRIVY_INPUT_NAME
        if default_path.is_file():
            return str(default_path)
        return str(default_path)

    # Explicit path that does not exist yet — write under output_dir unless absolute.
    candidate = Path(name)
    if candidate.is_absolute():
        return str(candidate)
    return str(output / name)


def resolve_services_path(
    raw: Optional[str],
    *,
    project_dir: str | Path,
) -> Optional[str]:
    """Resolve optional services YAML for graph entry points.

    ``auto`` / empty / None: use ``<project_dir>/services.yaml`` when present,
    otherwise ``None`` (auto-discover Flask/Django/FastAPI routes).

    Explicit path: resolve under project dir first, then cwd.
    """
    project = Path(project_dir).resolve()
    token = (raw or "auto").strip()

    if token.lower() in ("auto", "none", "discover", ""):
        auto = project / SERVICES_FILE_NAME
        return str(auto) if auto.is_file() else None

    candidate = Path(token)
    if candidate.is_absolute() and candidate.is_file():
        return str(candidate)

    for base in (project, Path.cwd()):
        resolved = (base / token).resolve()
        if resolved.is_file():
            return str(resolved)

    return None

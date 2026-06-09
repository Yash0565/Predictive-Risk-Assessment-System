"""Tests for repo-scoped scan path resolution."""

from __future__ import annotations

from pathlib import Path

from src.scan_paths import (
    default_output_dir,
    resolve_services_path,
    resolve_trivy_input,
)


def test_default_output_dir_under_project(tmp_path) -> None:
    project = tmp_path / "my-app"
    project.mkdir()
    assert default_output_dir(project).endswith(".risk-scan")
    assert Path(default_output_dir(project)).parent == project.resolve()


def test_trivy_input_defaults_to_output_dir_not_cwd(tmp_path, monkeypatch) -> None:
    tool_root = tmp_path / "tool"
    project = tmp_path / "other-repo"
    output = project / ".risk-scan"
    stale = tool_root / "enriched_trivy_output.json"
    tool_root.mkdir()
    project.mkdir()
    output.mkdir()
    stale.write_text("[]", encoding="utf-8")
    monkeypatch.chdir(tool_root)

    resolved = resolve_trivy_input(
        None,
        project_dir=project,
        output_dir=output,
    )
    assert resolved == str(output / "enriched_trivy_output.json")
    assert resolved != str(stale)


def test_trivy_input_prefers_output_dir_over_cwd(tmp_path, monkeypatch) -> None:
    tool_root = tmp_path / "tool"
    project = tmp_path / "app"
    output = project / ".risk-scan"
    tool_root.mkdir()
    project.mkdir()
    output.mkdir()
    (tool_root / "enriched_trivy_output.json").write_text("[]", encoding="utf-8")
    target_file = output / "enriched_trivy_output.json"
    target_file.write_text('[{"cve":"CVE-1"}]', encoding="utf-8")
    monkeypatch.chdir(tool_root)

    resolved = resolve_trivy_input(
        "enriched_trivy_output.json",
        project_dir=project,
        output_dir=output,
    )
    assert resolved == str(target_file)


def test_services_auto_uses_project_dir_only(tmp_path, monkeypatch) -> None:
    tool_root = tmp_path / "tool"
    project = tmp_path / "app"
    tool_root.mkdir()
    project.mkdir()
    (tool_root / "services.yaml").write_text("services: []\n", encoding="utf-8")
    monkeypatch.chdir(tool_root)

    assert resolve_services_path("auto", project_dir=project) is None

    (project / "services.yaml").write_text("services: []\n", encoding="utf-8")
    resolved = resolve_services_path("auto", project_dir=project)
    assert resolved == str(project / "services.yaml")


def test_services_explicit_relative_to_project(tmp_path) -> None:
    project = tmp_path / "app"
    project.mkdir()
    custom = project / "deploy" / "routes.yaml"
    custom.parent.mkdir()
    custom.write_text("services: []\n", encoding="utf-8")

    resolved = resolve_services_path(
        "deploy/routes.yaml",
        project_dir=project,
    )
    assert resolved == str(custom)

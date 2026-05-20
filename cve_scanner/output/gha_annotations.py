from __future__ import annotations

import re
from pathlib import Path

from cve_scanner.models import CVEFinding, ReachabilityResult, ScanResult


def _escape_message(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_title(text: str) -> str:
    return _escape_message(text).replace(",", "%2C")


def _annotation_level(verdict: str) -> str:
    if verdict == "BLOCK":
        return "error"
    if verdict == "REVIEW":
        return "warning"
    return "notice"


def _vulnerable_range(finding: CVEFinding) -> str:
    if finding.fixed_version:
        return f"< {finding.fixed_version}"
    return "unknown"


def _extract_location(
    finding: CVEFinding,
    reachability_map: dict[str, ReachabilityResult],
) -> tuple[str | None, int | None]:
    reach = reachability_map.get(finding.cve_id)
    if reach and reach.call_chain:
        candidate = reach.call_chain[0]
        match = re.match(r"^(.*):(\d+)$", candidate)
        if match:
            path = match.group(1)
            line = int(match.group(2))
            return path, line
        if ":" in candidate:
            path_part, line_part = candidate.rsplit(":", 1)
            if line_part.isdigit():
                return path_part, int(line_part)

    if finding.defined_in and finding.defined_in != "unknown":
        return finding.defined_in, None

    return None, None


def build_github_annotations(scan_result: ScanResult) -> str:
    reachability_map = {entry.cve_id: entry for entry in scan_result.reachability}
    verdict_by_package = {score.package_name: score.verdict for score in scan_result.risk_scores}
    lines: list[str] = []

    for finding in scan_result.cve_findings:
        verdict = verdict_by_package.get(finding.package_name, "PROCEED")
        level = _annotation_level(verdict)
        file_path, line = _extract_location(finding, reachability_map)
        vulnerable_range = _vulnerable_range(finding)
        title = _escape_title(f"{finding.cve_id} ({verdict})")
        message = (
            f"{finding.package_name} {vulnerable_range} - upgrade to "
            f"{finding.fixed_version or 'unknown'}"
        )
        message = _escape_message(message)

        if file_path:
            file_path = str(Path(file_path)).replace("\\", "/")
            if line:
                lines.append(
                    f"::{level} file={file_path},line={line},title={title}::{message}"
                )
            else:
                lines.append(f"::{level} file={file_path},title={title}::{message}")
        else:
            lines.append(f"::{level} title={title}::{message}")

    return "\n".join(lines)

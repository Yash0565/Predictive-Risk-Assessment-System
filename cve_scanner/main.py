from __future__ import annotations

import argparse
import asyncio
import base64
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel, Field

if __package__ is None and __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cve_scanner.config import get_settings
from cve_scanner.models import ScanResult
from cve_scanner.orchestrator import analyze_repo
from cve_scanner.output.digest_builder import build_digest
from cve_scanner.output.gha_annotations import build_github_annotations
from cve_scanner.output.html_report import build_html_report

app = FastAPI(title="CVE Pre-Upgrade Risk Scanner", version="1.0.0")


class AnalyzeRequest(BaseModel):
    repo_path: str
    output_format: list[str] = Field(default_factory=lambda: ["json", "html", "markdown"])
    dry_run: bool = False
    mock: bool = False
    mock_llm: bool = False


class AnalyzeResponse(BaseModel):
    scan_result: ScanResult
    html_report_b64: str | None = None
    markdown_digest: str | None = None
    github_annotations: str | None = None


def _configure_logging() -> None:
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _default_date_range() -> str:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=7)
    return f"{start.strftime('%b')} {start.day}\u2013{end.strftime('%b')} {end.day}"


def _exit_code_for_verdict(verdict: str) -> int:
    return {"PROCEED": 0, "REVIEW": 1, "BLOCK": 2}.get(verdict, 0)


def _verdict_order(verdict: str) -> int:
    return {"PROCEED": 0, "REVIEW": 1, "BLOCK": 2}.get(verdict, 0)


@app.post("/api/v1/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    _configure_logging()
    scan_result = await analyze_repo(
        request.repo_path,
        dry_run=request.dry_run,
        mock=request.mock,
        mock_llm=request.mock_llm,
    )
    repo_name = Path(request.repo_path).name
    date_range = _default_date_range()

    html_b64 = None
    markdown = None
    annotations = None
    if "html" in request.output_format:
        html = build_html_report(scan_result, repo_name)
        html_b64 = base64.b64encode(html.encode("utf-8")).decode("utf-8")
    if "markdown" in request.output_format:
        markdown = build_digest(scan_result, repo_name, date_range)
    if "annotations" in request.output_format:
        annotations = build_github_annotations(scan_result)

    return AnalyzeResponse(
        scan_result=scan_result,
        html_report_b64=html_b64,
        markdown_digest=markdown,
        github_annotations=annotations,
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CVE Pre-Upgrade Risk Scanner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run CVE pre-upgrade scan")
    scan.add_argument("--repo", required=True, help="Path to repository")
    scan.add_argument("--output-dir", default=None, help="Directory to write reports")
    scan.add_argument(
        "--format",
        default="html,markdown,json",
        help="Comma-separated list: html,markdown,json,annotations",
    )
    scan.add_argument(
        "--fail-on",
        default="REVIEW",
        choices=["PROCEED", "REVIEW", "BLOCK"],
        help="Exit non-zero if verdict is at or above this threshold",
    )
    scan.add_argument("--dry-run", action="store_true", help="Skip Claude API calls")
    scan.add_argument("--mock", action="store_true", help="Return mock scan result")
    scan.add_argument(
        "--mock-llm",
        action="store_true",
        help="Use LLM summary with mock data",
    )

    return parser.parse_args()


def _write_output(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _format_list(value: str) -> list[str]:
    return [item.strip().lower() for item in value.split(",") if item.strip()]


def _determine_exit_code(verdict: str, fail_on: Literal["PROCEED", "REVIEW", "BLOCK"]) -> int:
    if _verdict_order(verdict) < _verdict_order(fail_on):
        return 0
    return _exit_code_for_verdict(verdict)


def run_cli() -> int:
    _configure_logging()
    args = _parse_args()
    settings = get_settings()

    if args.command != "scan":
        return 0

    repo_path = args.repo
    output_formats = _format_list(args.format)
    output_dir = Path(args.output_dir or settings.REPORT_OUTPUT_DIR)
    date_range = _default_date_range()
    repo_name = Path(repo_path).name

    scan_result = asyncio.run(
        analyze_repo(
            repo_path,
            dry_run=args.dry_run,
            mock=args.mock,
            mock_llm=args.mock_llm,
        )
    )

    if "json" in output_formats:
        _write_output(output_dir / "scan_result.json", scan_result.model_dump_json(indent=2))
    if "markdown" in output_formats:
        digest = build_digest(scan_result, repo_name, date_range)
        _write_output(output_dir / "security_digest.md", digest)
    if "annotations" in output_formats:
        annotations = build_github_annotations(scan_result)
        _write_output(output_dir / "github_annotations.txt", annotations)
    if "html" in output_formats:
        html = build_html_report(scan_result, repo_name)
        _write_output(output_dir / "risk_report.html", html)

    return _determine_exit_code(scan_result.overall_verdict, args.fail_on)


if __name__ == "__main__":
    sys.exit(run_cli())
